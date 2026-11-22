//! WFP（Windows Filtering Platform）用户态阻断。
//!
//! - 使用动态会话（FWPM_SESSION_FLAG_DYNAMIC）：本进程退出、崩溃或被结束时，
//!   本会话添加的子层和过滤器全部由系统自动删除，不会残留规则。
//! - 按应用 ID（FWPM_CONDITION_ALE_APP_ID）在 ALE 连接/接受层阻断 IPv4 与 IPv6。
//! - 全局断网时再加一条不带条件的兜底阻断，以及若干放行例外。
//!   同一子层内按权重裁决：受控应用阻断（15）> 例外放行（8）> 兜底阻断（0），
//!   因此受控应用在全局断网时也不享受局域网等例外。

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use ipnet::IpNet;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::tcpkill;
use crate::blockall::{lan_nets, BlockAllPolicy, DHCP_V4_CLIENT_PORT, DHCP_V6_CLIENT_PORT, DNS_PORT};
use crate::controller::{Firewall, Rules};
use crate::discovery::normalize_path;

/// 本工具子层的固定 GUID。固定值便于识别"已有实例在运行"。
const SUBLAYER_KEY: GUID = GUID::from_u128(0x6a1e_93c4_2b7d_4f0e_9c51_3e8a_d4b2_7f10);

struct Layer {
    key: GUID,
    name: &'static str,
    v6: bool,
    /// 出站连接层（另一类是入站接受层）。
    connect: bool,
}

/// 阻断的 ALE 层：出站连接 + 入站接受，覆盖 TCP 与 UDP。
const LAYERS: [Layer; 4] = [
    Layer { key: FWPM_LAYER_ALE_AUTH_CONNECT_V4, name: "connect-v4", v6: false, connect: true },
    Layer { key: FWPM_LAYER_ALE_AUTH_CONNECT_V6, name: "connect-v6", v6: true, connect: true },
    Layer { key: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, name: "accept-v4", v6: false, connect: false },
    Layer { key: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, name: "accept-v6", v6: true, connect: false },
];

/// 过滤器权重（FWP_UINT8 权重档位，0–15）。
const W_APP_BLOCK: u8 = 15;
const W_PERMIT: u8 = 8;
const W_CATCH_ALL: u8 = 0;

const IPPROTO_UDP: u8 = 17;

const ERROR_ACCESS_DENIED: u32 = 5;
const E_ACCESSDENIED: u32 = 0x8007_0005;
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

/// 已生效的全局断网规则。
struct Global {
    policy: BlockAllPolicy,
    ids: Vec<u64>,
    /// 例外程序是否全部加上了（有程序暂不存在等情况时为 false，稍后重试）。
    complete: bool,
}

pub struct WfpFirewall {
    engine: HANDLE,
    rules: Rules,
    /// 规范化路径 → 该受控程序的过滤器 ID。
    filters: HashMap<String, Vec<u64>>,
    global: Option<Global>,
    blocked: bool,
    /// 本轮未能加上规则的受控程序（文件不存在或添加失败），等待重试。
    pending: HashSet<String>,
    /// 已经警告过的程序，成功前不再重复警告。
    warned: HashSet<String>,
    /// 本工具自身，全局断网时始终放行（否则无法再检测出口 IP）。
    self_exe: Option<PathBuf>,
}

/// 同步结果。
#[derive(Default)]
struct Synced {
    added_apps: Vec<PathBuf>,
    global_applied: bool,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check(code: u32, what: &str) -> Result<()> {
    match code {
        0 => Ok(()),
        ERROR_ACCESS_DENIED | E_ACCESSDENIED => {
            bail!("{what} 失败：拒绝访问，请以管理员身份运行")
        }
        FWP_E_ALREADY_EXISTS => {
            bail!("{what} 失败：对象已存在，可能已有另一个 egress-guard 实例在运行")
        }
        c => bail!("{what} 失败：0x{c:08X}"),
    }
}

impl WfpFirewall {
    pub fn open() -> Result<Self> {
        let mut session_name = wide("egress-guard");
        let mut session_desc = wide("Egress IP based app network control (dynamic session)");
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(session_name.as_mut_ptr()),
                description: PWSTR(session_desc.as_mut_ptr()),
            },
            ..Default::default()
        };

        let mut engine = HANDLE::default();
        check(
            unsafe {
                FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, Some(&session), &mut engine)
            },
            "FwpmEngineOpen0",
        )?;

        let fw = Self {
            engine,
            rules: Rules::default(),
            filters: HashMap::new(),
            global: None,
            blocked: false,
            pending: HashSet::new(),
            warned: HashSet::new(),
            self_exe: std::env::current_exe().ok(),
        };

        let mut sl_name = wide("egress-guard sublayer");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(sl_name.as_mut_ptr()),
                description: PWSTR::null(),
            },
            weight: 0xFFFF, // 最高子层权重
            ..Default::default()
        };
        check(unsafe { FwpmSubLayerAdd0(fw.engine, &sublayer, None) }, "FwpmSubLayerAdd0")?;
        Ok(fw)
    }

    fn in_transaction(&mut self, f: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        check(unsafe { FwpmTransactionBegin0(self.engine, 0) }, "FwpmTransactionBegin0")?;
        match f(self) {
            Ok(()) => check(unsafe { FwpmTransactionCommit0(self.engine) }, "FwpmTransactionCommit0"),
            Err(e) => {
                unsafe { FwpmTransactionAbort0(self.engine) };
                Err(e)
            }
        }
    }

    /// 添加一个过滤器。权限阻断会清除动作权限，低优先级子层的放行无法覆盖。
    fn add_filter(
        &self,
        layer: &Layer,
        what: &str,
        permit: bool,
        weight: u8,
        conds: &mut [FWPM_FILTER_CONDITION0],
    ) -> Result<u64> {
        let mut name = wide(&format!("egress-guard {what} {}", layer.name));
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 { name: PWSTR(name.as_mut_ptr()), description: PWSTR::null() },
            flags: if permit { FWPM_FILTER_FLAG_NONE } else { FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT },
            layerKey: layer.key,
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_VALUE0_0 { uint8: weight } },
            numFilterConditions: conds.len() as u32,
            filterCondition: if conds.is_empty() { std::ptr::null_mut() } else { conds.as_mut_ptr() },
            action: FWPM_ACTION0 {
                r#type: if permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK },
                ..Default::default()
            },
            ..Default::default()
        };
        let mut id = 0u64;
        check(
            unsafe { FwpmFilterAdd0(self.engine, &filter, None, Some(&mut id)) },
            &format!("FwpmFilterAdd0({what}, {})", layer.name),
        )?;
        Ok(id)
    }

    fn delete_ids(&self, ids: &[u64]) {
        for id in ids {
            unsafe { FwpmFilterDeleteById0(self.engine, *id) };
        }
    }

    /// 为单个程序在 4 个层上添加过滤器（阻断或放行），返回过滤器 ID。
    /// 任一层失败时删掉已加上的部分，不留半套规则。
    fn add_app_filters(&self, app: &Path, permit: bool) -> Result<Vec<u64>> {
        let path_w = wide(&app.to_string_lossy());
        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        check(
            unsafe { FwpmGetAppIdFromFileName0(PCWSTR(path_w.as_ptr()), &mut app_id) },
            &format!("FwpmGetAppIdFromFileName0({})", app.display()),
        )?;
        let (what, weight) = if permit { ("allow app", W_PERMIT) } else { ("block app", W_APP_BLOCK) };
        let mut ids = Vec::with_capacity(LAYERS.len());
        let mut result = Ok(());
        for layer in &LAYERS {
            let mut cond = [FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
                },
            }];
            match self.add_filter(layer, what, permit, weight, &mut cond) {
                Ok(id) => ids.push(id),
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        let mut p = app_id as *mut c_void;
        unsafe { FwpmFreeMemory0(&mut p) };
        match result {
            Ok(()) => Ok(ids),
            Err(e) => {
                self.delete_ids(&ids);
                Err(e)
            }
        }
    }

    /// 添加全局断网的兜底阻断与例外放行。基础规则失败时返回错误（整个事务回滚）；
    /// 单个例外程序失败只跳过它，并把 complete 记为 false 以便稍后重试。
    fn add_global_filters(
        &self,
        policy: &BlockAllPolicy,
        warnings: &mut Vec<(String, String)>,
        ok_keys: &mut Vec<String>,
    ) -> Result<(Vec<u64>, bool)> {
        let mut ids = Vec::new();
        let mut remote: Vec<IpNet> = if policy.allow_lan { lan_nets() } else { Vec::new() };
        remote.extend(policy.allow_remote.iter().copied());

        let base = (|| -> Result<()> {
            for layer in &LAYERS {
                let mut c = [cond_flags(FWP_CONDITION_FLAG_IS_LOOPBACK)];
                ids.push(self.add_filter(layer, "allow loopback", true, W_PERMIT, &mut c)?);

                let port = if layer.v6 { DHCP_V6_CLIENT_PORT } else { DHCP_V4_CLIENT_PORT };
                let mut c = [cond_u8(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_UDP), cond_u16(FWPM_CONDITION_IP_LOCAL_PORT, port)];
                ids.push(self.add_filter(layer, "allow dhcp", true, W_PERMIT, &mut c)?);

                if policy.allow_dns && layer.connect {
                    let mut c = [cond_u16(FWPM_CONDITION_IP_REMOTE_PORT, DNS_PORT)];
                    ids.push(self.add_filter(layer, "allow dns", true, W_PERMIT, &mut c)?);
                }

                // 同一字段的多个条件之间是"或"关系
                let mut v4: Vec<FWP_V4_ADDR_AND_MASK> = Vec::new();
                let mut v6: Vec<FWP_V6_ADDR_AND_MASK> = Vec::new();
                for net in &remote {
                    match net {
                        IpNet::V4(n) if !layer.v6 => v4.push(FWP_V4_ADDR_AND_MASK {
                            addr: u32::from(n.network()),
                            mask: if n.prefix_len() == 0 { 0 } else { u32::MAX << (32 - n.prefix_len()) },
                        }),
                        IpNet::V6(n) if layer.v6 => v6.push(FWP_V6_ADDR_AND_MASK {
                            addr: n.network().octets(),
                            prefixLength: n.prefix_len(),
                        }),
                        _ => {}
                    }
                }
                let mut c: Vec<FWPM_FILTER_CONDITION0> = if layer.v6 {
                    v6.iter_mut().map(cond_v6).collect()
                } else {
                    v4.iter_mut().map(cond_v4).collect()
                };
                if !c.is_empty() {
                    ids.push(self.add_filter(layer, "allow remote", true, W_PERMIT, &mut c)?);
                }

                ids.push(self.add_filter(layer, "block all", false, W_CATCH_ALL, &mut [])?);
            }
            Ok(())
        })();
        if let Err(e) = base {
            self.delete_ids(&ids);
            return Err(e);
        }

        let mut complete = true;
        for app in self.self_exe.iter().chain(policy.allow_apps.iter()) {
            let key = format!("allow:{}", normalize_path(app));
            if !app.exists() {
                complete = false;
                warnings.push((key, format!("例外程序不存在，暂时跳过: {}", app.display())));
                continue;
            }
            match self.add_app_filters(app, true) {
                Ok(mut v) => {
                    ids.append(&mut v);
                    ok_keys.push(key);
                }
                Err(e) => {
                    complete = false;
                    warnings.push((key, format!("无法放行例外程序 {}，稍后重试: {e:#}", app.display())));
                }
            }
        }
        Ok((ids, complete))
    }

    /// 在一个事务里让过滤器与规则一致：为缺少的程序添加、为多余的程序删除，
    /// 全局断网规则有变化时整体替换。整个过程没有"先全部删除再添加"的放行空档。
    fn sync_filters(&mut self) -> Result<Synced> {
        let wanted: HashMap<String, PathBuf> =
            self.rules.apps.iter().map(|p| (normalize_path(p), p.clone())).collect();
        let to_remove: Vec<String> =
            self.filters.keys().filter(|k| !wanted.contains_key(*k)).cloned().collect();
        let to_add: Vec<(String, PathBuf)> = wanted
            .iter()
            .filter(|(k, _)| !self.filters.contains_key(*k))
            .map(|(k, p)| (k.clone(), p.clone()))
            .collect();
        let want_global = self.rules.block_all.clone();
        let global_stale = match (&self.global, &want_global) {
            (None, None) => false,
            (Some(g), Some(p)) => g.policy != *p || !g.complete,
            _ => true,
        };
        if to_remove.is_empty() && to_add.is_empty() && !global_stale {
            self.pending.clear();
            return Ok(Synced::default());
        }

        let mut added: Vec<(String, PathBuf, Vec<u64>)> = Vec::new();
        let mut pending = HashSet::new();
        let mut warnings = Vec::new();
        let mut ok_keys = Vec::new();
        let mut new_global: Option<Option<Global>> = None;
        self.in_transaction(|fw| {
            for k in &to_remove {
                for id in &fw.filters[k] {
                    check(unsafe { FwpmFilterDeleteById0(fw.engine, *id) }, "FwpmFilterDeleteById0")?;
                }
            }
            // 单个程序失败（文件不存在、路径无效等）只跳过它，不影响其他程序的阻断
            for (k, app) in &to_add {
                if !app.exists() {
                    pending.insert(k.clone());
                    warnings.push((k.clone(), format!("程序不存在，暂时跳过: {}", app.display())));
                    continue;
                }
                match fw.add_app_filters(app, false) {
                    Ok(ids) => {
                        ok_keys.push(k.clone());
                        added.push((k.clone(), app.clone(), ids));
                    }
                    Err(e) => {
                        pending.insert(k.clone());
                        warnings.push((k.clone(), format!("无法阻断 {}，稍后重试: {e:#}", app.display())));
                    }
                }
            }
            if global_stale {
                if let Some(g) = &fw.global {
                    for id in &g.ids {
                        check(unsafe { FwpmFilterDeleteById0(fw.engine, *id) }, "FwpmFilterDeleteById0")?;
                    }
                }
                new_global = Some(match &want_global {
                    Some(p) => {
                        let (ids, complete) = fw.add_global_filters(p, &mut warnings, &mut ok_keys)?;
                        Some(Global { policy: p.clone(), ids, complete })
                    }
                    None => None,
                });
            }
            Ok(())
        })?;

        for k in &ok_keys {
            self.warned.remove(k);
        }
        for (k, msg) in warnings {
            if self.warned.insert(k) {
                log::warn!("{msg}");
            }
        }
        self.pending = pending;

        let mut global_applied = false;
        if let Some(g) = new_global {
            match &g {
                Some(g) => {
                    global_applied = true;
                    log::info!(
                        "全局断网规则已生效：{} 个过滤器（局域网{}，DNS {}，例外程序 {} 个，例外地址 {} 条）",
                        g.ids.len(),
                        if g.policy.allow_lan { "放行" } else { "阻断" },
                        if g.policy.allow_dns { "放行" } else { "阻断" },
                        g.policy.allow_apps.len(),
                        g.policy.allow_remote.len()
                    );
                }
                None => log::info!("全局断网规则已移除，只阻断受控应用"),
            }
            self.global = g;
        }

        for k in &to_remove {
            self.filters.remove(k);
        }
        let mut added_apps = Vec::new();
        for (k, app, ids) in added {
            self.filters.insert(k, ids);
            added_apps.push(app);
        }
        if !added_apps.is_empty() || !to_remove.is_empty() {
            let total: usize = self.filters.values().map(Vec::len).sum();
            log::info!(
                "WFP 规则已更新：新增 {} 个程序，移除 {} 个，受控应用共 {} 个过滤器",
                added_apps.len(),
                to_remove.len(),
                total
            );
        }
        Ok(Synced { added_apps, global_applied })
    }

    /// 主动断开现有 IPv4 TCP 连接。全局断网刚生效时断开所有非例外连接，
    /// 否则只断开新加入阻断的受控程序。
    fn kill_connections(&self, s: &Synced, entering_block: bool) {
        if !self.rules.kill_existing_tcp {
            return;
        }
        let result = match &self.global {
            Some(g) if entering_block || s.global_applied => {
                let apps: HashSet<String> = self.rules.apps.iter().map(|p| normalize_path(p)).collect();
                let allowed: HashSet<String> =
                    self.self_exe.iter().chain(g.policy.allow_apps.iter()).map(|p| normalize_path(p)).collect();
                tcpkill::kill_tcp_where(|path, ip, port| {
                    if path.is_some_and(|p| apps.contains(p)) {
                        return true;
                    }
                    if path.is_some_and(|p| allowed.contains(p)) {
                        return false;
                    }
                    !g.policy.permits_remote(IpAddr::V4(ip), port)
                })
            }
            _ if !s.added_apps.is_empty() => tcpkill::kill_tcp_connections(&s.added_apps),
            _ => return,
        };
        match result {
            Ok(0) => {}
            Ok(n) => log::info!("已断开 {n} 条现有 IPv4 TCP 连接"),
            Err(e) => log::warn!("断开现有 TCP 连接失败: {e:#}"),
        }
    }
}

fn cond_u8(field: GUID, v: u8) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_CONDITION_VALUE0_0 { uint8: v } },
    }
}

fn cond_u16(field: GUID, v: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 { r#type: FWP_UINT16, Anonymous: FWP_CONDITION_VALUE0_0 { uint16: v } },
    }
}

fn cond_flags(flags: u32) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_FLAGS,
        matchType: FWP_MATCH_FLAGS_ALL_SET,
        conditionValue: FWP_CONDITION_VALUE0 { r#type: FWP_UINT32, Anonymous: FWP_CONDITION_VALUE0_0 { uint32: flags } },
    }
}

fn cond_v4(m: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: m },
        },
    }
}

fn cond_v6(m: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V6_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: m },
        },
    }
}

impl Firewall for WfpFirewall {
    fn block(&mut self) -> Result<()> {
        if self.blocked {
            return Ok(());
        }
        let s = self.sync_filters()?;
        self.blocked = true;
        self.kill_connections(&s, true);
        Ok(())
    }

    fn unblock(&mut self) -> Result<()> {
        if !self.blocked {
            return Ok(());
        }
        let ids: Vec<u64> = self
            .filters
            .values()
            .flatten()
            .chain(self.global.iter().flat_map(|g| g.ids.iter()))
            .copied()
            .collect();
        self.in_transaction(|fw| {
            for id in &ids {
                check(unsafe { FwpmFilterDeleteById0(fw.engine, *id) }, "FwpmFilterDeleteById0")?;
            }
            Ok(())
        })?;
        log::info!("WFP 已删除 {} 个过滤器", ids.len());
        self.filters.clear();
        self.global = None;
        self.pending.clear();
        self.blocked = false;
        Ok(())
    }

    fn is_blocked(&self) -> bool {
        self.blocked
    }

    fn has_pending(&self) -> bool {
        self.blocked && (!self.pending.is_empty() || self.global.as_ref().is_some_and(|g| !g.complete))
    }

    fn set_rules(&mut self, rules: Rules) -> Result<()> {
        self.rules = rules;
        if self.blocked {
            let s = self.sync_filters()?;
            self.kill_connections(&s, false);
        }
        Ok(())
    }
}

impl Drop for WfpFirewall {
    fn drop(&mut self) {
        // 关闭动态会话后，系统自动删除本会话的全部子层与过滤器
        unsafe { FwpmEngineClose0(self.engine) };
        log::info!("WFP 会话已关闭，所有阻断规则已移除");
    }
}
