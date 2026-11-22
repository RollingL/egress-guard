//! WFP（Windows Filtering Platform）用户态阻断。
//!
//! - 使用动态会话（FWPM_SESSION_FLAG_DYNAMIC）：本进程退出、崩溃或被结束时，
//!   本会话添加的子层和过滤器全部由系统自动删除，不会残留规则。
//! - 按应用 ID（FWPM_CONDITION_ALE_APP_ID）在 ALE 连接/接受层阻断 IPv4 与 IPv6。

use std::ffi::c_void;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::tcpkill;
use crate::controller::Firewall;
use crate::discovery::normalize_path;

/// 本工具子层的固定 GUID。固定值便于识别"已有实例在运行"。
const SUBLAYER_KEY: GUID = GUID::from_u128(0x6a1e_93c4_2b7d_4f0e_9c51_3e8a_d4b2_7f10);

/// 阻断的 ALE 层：出站连接 + 入站接受，覆盖 TCP 与 UDP。
const LAYERS: [(GUID, &str); 4] = [
    (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "connect-v4"),
    (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "connect-v6"),
    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "accept-v4"),
    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "accept-v6"),
];

const ERROR_ACCESS_DENIED: u32 = 5;
const E_ACCESSDENIED: u32 = 0x8007_0005;
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

pub struct WfpFirewall {
    engine: HANDLE,
    apps: Vec<PathBuf>,
    /// 规范化路径 → 该程序的过滤器 ID。
    filters: HashMap<String, Vec<u64>>,
    blocked: bool,
    kill_existing_tcp: bool,
    /// 本轮未能加上规则的程序（文件不存在或添加失败），等待重试。
    pending: HashSet<String>,
    /// 已经警告过的程序，避免每次重试都刷屏。
    warned: HashSet<String>,
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
    pub fn open(apps: Vec<PathBuf>, kill_existing_tcp: bool) -> Result<Self> {
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
            apps,
            filters: HashMap::new(),
            blocked: false,
            kill_existing_tcp,
            pending: HashSet::new(),
            warned: HashSet::new(),
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

    /// 为单个应用添加 4 个阻断过滤器，返回过滤器 ID。
    fn add_app_filters(&self, app: &Path) -> Result<Vec<u64>> {
        let path_w = wide(&app.to_string_lossy());
        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        check(
            unsafe { FwpmGetAppIdFromFileName0(PCWSTR(path_w.as_ptr()), &mut app_id) },
            &format!("FwpmGetAppIdFromFileName0({})", app.display()),
        )?;

        let mut ids = Vec::with_capacity(LAYERS.len());
        let result = (|| {
            for (layer, layer_name) in LAYERS {
                let mut cond = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_ALE_APP_ID,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_BLOB_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
                    },
                };
                let mut name = wide(&format!("egress-guard block {layer_name}"));
                let filter = FWPM_FILTER0 {
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: PWSTR(name.as_mut_ptr()),
                        description: PWSTR::null(),
                    },
                    // 硬阻断：清除动作权限，低优先级子层的放行无法覆盖
                    flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
                    layerKey: layer,
                    subLayerKey: SUBLAYER_KEY,
                    weight: FWP_VALUE0 { r#type: FWP_EMPTY, ..Default::default() },
                    numFilterConditions: 1,
                    filterCondition: &mut cond,
                    action: FWPM_ACTION0 { r#type: FWP_ACTION_BLOCK, ..Default::default() },
                    ..Default::default()
                };
                let mut id = 0u64;
                check(
                    unsafe { FwpmFilterAdd0(self.engine, &filter, None, Some(&mut id)) },
                    &format!("FwpmFilterAdd0({}, {layer_name})", app.display()),
                )?;
                ids.push(id);
            }
            Ok(())
        })();

        let mut p = app_id as *mut c_void;
        unsafe { FwpmFreeMemory0(&mut p) };
        match result {
            Ok(()) => Ok(ids),
            Err(e) => {
                // 删掉已加上的部分过滤器，不留半套规则
                for id in ids {
                    unsafe { FwpmFilterDeleteById0(self.engine, id) };
                }
                Err(e)
            }
        }
    }
}

impl WfpFirewall {
    /// 在一个事务里让过滤器与 `apps` 一致：为缺少的程序添加、为多余的程序删除。
    /// 返回新加入阻断的程序。整个过程没有"先全部删除再添加"的放行空档。
    fn sync_filters(&mut self) -> Result<Vec<PathBuf>> {
        let wanted: HashMap<String, PathBuf> =
            self.apps.iter().map(|p| (normalize_path(p), p.clone())).collect();
        let to_remove: Vec<String> =
            self.filters.keys().filter(|k| !wanted.contains_key(*k)).cloned().collect();
        let to_add: Vec<(String, PathBuf)> = wanted
            .iter()
            .filter(|(k, _)| !self.filters.contains_key(*k))
            .map(|(k, p)| (k.clone(), p.clone()))
            .collect();
        if to_remove.is_empty() && to_add.is_empty() {
            self.pending.clear();
            self.warned.clear();
            return Ok(Vec::new());
        }

        let mut added: Vec<(String, PathBuf, Vec<u64>)> = Vec::new();
        let mut pending = HashSet::new();
        let mut warnings = Vec::new();
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
                match fw.add_app_filters(app) {
                    Ok(ids) => added.push((k.clone(), app.clone(), ids)),
                    Err(e) => {
                        pending.insert(k.clone());
                        warnings.push((k.clone(), format!("无法阻断 {}，稍后重试: {e:#}", app.display())));
                    }
                }
            }
            Ok(())
        })?;

        for (k, msg) in warnings {
            if self.warned.insert(k) {
                log::warn!("{msg}");
            }
        }
        // 已成功或已不再需要的程序，之后再失败时重新警告
        self.warned.retain(|k| pending.contains(k));
        self.pending = pending;

        for k in &to_remove {
            self.filters.remove(k);
        }
        let mut new_apps = Vec::new();
        for (k, app, ids) in added {
            self.filters.insert(k, ids);
            new_apps.push(app);
        }
        if !new_apps.is_empty() || !to_remove.is_empty() {
            let total: usize = self.filters.values().map(Vec::len).sum();
            log::info!(
                "WFP 规则已更新：新增 {} 个程序，移除 {} 个，当前 {} 个过滤器",
                new_apps.len(),
                to_remove.len(),
                total
            );
        }
        Ok(new_apps)
    }

    fn kill_connections(&self, apps: &[PathBuf]) {
        if !self.kill_existing_tcp || apps.is_empty() {
            return;
        }
        match tcpkill::kill_tcp_connections(apps) {
            Ok(0) => {}
            Ok(n) => log::info!("已断开 {n} 条现有 IPv4 TCP 连接"),
            Err(e) => log::warn!("断开现有 TCP 连接失败: {e:#}"),
        }
    }
}

impl Firewall for WfpFirewall {
    fn block(&mut self) -> Result<()> {
        if self.blocked {
            return Ok(());
        }
        let added = self.sync_filters()?;
        self.blocked = true;
        self.kill_connections(&added);
        Ok(())
    }

    fn unblock(&mut self) -> Result<()> {
        if !self.blocked {
            return Ok(());
        }
        let ids: Vec<u64> = self.filters.values().flatten().copied().collect();
        self.in_transaction(|fw| {
            for id in &ids {
                check(unsafe { FwpmFilterDeleteById0(fw.engine, *id) }, "FwpmFilterDeleteById0")?;
            }
            Ok(())
        })?;
        log::info!("WFP 已删除 {} 个阻断过滤器", ids.len());
        self.filters.clear();
        self.pending.clear();
        self.blocked = false;
        Ok(())
    }

    fn is_blocked(&self) -> bool {
        self.blocked
    }

    fn has_pending(&self) -> bool {
        self.blocked && !self.pending.is_empty()
    }

    fn set_apps(&mut self, apps: Vec<PathBuf>, kill_existing_tcp: bool) -> Result<()> {
        self.apps = apps;
        self.kill_existing_tcp = kill_existing_tcp;
        if self.blocked {
            let added = self.sync_filters()?;
            self.kill_connections(&added);
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
