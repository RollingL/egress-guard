//! WFP 阻断的状态机（与平台无关，便于用模拟的 WFP 事务测试）。
//!
//! 真正的 WFP 调用在 `win::wfp`（实现 [`Api`]）；这里决定什么时候、在哪个事务里加哪些过滤器、删哪些，
//! 以及每个过滤器归谁所有。原则：
//!
//! - 过滤器 ID 只在事务提交之后才换主人（例如放行期间保留的 IPv6 阻断并入新的阻断）。
//!   事务失败、回滚时，原来的记录与 WFP 里实际存在的过滤器保持一致，之后改换目标时仍能找到它们。
//! - 每个过滤器记下所在的层是不是 IPv6。放行时，IPv6 兜底规则（受控应用的、全局断网的）没能加上的，
//!   只保留原阻断里 IPv6 层的那部分，IPv4 照常放行；整机不会因为 IPv6 规则失败而一直断网。
//! - 例外放行（局域网、DNS、例外程序）失败只单独报告，不影响阻断本身。
//!
//! 同一子层内按权重裁决：受控应用阻断（15）> 例外放行（8）> 兜底阻断（0），
//! 因此受控应用在全局断网时也不享受局域网等例外。

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use ipnet::IpNet;

use crate::blockall::{
    lan_nets, BlockAllPolicy, DHCP_V4_CLIENT_PORT, DHCP_V4_SERVER_PORT, DHCP_V6_CLIENT_PORT, DHCP_V6_SERVER_PORT,
};
use crate::controller::{Firewall, Rules};
use crate::discovery::normalize_path;

/// 一个 ALE 层。`index` 对应 Windows 上的层 GUID（见 `win::wfp`）。
#[derive(Debug)]
pub struct Layer {
    pub index: usize,
    pub name: &'static str,
    pub v6: bool,
    /// 出站连接层（另一类是入站接受层）。
    pub connect: bool,
}

/// 阻断的 ALE 层：出站连接 + 入站接受，覆盖 TCP 与 UDP。
pub static LAYERS: [Layer; 4] = [
    Layer { index: 0, name: "connect-v4", v6: false, connect: true },
    Layer { index: 1, name: "connect-v6", v6: true, connect: true },
    Layer { index: 2, name: "accept-v4", v6: false, connect: false },
    Layer { index: 3, name: "accept-v6", v6: true, connect: false },
];

fn all_layers() -> Vec<&'static Layer> {
    LAYERS.iter().collect()
}

fn v6_layers() -> Vec<&'static Layer> {
    LAYERS.iter().filter(|l| l.v6).collect()
}

/// 过滤器权重（FWP_UINT8 权重档位，0–15）。
pub const W_APP_BLOCK: u8 = 15;
pub const W_PERMIT: u8 = 8;
pub const W_CATCH_ALL: u8 = 0;

/// 要添加的一个过滤器。
#[derive(Debug)]
pub enum Filter<'a> {
    /// 放行回环。
    Loopback,
    /// 只放行 DHCP 客户端与服务器端口之间的 UDP。
    Dhcp { client: u16, server: u16 },
    /// 放行发往 53 端口的连接。
    Dns,
    /// 放行发往这些网段的连接（只含本层地址族的网段，不为空）。
    Remote(&'a [IpNet]),
    /// 兜底阻断。
    BlockAll,
    /// 按程序阻断或放行。
    App { path: &'a Path, permit: bool },
}

impl Filter<'_> {
    pub fn permit(&self) -> bool {
        !matches!(self, Filter::BlockAll | Filter::App { permit: false, .. })
    }

    pub fn weight(&self) -> u8 {
        match self {
            Filter::App { permit: false, .. } => W_APP_BLOCK,
            Filter::BlockAll => W_CATCH_ALL,
            _ => W_PERMIT,
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Filter::Loopback => "allow loopback",
            Filter::Dhcp { .. } => "allow dhcp",
            Filter::Dns => "allow dns",
            Filter::Remote(_) => "allow remote",
            Filter::BlockAll => "block all",
            Filter::App { permit: true, .. } => "allow app",
            Filter::App { permit: false, .. } => "block app",
        }
    }
}

/// 主动断开现有 IPv4 TCP 连接的范围。
pub enum Kill {
    /// 全局断网刚生效：断开受控程序的、以及不在例外里的全部连接。
    Global { apps: HashSet<String>, allowed: HashSet<String>, policy: BlockAllPolicy },
    /// 只断开新加入阻断的受控程序。
    Apps(Vec<PathBuf>),
}

impl Kill {
    /// 这条连接是否要断开（`path` 为规范化的程序路径）。
    pub fn matches(&self, path: Option<&str>, ip: IpAddr, port: u16) -> bool {
        match self {
            Kill::Global { apps, allowed, policy } => {
                if path.is_some_and(|p| apps.contains(p)) {
                    return true;
                }
                if path.is_some_and(|p| allowed.contains(p)) {
                    return false;
                }
                !policy.permits_remote(ip, port)
            }
            Kill::Apps(list) => {
                let set: HashSet<String> = list.iter().map(|p| normalize_path(p)).collect();
                path.is_some_and(|p| set.contains(p))
            }
        }
    }
}

/// 底层的 WFP 操作。所有修改都在 `begin` 与 `commit` / `abort` 之间进行。
pub trait Api {
    fn begin(&mut self) -> Result<()>;
    fn commit(&mut self) -> Result<()>;
    fn abort(&mut self);
    fn add(&mut self, layer: &Layer, filter: &Filter<'_>) -> Result<u64>;
    fn delete(&mut self, id: u64) -> Result<()>;
    /// 文件可能存在：只有确认「不存在」才算不存在。权限不足等其他错误照常尝试加规则
    /// （加不上记为失败并重试），而不是当作文件不存在悄悄跳过。
    fn may_exist(&self, p: &Path) -> bool {
        !matches!(p.try_exists(), Ok(false))
    }
    fn kill(&self, k: Kill);
}

/// 一个过滤器的 ID，以及它所在的层是不是 IPv6。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fid {
    pub v6: bool,
    pub id: u64,
}

fn ids(v: &[Fid]) -> impl Iterator<Item = u64> + '_ {
    v.iter().map(|f| f.id)
}

/// 「始终阻断 IPv6」的过滤器：放行期间也在 IPv6 层阻断受控应用（全局断网时为全部 IPv6）。
/// 与阻断状态无关。和主规则一样按程序增量同步：已经生效的阻断在新程序加不上时保持不动，
/// 不会出现「先删掉旧的一整套、新的只加上一半」的情况。阻断期间与主规则重复，不影响结果。
#[derive(Default)]
struct V6Guard {
    /// 规范化路径 → 该程序在 IPv6 层的阻断过滤器。
    apps: HashMap<String, Vec<u64>>,
    /// 因为文件不存在而暂未加上的程序：等它出现再加。
    missing: HashMap<String, PathBuf>,
    /// 添加失败的程序：定时重试。
    failed: HashSet<String>,
    /// 全局断网时的 IPv6 兜底阻断与例外。
    global: Option<V6Global>,
    /// 全局部分（基础规则）没能加上：定时重试。
    global_failed: bool,
}

struct V6Global {
    policy: BlockAllPolicy,
    ids: Vec<u64>,
    /// 不存在的例外程序（出现后重建）。
    missing: Vec<PathBuf>,
    /// 有例外程序添加失败（定时重试）。
    failed: bool,
}

impl V6Guard {
    fn all_ids(&self) -> Vec<u64> {
        self.apps.values().flatten().chain(self.global.iter().flat_map(|g| g.ids.iter())).copied().collect()
    }
}

/// 已生效的全局断网规则。
struct Global {
    policy: BlockAllPolicy,
    ids: Vec<Fid>,
    /// 例外程序是否全部加上了（有程序暂不存在等情况时为 false，稍后重试）。
    complete: bool,
    /// 有例外程序添加失败（不是暂不存在）。
    failed: bool,
    /// 暂不存在、没有加上放行的例外程序：出现之后才需要重建全局部分。
    missing: Vec<PathBuf>,
}

/// 新加上的全局断网规则。
struct GlobalAdded {
    ids: Vec<Fid>,
    missing: Vec<PathBuf>,
    failed: bool,
}

/// 同步结果。
#[derive(Default)]
struct Synced {
    added_apps: Vec<PathBuf>,
    global_applied: bool,
}

pub struct Wfp<A: Api> {
    api: A,
    rules: Rules,
    /// 规范化路径 → 该受控程序的阻断过滤器（阻断期间）。
    filters: HashMap<String, Vec<Fid>>,
    global: Option<Global>,
    blocked: bool,
    /// 本轮未能加上规则的受控程序（文件不存在或添加失败），等待重试。
    pending: HashSet<String>,
    /// 已经警告过的程序，成功前不再重复警告。
    warned: HashSet<String>,
    /// 本工具自身，全局断网时始终放行（否则无法再检测出口 IP）。
    self_exe: Option<PathBuf>,
    v6guard: Option<V6Guard>,
    /// 放行后仍保留的受控程序 IPv6 阻断：「始终阻断 IPv6」时这些程序的 IPv6 阻断没能加上，
    /// 于是留着原阻断里 IPv6 层的过滤器（IPv4 照常放行），等 IPv6 阻断补上后再撤。
    retained: HashMap<String, Vec<u64>>,
    /// 同上，全局断网的 IPv6 部分：全局 IPv6 兜底规则没能加上时，留着原全局阻断里 IPv6 层的过滤器。
    retained_global: Option<Vec<u64>>,
}

impl<A: Api> Wfp<A> {
    pub fn new(api: A, self_exe: Option<PathBuf>) -> Self {
        Self {
            api,
            rules: Rules::default(),
            filters: HashMap::new(),
            global: None,
            blocked: false,
            pending: HashSet::new(),
            warned: HashSet::new(),
            self_exe,
            v6guard: None,
            retained: HashMap::new(),
            retained_global: None,
        }
    }

    /// 在一个事务里执行 `f`。`f` 出错或提交失败时回滚，WFP 里的过滤器保持原样。
    fn in_transaction<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.api.begin()?;
        match f(self) {
            Ok(v) => match self.api.commit() {
                Ok(()) => Ok(v),
                Err(e) => {
                    self.api.abort();
                    Err(e)
                }
            },
            Err(e) => {
                self.api.abort();
                Err(e)
            }
        }
    }

    fn delete_all(&mut self, list: &[u64]) -> Result<()> {
        for id in list {
            self.api.delete(*id)?;
        }
        Ok(())
    }

    /// 为单个程序在给定的层上添加过滤器（阻断或放行）。
    /// 任一层失败时删掉已加上的部分，不留半套规则：这时返回 `Ok(Err(..))`，调用方可以跳过这个程序继续；
    /// 清理本身失败时返回外层的 `Err`，调用方必须中止整个事务（否则会提交半套规则）。
    fn add_app_filters(&mut self, app: &Path, permit: bool, layers: &[&Layer]) -> Result<Result<Vec<Fid>>> {
        let mut added = Vec::with_capacity(layers.len());
        for layer in layers {
            match self.api.add(layer, &Filter::App { path: app, permit }) {
                Ok(id) => added.push(Fid { v6: layer.v6, id }),
                Err(e) => {
                    for f in &added {
                        self.api
                            .delete(f.id)
                            .map_err(|d| d.context(format!("清理 {} 的部分过滤器失败", app.display())))?;
                    }
                    return Ok(Err(e));
                }
            }
        }
        Ok(Ok(added))
    }

    /// 添加全局断网的兜底阻断与例外放行。基础规则失败时返回错误（整个事务回滚）；
    /// 单个例外程序失败只跳过它：不存在的记进 missing（等它出现），添加失败的把 failed 记为 true（定时重试）。
    fn add_global_filters(
        &mut self,
        policy: &BlockAllPolicy,
        layers: &[&Layer],
        warnings: &mut Vec<(String, String)>,
        ok_keys: &mut Vec<String>,
    ) -> Result<GlobalAdded> {
        let mut added = Vec::new();
        let mut remote: Vec<IpNet> = if policy.allow_lan { lan_nets() } else { Vec::new() };
        remote.extend(policy.allow_remote.iter().copied());
        for layer in layers {
            let mut add = |api: &mut A, f: Filter<'_>| -> Result<()> {
                added.push(Fid { v6: layer.v6, id: api.add(layer, &f)? });
                Ok(())
            };
            add(&mut self.api, Filter::Loopback)?;
            // 只放行 DHCP 客户端与服务器端口之间的 UDP（连接层是发往服务器，接受层是服务器的回复），
            // 而不是本地 68/546 端口发往任意端口的流量
            let (client, server) = if layer.v6 {
                (DHCP_V6_CLIENT_PORT, DHCP_V6_SERVER_PORT)
            } else {
                (DHCP_V4_CLIENT_PORT, DHCP_V4_SERVER_PORT)
            };
            add(&mut self.api, Filter::Dhcp { client, server })?;
            if policy.allow_dns && layer.connect {
                add(&mut self.api, Filter::Dns)?;
            }
            let nets: Vec<IpNet> = remote.iter().filter(|n| matches!(n, IpNet::V6(_)) == layer.v6).copied().collect();
            if !nets.is_empty() {
                add(&mut self.api, Filter::Remote(&nets))?;
            }
            add(&mut self.api, Filter::BlockAll)?;
        }

        let mut missing = Vec::new();
        let mut failed = false;
        let apps: Vec<PathBuf> = self.self_exe.iter().chain(policy.allow_apps.iter()).cloned().collect();
        for app in apps {
            let key = format!("allow:{}", normalize_path(&app));
            if !self.api.may_exist(&app) {
                warnings.push((key, format!("例外程序不存在，暂时跳过: {}", app.display())));
                missing.push(app);
                continue;
            }
            match self.add_app_filters(&app, true, layers)? {
                Ok(mut v) => {
                    added.append(&mut v);
                    ok_keys.push(key);
                }
                Err(e) => {
                    failed = true;
                    warnings.push((key, format!("无法放行例外程序 {}，稍后重试: {e:#}", app.display())));
                }
            }
        }
        Ok(GlobalAdded { ids: added, missing, failed })
    }

    fn report(&mut self, ok_keys: &[String], warnings: Vec<(String, String)>) {
        for k in ok_keys {
            self.warned.remove(k);
        }
        for (k, msg) in warnings {
            if self.warned.insert(k) {
                log::warn!("{msg}");
            }
        }
    }

    /// 在一个事务里让阻断过滤器与规则一致：为缺少的程序添加、为多余的程序删除，
    /// 全局断网规则有变化时整体替换。整个过程没有"先全部删除再添加"的放行空档。
    ///
    /// 新的整套阻断加上之后，放行期间为同一范围保留的 IPv6 过滤器在同一个事务里删除；
    /// 事务失败时两边都保持原样，记录与 WFP 一致。
    fn sync_filters(&mut self) -> Result<Synced> {
        let wanted: HashMap<String, PathBuf> =
            self.rules.apps.iter().map(|p| (normalize_path(p), p.clone())).collect();
        let to_remove: Vec<String> = self.filters.keys().filter(|k| !wanted.contains_key(*k)).cloned().collect();
        let to_add: Vec<(String, PathBuf)> = wanted
            .iter()
            .filter(|(k, _)| !self.filters.contains_key(*k))
            .map(|(k, p)| (k.clone(), p.clone()))
            .collect();
        let want_global = self.rules.block_all.clone();
        let api = &self.api;
        // 全局部分只在规则变了、上次有例外程序添加失败、或缺的例外程序现在出现了时才重建：
        // 例外程序仍然不存在时重建也加不上它，只是白白开一个事务
        let global_stale = match (&self.global, &want_global) {
            (None, None) => false,
            (Some(g), Some(p)) => g.policy != *p || g.failed || g.missing.iter().any(|a| api.may_exist(a)),
            _ => true,
        };
        // 仍然不存在的程序加不上：只有它们时不开事务（定时重试照旧，程序出现后再加）
        let work = !to_remove.is_empty() || global_stale || to_add.iter().any(|(_, p)| api.may_exist(p));
        if !work {
            for (k, app) in &to_add {
                if self.warned.insert(k.clone()) {
                    log::warn!("程序不存在，暂时跳过: {}", app.display());
                }
            }
            self.pending = to_add.into_iter().map(|(k, _)| k).collect();
            return Ok(Synced::default());
        }

        let mut added: Vec<(String, PathBuf, Vec<Fid>)> = Vec::new();
        let mut pending = HashSet::new();
        let mut warnings = Vec::new();
        let mut ok_keys = Vec::new();
        let mut new_global: Option<Option<Global>> = None;
        let mut released: Vec<String> = Vec::new();
        let mut released_global = false;
        self.in_transaction(|fw| {
            let remove_ids: Vec<u64> = to_remove.iter().flat_map(|k| ids(&fw.filters[k]).collect::<Vec<_>>()).collect();
            fw.delete_all(&remove_ids)?;
            // 单个程序失败（文件不存在、路径无效等）只跳过它，不影响其他程序的阻断
            for (k, app) in &to_add {
                if !fw.api.may_exist(app) {
                    pending.insert(k.clone());
                    warnings.push((k.clone(), format!("程序不存在，暂时跳过: {}", app.display())));
                    continue;
                }
                match fw.add_app_filters(app, false, &all_layers())? {
                    Ok(v) => {
                        // 整套阻断已经覆盖 IPv6：放行期间保留的那部分在同一个事务里撤掉
                        if let Some(old) = fw.retained.get(k).cloned() {
                            fw.delete_all(&old)?;
                            released.push(k.clone());
                        }
                        ok_keys.push(k.clone());
                        added.push((k.clone(), app.clone(), v));
                    }
                    Err(e) => {
                        pending.insert(k.clone());
                        warnings.push((k.clone(), format!("无法阻断 {}，稍后重试: {e:#}", app.display())));
                    }
                }
            }
            if global_stale {
                let old: Vec<u64> = fw.global.as_ref().map(|g| ids(&g.ids).collect()).unwrap_or_default();
                fw.delete_all(&old)?;
                new_global = Some(match &want_global {
                    Some(p) => {
                        let g = fw.add_global_filters(p, &all_layers(), &mut warnings, &mut ok_keys)?;
                        if let Some(old) = fw.retained_global.clone() {
                            fw.delete_all(&old)?;
                            released_global = true;
                        }
                        let complete = g.missing.is_empty() && !g.failed;
                        Some(Global { policy: p.clone(), ids: g.ids, complete, failed: g.failed, missing: g.missing })
                    }
                    None => None,
                });
            }
            Ok(())
        })?;

        // 事务已提交：现在才转移所有权
        self.report(&ok_keys, warnings);
        self.pending = pending;
        for k in &released {
            self.retained.remove(k);
        }
        if released_global {
            self.retained_global = None;
        }
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
        for (k, app, v) in added {
            self.filters.insert(k, v);
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

    /// 让「始终阻断 IPv6」的过滤器与规则一致（与阻断状态无关）。
    ///
    /// 在一个事务里：删除不再受控的程序、为新程序添加、全局断网规则变化时整体替换。
    /// 已经生效的程序阻断不会被重建，新程序加不上只记下来（报告具体路径并稍后重试）；
    /// 删除失败或全局部分的基础规则失败时回滚整个事务，原来的保护保持不变。
    fn sync_v6guard(&mut self) -> Result<()> {
        if !self.rules.block_ipv6 {
            if let Some(g) = &self.v6guard {
                let list = g.all_ids();
                self.in_transaction(|fw| fw.delete_all(&list))?;
                log::info!("已移除「始终阻断 IPv6」的 {} 个过滤器", list.len());
            }
            self.v6guard = None;
            return Ok(());
        }
        let first = self.v6guard.is_none();
        let guard = self.v6guard.get_or_insert_with(V6Guard::default);
        let wanted: HashMap<String, PathBuf> =
            self.rules.apps.iter().map(|p| (normalize_path(p), p.clone())).collect();
        let to_remove: Vec<String> = guard.apps.keys().filter(|k| !wanted.contains_key(*k)).cloned().collect();
        // 还没加上的（新程序、之前不存在的、之前添加失败的）都在这里；仍然不存在的不必进事务
        let to_add: Vec<(String, PathBuf)> = wanted
            .iter()
            .filter(|(k, _)| !guard.apps.contains_key(*k))
            .map(|(k, p)| (k.clone(), p.clone()))
            .collect();
        let want_global = self.rules.block_all.clone();
        let api = &self.api;
        let global_stale = match (&guard.global, &want_global) {
            (None, None) => false,
            (Some(g), Some(p)) => g.policy != *p || g.failed || g.missing.iter().any(|a| api.may_exist(a)),
            _ => true,
        };
        let work = !to_remove.is_empty() || global_stale || to_add.iter().any(|(_, p)| api.may_exist(p));
        if !work {
            guard.missing = to_add.into_iter().collect();
            guard.failed.clear();
            return Ok(());
        }

        let old_global_ids: Vec<u64> = guard.global.as_ref().map(|g| g.ids.clone()).unwrap_or_default();
        let remove_ids: Vec<u64> = to_remove.iter().flat_map(|k| guard.apps[k].iter().copied()).collect();
        let mut added: Vec<(String, Vec<u64>)> = Vec::new();
        let mut missing = HashMap::new();
        let mut failed = HashSet::new();
        let mut warnings = Vec::new();
        let mut ok_keys = Vec::new();
        let mut new_global: Option<Option<V6Global>> = None;
        let r = self.in_transaction(|fw| {
            fw.delete_all(&remove_ids)?;
            let layers = v6_layers();
            for (k, app) in &to_add {
                if !fw.api.may_exist(app) {
                    missing.insert(k.clone(), app.clone());
                    warnings.push((format!("v6:{k}"), format!("程序不存在，暂时跳过: {}", app.display())));
                    continue;
                }
                match fw.add_app_filters(app, false, &layers)? {
                    Ok(v) => {
                        ok_keys.push(format!("v6:{k}"));
                        added.push((k.clone(), ids(&v).collect()));
                    }
                    Err(e) => {
                        failed.insert(k.clone());
                        warnings.push((format!("v6:{k}"), format!("无法阻断 {} 的 IPv6，稍后重试: {e:#}", app.display())));
                    }
                }
            }
            if global_stale {
                fw.delete_all(&old_global_ids)?;
                new_global = Some(match &want_global {
                    Some(p) => {
                        let g = fw.add_global_filters(p, &layers, &mut warnings, &mut ok_keys)?;
                        Some(V6Global { policy: p.clone(), ids: ids(&g.ids).collect(), missing: g.missing, failed: g.failed })
                    }
                    None => None,
                });
            }
            Ok(())
        });
        if let Err(e) = r {
            // 整个事务回滚：原来的过滤器都还在。全局部分要求加上却失败时记下，定时重试、界面上提示
            let guard = self.v6guard.as_mut().expect("上面已经创建");
            guard.global_failed = global_stale && want_global.is_some();
            for (k, _) in &to_add {
                guard.failed.insert(k.clone());
            }
            return Err(e);
        }

        self.report(&ok_keys, warnings);
        let guard = self.v6guard.as_mut().expect("上面已经创建");
        for k in &to_remove {
            guard.apps.remove(k);
        }
        let added_n = added.len();
        for (k, v) in added {
            guard.apps.insert(k, v);
        }
        guard.missing = missing;
        guard.failed = failed;
        guard.global_failed = false;
        if let Some(g) = new_global {
            guard.global = g;
        }
        if first || added_n > 0 || !to_remove.is_empty() || global_stale {
            let n = guard.all_ids().len();
            log::info!(
                "始终阻断 IPv6：{n} 个过滤器（受控应用 {} 个{}{}）",
                guard.apps.len(),
                if guard.global.is_some() { "，全部 IPv6，例外同全局断网" } else { "" },
                if guard.missing.is_empty() && guard.failed.is_empty() {
                    String::new()
                } else {
                    format!("，{} 个暂未加上", guard.missing.len() + guard.failed.len())
                }
            );
        }
        Ok(())
    }

    fn v6guard_needs_retry(&self) -> bool {
        self.v6guard.as_ref().is_some_and(|g| {
            !g.failed.is_empty()
                || g.global_failed
                || g.missing.values().any(|p| self.api.may_exist(p))
                || g.global.as_ref().is_some_and(|x| x.failed || x.missing.iter().any(|p| self.api.may_exist(p)))
        })
    }

    /// 「始终阻断 IPv6」时，IPv6 阻断还没加上的受控程序（有主阻断规则的那些）。
    /// 放行时它们主阻断里 IPv6 层的过滤器要保留，否则 IPv6 没有任何覆盖。
    fn uncovered_v6(&self) -> HashSet<String> {
        if !self.rules.block_ipv6 {
            return HashSet::new();
        }
        self.filters
            .keys()
            .filter(|k| self.v6guard.as_ref().is_none_or(|g| !g.apps.contains_key(*k)))
            .cloned()
            .collect()
    }

    /// 全局断网时需要全局的 IPv6 兜底，但它没能加上（之前的版本也没有）。
    fn global_v6_uncovered(&self) -> bool {
        self.rules.block_ipv6
            && self.rules.block_all.is_some()
            && self.v6guard.as_ref().is_none_or(|g| g.global.is_none())
    }

    /// 撤掉不再需要保留的 IPv6 过滤器：IPv6 阻断已经补上、程序不再受控，或者不再需要。
    fn release_retained(&mut self) -> Result<()> {
        let wanted: HashSet<String> = self.rules.apps.iter().map(|p| normalize_path(p)).collect();
        let release: Vec<String> = self
            .retained
            .keys()
            .filter(|k| {
                !self.rules.block_ipv6
                    || !wanted.contains(*k)
                    || self.v6guard.as_ref().is_some_and(|g| g.apps.contains_key(*k))
            })
            .cloned()
            .collect();
        let release_global = self.retained_global.is_some() && !self.global_v6_uncovered();
        if release.is_empty() && !release_global {
            return Ok(());
        }
        let mut list: Vec<u64> = release.iter().flat_map(|k| self.retained[k].iter().copied()).collect();
        if release_global {
            list.extend(self.retained_global.iter().flatten().copied());
        }
        self.in_transaction(|fw| fw.delete_all(&list))?;
        for k in &release {
            self.retained.remove(k);
        }
        if release_global {
            self.retained_global = None;
        }
        log::info!(
            "IPv6 阻断已补上（或不再需要），撤掉放行期间保留的 {} 个过滤器（程序 {} 个{}）",
            list.len(),
            release.len(),
            if release_global { "，全局 IPv6" } else { "" }
        );
        Ok(())
    }

    /// 主动断开现有 IPv4 TCP 连接。全局断网刚生效时断开所有非例外连接，
    /// 否则只断开新加入阻断的受控程序。
    fn kill_connections(&self, s: &Synced, entering_block: bool) {
        if !self.rules.kill_existing_tcp {
            return;
        }
        match &self.global {
            Some(g) if entering_block || s.global_applied => {
                let apps: HashSet<String> = self.rules.apps.iter().map(|p| normalize_path(p)).collect();
                let allowed: HashSet<String> =
                    self.self_exe.iter().chain(g.policy.allow_apps.iter()).map(|p| normalize_path(p)).collect();
                self.api.kill(Kill::Global { apps, allowed, policy: g.policy.clone() });
            }
            _ if !s.added_apps.is_empty() => self.api.kill(Kill::Apps(s.added_apps.clone())),
            _ => {}
        }
    }
}

impl<A: Api> Firewall for Wfp<A> {
    fn block(&mut self) -> Result<()> {
        if self.blocked {
            return Ok(());
        }
        // 放行期间保留的 IPv6 过滤器在新阻断的同一个事务里撤掉；失败时保持原样（仍归 retained 所有）
        let s = self.sync_filters()?;
        self.blocked = true;
        self.kill_connections(&s, true);
        Ok(())
    }

    fn unblock(&mut self) -> Result<()> {
        if !self.blocked {
            return Ok(());
        }
        // IPv6 兜底没加上的范围（受控程序、全局断网）：放行后 IPv6 没有覆盖，
        // 只保留原阻断里 IPv6 层的过滤器（IPv4 照常放行），稍后重试
        let keep = self.uncovered_v6();
        let keep_global = self.global_v6_uncovered();
        let mut delete = Vec::new();
        let mut retain: Vec<(String, Vec<u64>)> = Vec::new();
        for (k, v) in &self.filters {
            if keep.contains(k) {
                delete.extend(v.iter().filter(|f| !f.v6).map(|f| f.id));
                retain.push((k.clone(), v.iter().filter(|f| f.v6).map(|f| f.id).collect()));
            } else {
                delete.extend(ids(v));
            }
        }
        let mut retain_global = None;
        if let Some(g) = &self.global {
            if keep_global {
                delete.extend(g.ids.iter().filter(|f| !f.v6).map(|f| f.id));
                retain_global = Some(g.ids.iter().filter(|f| f.v6).map(|f| f.id).collect::<Vec<_>>());
            } else {
                delete.extend(ids(&g.ids));
            }
        }
        self.in_transaction(|fw| fw.delete_all(&delete))?;
        log::info!("WFP 已删除 {} 个过滤器", delete.len());
        self.filters.clear();
        if !retain.is_empty() {
            log::warn!(
                "{} 个受控程序的 IPv6 阻断没能加上，放行期间仍阻断它们的 IPv6（IPv4 已放行），稍后重试: {}",
                retain.len(),
                retain.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join("、")
            );
        }
        for (k, v) in retain {
            self.retained.entry(k).or_default().extend(v);
        }
        if let Some(v) = retain_global {
            log::warn!("全局 IPv6 兜底规则没能加上，放行期间仍阻断全部 IPv6（IPv4 已放行），稍后重试");
            self.retained_global.get_or_insert_with(Vec::new).extend(v);
        }
        self.global = None;
        self.pending.clear();
        self.blocked = false;
        Ok(())
    }

    fn is_blocked(&self) -> bool {
        self.blocked
    }

    fn has_pending(&self) -> bool {
        (self.blocked && (!self.pending.is_empty() || self.global.as_ref().is_some_and(|g| !g.complete)))
            || self.v6guard_needs_retry()
            || !self.retained.is_empty()
            || self.retained_global.is_some()
    }

    fn set_rules(&mut self, rules: Rules) -> Result<()> {
        self.rules = rules;
        // 「始终阻断 IPv6」失败不影响主规则的同步，错误最后再返回
        let v6 = self.sync_v6guard();
        if self.blocked {
            let s = self.sync_filters()?;
            self.kill_connections(&s, false);
        }
        // IPv6 阻断补上之后才撤掉保留的过滤器
        self.release_retained()?;
        v6
    }

    fn degraded(&self) -> Option<String> {
        let mut parts = Vec::new();
        if !self.retained.is_empty() {
            parts.push(format!(
                "{} 个受控应用的「始终阻断 IPv6」规则没能加上，放行期间仍保留原来的 IPv6 阻断（IPv4 已放行）",
                self.retained.len()
            ));
        }
        if self.retained_global.is_some() {
            parts.push("全局断网的 IPv6 兜底规则没能加上，放行期间仍保留原来的全局 IPv6 阻断（IPv4 已放行）".to_owned());
        }
        if let Some(g) = &self.v6guard {
            // 放行后才加入的程序：没有可保留的旧阻断，IPv6 暂时没有覆盖
            let uncovered = g
                .failed
                .iter()
                .filter(|k| !self.retained.contains_key(*k) && !(self.blocked && self.filters.contains_key(*k)))
                .count();
            if uncovered > 0 {
                parts.push(format!("{uncovered} 个受控应用的「始终阻断 IPv6」规则没能加上，它们的 IPv6 暂时没有受到保护"));
            }
            if g.global_failed && g.global.is_none() && self.retained_global.is_none() && !self.blocked {
                parts.push("全局断网的 IPv6 兜底规则没能加上，IPv6 暂时没有受到保护".to_owned());
            }
        }
        // 例外放行失败只影响例外本身（相应的程序暂时也被阻断），不影响保护
        let exceptions = (self.blocked && self.global.as_ref().is_some_and(|g| g.failed))
            || self.v6guard.as_ref().and_then(|g| g.global.as_ref()).is_some_and(|g| g.failed);
        if exceptions {
            parts.push("有例外程序的放行规则没能加上（阻断照常生效，这些程序暂时也被阻断）".to_owned());
        }
        (!parts.is_empty()).then(|| format!("{}，每 5 秒重试一次", parts.join("；")))
    }
}

#[cfg(test)]
pub mod fake {
    //! 模拟的 WFP：事务、按条件注入失败，记录实际生效的过滤器。
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    /// 生效的一个过滤器：层、描述（例如 "block app C:\\a.exe"）。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Entry {
        pub layer: &'static str,
        pub v6: bool,
        pub what: String,
    }

    pub type FailFn = Box<dyn Fn(&Layer, &Filter<'_>) -> bool>;

    #[derive(Default)]
    pub struct State {
        pub committed: BTreeMap<u64, Entry>,
        staged: Option<(BTreeMap<u64, Entry>, Vec<u64>)>,
        next: u64,
        pub fail_add: Option<FailFn>,
        pub fail_commit: bool,
        pub missing: HashSet<PathBuf>,
        pub commits: u32,
        pub kills: u32,
    }

    impl State {
        /// 生效的过滤器描述（层:描述），排好序，便于比较。
        pub fn active(&self) -> Vec<String> {
            let mut v: Vec<String> = self.committed.values().map(|e| format!("{}:{}", e.layer, e.what)).collect();
            v.sort();
            v
        }

        pub fn count(&self, pred: impl Fn(&Entry) -> bool) -> usize {
            self.committed.values().filter(|e| pred(e)).count()
        }
    }

    #[derive(Clone, Default)]
    pub struct FakeApi(pub Rc<RefCell<State>>);

    impl Api for FakeApi {
        fn begin(&mut self) -> Result<()> {
            let mut s = self.0.borrow_mut();
            assert!(s.staged.is_none(), "嵌套事务");
            s.staged = Some((BTreeMap::new(), Vec::new()));
            Ok(())
        }
        fn commit(&mut self) -> Result<()> {
            let mut s = self.0.borrow_mut();
            if s.fail_commit {
                anyhow::bail!("FwpmTransactionCommit0 失败");
            }
            let (adds, dels) = s.staged.take().expect("没有事务");
            for id in dels {
                s.committed.remove(&id);
            }
            s.committed.extend(adds);
            s.commits += 1;
            Ok(())
        }
        fn abort(&mut self) {
            self.0.borrow_mut().staged = None;
        }
        fn add(&mut self, layer: &Layer, f: &Filter<'_>) -> Result<u64> {
            let mut s = self.0.borrow_mut();
            if s.fail_add.as_ref().is_some_and(|fail| fail(layer, f)) {
                anyhow::bail!("FwpmFilterAdd0({}, {}) 失败", f.describe(), layer.name);
            }
            s.next += 1;
            let id = s.next;
            let what = match f {
                Filter::App { path, .. } => format!("{} {}", f.describe(), path.display()),
                _ => f.describe().to_owned(),
            };
            let (adds, _) = s.staged.as_mut().expect("事务外添加");
            adds.insert(id, Entry { layer: layer.name, v6: layer.v6, what });
            Ok(id)
        }
        fn delete(&mut self, id: u64) -> Result<()> {
            let mut s = self.0.borrow_mut();
            let in_committed = s.committed.contains_key(&id);
            let (adds, dels) = s.staged.as_mut().expect("事务外删除");
            if adds.remove(&id).is_some() {
                return Ok(());
            }
            if !in_committed || dels.contains(&id) {
                anyhow::bail!("FwpmFilterDeleteById0({id}) 失败：不存在");
            }
            dels.push(id);
            Ok(())
        }
        fn may_exist(&self, p: &Path) -> bool {
            !self.0.borrow().missing.contains(p)
        }
        fn kill(&self, _: Kill) {
            self.0.borrow_mut().kills += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::*;
    use super::*;

    fn wfp() -> (FakeApi, Wfp<FakeApi>) {
        let api = FakeApi::default();
        (api.clone(), Wfp::new(api, Some(PathBuf::from("C:\\eg\\egress-guard.exe"))))
    }

    fn rules(apps: &[&str], block_all: bool) -> Rules {
        Rules {
            apps: apps.iter().map(PathBuf::from).collect(),
            block_all: block_all.then(BlockAllPolicy::default),
            kill_existing_tcp: false,
            block_ipv6: true,
            v6_probe: false,
        }
    }

    fn fail_when(api: &FakeApi, f: impl Fn(&Layer, &Filter<'_>) -> bool + 'static) {
        api.0.borrow_mut().fail_add = Some(Box::new(f));
    }

    fn heal(api: &FakeApi) {
        api.0.borrow_mut().fail_add = None;
        api.0.borrow_mut().fail_commit = false;
    }

    fn is_block_all_v6(l: &Layer, f: &Filter<'_>) -> bool {
        l.v6 && matches!(f, Filter::BlockAll)
    }

    /// 全局断网、受控应用为空：常驻的全局 IPv6 兜底没加上时，放行只撤 IPv4，保留原全局阻断的 IPv6 层。
    #[test]
    fn global_mode_without_apps_keeps_v6_part_of_global_block() {
        let (api, mut w) = wfp();
        // 放行状态下打开全局断网：全局 IPv6 兜底失败（整个事务回滚）
        fail_when(&api, is_block_all_v6);
        assert!(w.set_rules(rules(&[], true)).is_err());
        assert!(api.0.borrow().committed.is_empty());
        assert!(w.has_pending());
        assert!(w.degraded().unwrap().contains("IPv6 暂时没有受到保护"), "{:?}", w.degraded());
        // 阻断：普通全局规则成功（只让 IPv6 兜底失败的条件不影响它：它在全部层上，IPv6 层也会失败，先放开）
        heal(&api);
        w.block().unwrap();
        // 再让 IPv6 兜底失败：controller 的重试会再次 set_rules
        fail_when(&api, is_block_all_v6);
        let _ = w.set_rules(rules(&[], true));
        // 放行：IPv4 放开，IPv6 层的全局阻断保留
        w.unblock().unwrap();
        {
            let s = api.0.borrow();
            assert!(s.count(|e| !e.v6) == 0, "IPv4 应该已经放行: {:?}", s.active());
            assert!(s.count(|e| e.v6 && e.what == "block all") == 2, "{:?}", s.active());
        }
        assert!(w.degraded().unwrap().contains("全局 IPv6 阻断"), "{:?}", w.degraded());
        assert!(w.has_pending());
        // 修好后重试：全局 IPv6 兜底加上，保留的那份撤掉，只剩 IPv6 兜底
        heal(&api);
        w.set_rules(rules(&[], true)).unwrap();
        let s = api.0.borrow();
        assert!(s.count(|e| !e.v6) == 0);
        assert_eq!(s.count(|e| e.what == "block all"), 2, "{:?}", s.active());
        drop(s);
        assert!(w.degraded().is_none() && !w.has_pending());
    }

    /// 放行后才加入的程序：IPv6 阻断加不上时没有旧规则可保留，要在降级说明里报告并重试。
    #[test]
    fn app_added_while_allowed_reports_missing_v6() {
        let (api, mut w) = wfp();
        w.set_rules(rules(&["C:\\a.exe"], false)).unwrap();
        fail_when(&api, |_, f| matches!(f, Filter::App { path, .. } if path.to_string_lossy().ends_with("b.exe")));
        w.set_rules(rules(&["C:\\a.exe", "C:\\b.exe"], false)).unwrap();
        assert!(w.has_pending());
        assert!(w.degraded().unwrap().contains("1 个受控应用"), "{:?}", w.degraded());
        heal(&api);
        w.set_rules(rules(&["C:\\a.exe", "C:\\b.exe"], false)).unwrap();
        assert!(w.degraded().is_none() && !w.has_pending());
        assert_eq!(api.0.borrow().count(|e| e.what.contains("b.exe")), 2);
    }

    /// 阻断期间受控程序或全局例外程序不存在：定时重试不开空事务，程序出现后的那次重试再加上。
    #[test]
    fn missing_apps_do_not_open_empty_transactions() {
        let (api, mut w) = wfp();
        let a = PathBuf::from("C:\\a.exe");
        let x = PathBuf::from("C:\\x.exe");
        api.0.borrow_mut().missing.extend([a.clone(), x.clone()]);
        let mut r = rules(&["C:\\a.exe"], true);
        r.block_all.as_mut().unwrap().allow_apps.push(x.clone());
        w.set_rules(r.clone()).unwrap();
        w.block().unwrap();
        assert!(w.has_pending());
        let commits = api.0.borrow().commits;
        for _ in 0..12 {
            w.set_rules(r.clone()).unwrap();
        }
        assert_eq!(api.0.borrow().commits, commits, "程序仍不存在时不应再提交事务");
        assert!(w.has_pending(), "程序出现之前仍要定时重试");
        // 受控程序出现：下一次重试加上它（主阻断和 IPv6 兜底各一个事务），全局部分不动
        api.0.borrow_mut().missing.remove(&a);
        w.set_rules(r.clone()).unwrap();
        let after_a = api.0.borrow().commits;
        assert!(after_a > commits);
        assert!(api.0.borrow().count(|e| e.what == "block app C:\\a.exe") >= 4);
        assert!(api.0.borrow().count(|e| e.what.contains("x.exe")) == 0);
        w.set_rules(r.clone()).unwrap();
        assert_eq!(api.0.borrow().commits, after_a, "例外程序仍不存在：不重建全局部分");
        // 全局例外程序出现：重建全局部分，放行它
        api.0.borrow_mut().missing.remove(&x);
        w.set_rules(r.clone()).unwrap();
        assert!(api.0.borrow().commits > after_a);
        assert!(api.0.borrow().count(|e| e.what.contains("x.exe")) > 0);
        assert!(!w.has_pending());
    }

    /// 保留了 IPv6 阻断之后再阻断失败、又改回放行：保留的过滤器仍归 retained，最终能撤掉，不残留。
    #[test]
    fn failed_block_keeps_retained_ownership() {
        let (api, mut w) = wfp();
        fail_when(&api, |l, f| l.v6 && matches!(f, Filter::App { .. }));
        let _ = w.set_rules(rules(&["C:\\a.exe"], false));
        heal(&api);
        w.block().unwrap();
        // 放行：a 的 IPv6 兜底没加上，只保留它主阻断的 IPv6 层
        fail_when(&api, |l, f| l.v6 && matches!(f, Filter::App { .. }));
        w.unblock().unwrap();
        assert_eq!(api.0.borrow().active(), vec!["accept-v6:block app C:\\a.exe", "connect-v6:block app C:\\a.exe"]);
        // 再次阻断失败（提交失败）：什么都没变
        api.0.borrow_mut().fail_commit = true;
        assert!(w.block().is_err());
        assert!(!w.is_blocked());
        assert_eq!(api.0.borrow().committed.len(), 2);
        // 改回放行：已经是放行，直接返回；保留的过滤器仍有主人、仍在重试
        w.unblock().unwrap();
        assert!(w.has_pending());
        assert!(w.degraded().unwrap().contains("保留原来的 IPv6 阻断"));
        // 修好后重试：IPv6 兜底加上，保留的撤掉，没有残留
        heal(&api);
        w.set_rules(rules(&["C:\\a.exe"], false)).unwrap();
        assert_eq!(api.0.borrow().active(), vec!["accept-v6:block app C:\\a.exe", "connect-v6:block app C:\\a.exe"]);
        assert!(!w.has_pending() && w.degraded().is_none());
        // 阻断再放行：全部撤干净，只剩 IPv6 兜底
        w.block().unwrap();
        assert_eq!(api.0.borrow().committed.len(), 6);
        w.unblock().unwrap();
        assert_eq!(api.0.borrow().committed.len(), 2);
    }

    /// 保留期间阻断成功：新的整套阻断与撤掉保留的在同一个事务里，之后放行不会删到别人的过滤器。
    #[test]
    fn block_absorbs_retained_in_same_transaction() {
        let (api, mut w) = wfp();
        let v6_fail = |l: &Layer, f: &Filter<'_>| l.v6 && matches!(f, Filter::App { permit: false, .. } | Filter::BlockAll);
        // 应用和全局的 IPv6 兜底都没加上
        fail_when(&api, v6_fail);
        assert!(w.set_rules(rules(&["C:\\a.exe"], true)).is_err());
        heal(&api);
        w.block().unwrap();
        fail_when(&api, v6_fail);
        w.unblock().unwrap();
        assert_eq!(api.0.borrow().count(|e| !e.v6), 0);
        assert!(!w.retained.is_empty() && w.retained_global.is_some());
        assert!(w.degraded().is_some());
        heal(&api);
        let before = api.0.borrow().commits;
        w.block().unwrap();
        assert_eq!(api.0.borrow().commits, before + 1, "阻断和撤掉保留的在一个事务里");
        assert!(w.retained.is_empty() && w.retained_global.is_none());
        assert_eq!(api.0.borrow().count(|e| e.what == "block app C:\\a.exe"), 4, "{:?}", api.0.borrow().active());
        assert_eq!(api.0.borrow().count(|e| e.what == "block all"), 4);
        // IPv6 兜底补上后放行：只剩兜底
        w.set_rules(rules(&["C:\\a.exe"], true)).unwrap();
        w.unblock().unwrap();
        let s = api.0.borrow();
        assert!(s.count(|e| !e.v6) == 0, "{:?}", s.active());
        assert_eq!(s.count(|e| e.what == "block app C:\\a.exe"), 2);
        assert_eq!(s.count(|e| e.what == "block all"), 2);
    }

    /// 只有可选的例外放行失败：阻断照常生效并单独报告；放行时整机不被锁住。
    #[test]
    fn only_optional_exception_fails() {
        let (api, mut w) = wfp();
        let mut r = rules(&["C:\\a.exe"], true);
        r.block_all.as_mut().unwrap().allow_apps = vec![PathBuf::from("C:\\vpn.exe")];
        fail_when(&api, |_, f| matches!(f, Filter::App { path, permit: true } if path.to_string_lossy().ends_with("vpn.exe")));
        w.set_rules(r.clone()).unwrap();
        w.block().unwrap();
        assert!(w.is_blocked());
        assert_eq!(api.0.borrow().count(|e| e.what == "block all"), 6, "全部层的全局阻断 + IPv6 兜底");
        let d = w.degraded().unwrap();
        assert!(d.contains("例外程序") && !d.contains("没有受到保护"), "{d}");
        assert!(w.has_pending());
        w.unblock().unwrap();
        let s = api.0.borrow();
        assert_eq!(s.count(|e| !e.v6), 0, "{:?}", s.active());
        assert!(w.retained.is_empty() && w.retained_global.is_none());
    }

    /// 放行的事务提交失败：仍然阻断，记录不变。
    #[test]
    fn failed_unblock_commit_keeps_everything() {
        let (api, mut w) = wfp();
        w.set_rules(rules(&["C:\\a.exe"], true)).unwrap();
        w.block().unwrap();
        let before = api.0.borrow().active();
        api.0.borrow_mut().fail_commit = true;
        assert!(w.unblock().is_err());
        assert!(w.is_blocked());
        assert_eq!(api.0.borrow().active(), before);
        heal(&api);
        w.unblock().unwrap();
        assert_eq!(api.0.borrow().count(|e| !e.v6), 0);
    }

    #[test]
    fn kill_plan_matches() {
        let k = Kill::Global {
            apps: ["c:\\a.exe".to_owned()].into(),
            allowed: ["c:\\vpn.exe".to_owned()].into(),
            policy: BlockAllPolicy { allow_dns: true, ..Default::default() },
        };
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(k.matches(Some("c:\\a.exe"), ip, 53));
        assert!(!k.matches(Some("c:\\vpn.exe"), ip, 443));
        assert!(!k.matches(None, ip, 53));
        assert!(k.matches(None, ip, 443));
    }
}
