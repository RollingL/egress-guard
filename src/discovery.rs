//! 自动识别受控应用的关联程序：
//!
//! - **子进程**：周期性扫描进程树，受控应用（及已识别程序）的后代进程，即使是不同的 exe，
//!   也会被记录并加入阻断。识别结果写入 `learned-apps.txt`，下次启动时立即生效。
//! - **同目录**（可选）：受控应用 exe 所在目录（含子目录）下的全部 exe。
//!
//! 系统目录（Windows 的 %WINDIR%，macOS 的 /System、/usr/bin 等）下的程序永远不会被自动加入，
//! 以免误伤系统组件（例如应用调用 cmd.exe、powershell.exe、conhost.exe 或 /bin/sh）。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::{ChildMode, Config};
use crate::engine::Event;

/// 路径比较用的规范形式（统一反斜杠、小写），与运行平台无关。
pub fn normalize(p: &str) -> String {
    p.replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

pub fn normalize_path(p: &Path) -> String {
    normalize(&p.to_string_lossy())
}

/// Windows 路径的父目录（规范形式），与运行平台无关。
fn parent_dir(norm: &str) -> Option<&str> {
    norm.rsplit_once('\\').map(|(d, _)| d)
}

/// 本平台的系统目录（规范形式）。
pub fn default_system_dirs() -> Vec<String> {
    let dirs: Vec<String> = if cfg!(windows) {
        vec![std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into())]
    } else if cfg!(target_os = "macos") {
        ["/System", "/usr/bin", "/usr/sbin", "/usr/libexec", "/bin", "/sbin", "/Library/Apple"]
            .map(String::from)
            .to_vec()
    } else {
        ["/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/bin", "/sbin"].map(String::from).to_vec()
    };
    dirs.iter().map(|d| normalize(d)).collect()
}

/// 是否位于系统目录下。
pub fn is_system_path(norm: &str, system_dirs: &[String]) -> bool {
    system_dirs
        .iter()
        .any(|d| !d.is_empty() && (norm == d || norm.starts_with(&format!("{d}\\"))))
}

/// Windows 目录是否太宽泛，不能整体扫描（盘符根目录及一级目录、Program Files、Common Files、AppData 等）。
pub fn is_too_broad_dir(dir_norm: &str, system_dirs: &[String]) -> bool {
    if is_system_path(dir_norm, system_dirs) {
        return true;
    }
    // parts[0] 为盘符（或 UNC 主机名）。根目录和一级目录（如 C:\Tools）都可能装着许多无关程序。
    let parts: Vec<&str> = dir_norm.split('\\').filter(|s| !s.is_empty()).collect();
    if parts.len() < 3 {
        return true;
    }
    let rel = parts[1..].join("\\");
    const BROAD: &[&str] = &[
        "program files\\common files",
        "program files (x86)\\common files",
        "program files\\windowsapps",
        "programdata\\microsoft",
        "users\\public",
        "users\\default",
    ];
    if BROAD.contains(&rel.as_str()) {
        return true;
    }
    // users\<name>\... 下的常见公共目录
    if parts[1] == "users" {
        let rest = parts[3..].join("\\");
        const USER_BROAD: &[&str] = &[
            "",
            "appdata",
            "appdata\\local",
            "appdata\\roaming",
            "appdata\\locallow",
            "appdata\\local\\programs",
            "appdata\\local\\temp",
            "appdata\\local\\microsoft\\windowsapps",
            "desktop",
            "downloads",
            "documents",
        ];
        return USER_BROAD.contains(&rest.as_str());
    }
    false
}

/// 进程快照中的一项。
#[derive(Debug, Clone)]
pub struct ProcEntry {
    pub pid: u32,
    pub ppid: u32,
    /// 创建时间（任意单调单位，用于识别 PID 复用）。
    pub created: u64,
    /// exe 完整路径；无法获取时为空。
    pub path: String,
}

/// 一个程序所属的受控应用（规范路径）。同一个辅助程序可以被多个受控应用启动。
pub type Roots = BTreeSet<String>;

/// 程序（规范路径）属于哪个目标：完全相同，或者位于作为目标的 `.app` 应用包里
/// （macOS 上受控应用通常是应用包本身，例如 `/Applications/Foo.app`，进程路径是包内的可执行文件）。
/// 返回目标的键和值。
pub fn lookup_target<'a, V>(norm: &str, targets: &'a HashMap<String, V>) -> Option<(&'a String, &'a V)> {
    if let Some(kv) = targets.get_key_value(norm) {
        return Some(kv);
    }
    norm.match_indices(".app\\").find_map(|(i, _)| targets.get_key_value(&norm[..i + 4]))
}

/// 目标本身就是受控应用（而不是识别出来的关联程序）。
fn is_direct(key: &str, roots: &Roots) -> bool {
    roots.contains(key)
}

/// 找出所有“祖先链上有目标进程”的进程，以及最近那个目标祖先所属的受控应用。
/// `targets`：目标程序的规范路径 → 它所属的受控应用（规范路径）。
///
/// 受控应用本身（及其 .app 包里的程序）不算；已经识别过的辅助程序照样返回：
/// 它可能这次是被另一个受控应用启动的，需要补记这个来源。
/// 返回 (进程下标, 所属受控应用)。
pub fn descendants_of_targets(procs: &[ProcEntry], targets: &HashMap<String, Roots>) -> Vec<(usize, Roots)> {
    let by_pid: HashMap<u32, usize> = procs.iter().enumerate().map(|(i, p)| (p.pid, i)).collect();
    // 每个进程只规范化一次路径（祖先链会反复经过同一个进程）
    let hits: Vec<Option<(&String, &Roots)>> = procs
        .iter()
        .map(|p| if p.path.is_empty() { None } else { lookup_target(&normalize(&p.path), targets) })
        .collect();
    let target_of = |p: &ProcEntry| by_pid.get(&p.pid).and_then(|&i| hits[i]);
    let mut out = Vec::new();
    for (i, p) in procs.iter().enumerate() {
        if p.pid <= 4 || hits[i].is_some_and(|(k, r)| is_direct(k, r)) {
            continue;
        }
        let mut cur = p;
        for _ in 0..32 {
            let Some(&pi) = by_pid.get(&cur.ppid) else { break };
            let parent = &procs[pi];
            // 创建时间未知（0）时无法排除 PID 复用，保守起见断开链条；
            // 父进程比子进程晚创建，说明父 PID 已被复用，同样断开。
            if parent.pid == cur.pid
                || parent.created == 0
                || cur.created == 0
                || parent.created > cur.created
            {
                break;
            }
            if let Some((_, roots)) = target_of(parent) {
                out.push((i, roots.clone()));
                break;
            }
            cur = parent;
        }
    }
    out
}

/// 受控应用"所在目录"模式要扫描的目录。
///
/// - Windows 路径：exe 所在目录（太宽泛的目录除外）。
/// - Unix 路径（macOS）：应用所在的最外层 `.app` 包，例如
///   `/Applications/Foo.app/Contents/MacOS/foo` 扫描 `/Applications/Foo.app`；不在 `.app` 包里的程序不整体扫描。
pub fn app_scan_root(app: &Path, system_dirs: &[String]) -> Option<PathBuf> {
    let text = app.to_string_lossy();
    if crate::config::is_windows_absolute(&text) {
        let norm = normalize(&text);
        let dir_norm = parent_dir(&norm)?;
        if is_too_broad_dir(dir_norm, system_dirs) {
            return None;
        }
        return app.parent().map(Path::to_path_buf);
    }
    let bundle = app
        .ancestors()
        .filter(|a| a.extension().is_some_and(|e| e.eq_ignore_ascii_case("app")))
        .last()?;
    (!is_system_path(&normalize_path(bundle), system_dirs)).then(|| bundle.to_path_buf())
}

/// 是否为可执行程序：Windows 上看扩展名 .exe；Unix 上还看可执行权限位。
fn is_program(path: &Path, meta: &std::fs::Metadata) -> bool {
    if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")) {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 != 0 {
            return true;
        }
    }
    let _ = meta;
    false
}

/// 递归列出目录下的程序（限制深度和数量）。
pub fn scan_dir_exes(dir: &Path, max_depth: usize, max_count: usize) -> Vec<PathBuf> {
    let mut scan = DirWalk::new(dir);
    while !scan.step(max_depth, max_count, usize::MAX).0 {}
    scan.found
}

/// 扩展名是 .exe 的不必再取文件属性；其余的（Unix 上没有扩展名的可执行文件）才看权限位。
fn is_program_entry(path: &Path, entry: &std::fs::DirEntry) -> bool {
    if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")) {
        return true;
    }
    cfg!(unix) && entry.metadata().is_ok_and(|m| is_program(path, &m))
}

/// 可以分几次走完的目录遍历：每次最多看大约 `budget` 个条目（按整个目录计），下次从停下的位置继续。
struct DirWalk {
    stack: Vec<(PathBuf, usize)>,
    found: Vec<PathBuf>,
}

impl DirWalk {
    fn new(root: &Path) -> Self {
        Self { stack: vec![(root.to_path_buf(), 0)], found: Vec::new() }
    }

    /// 走一批；返回（是否已经走完，这一批看过的条目数）。
    fn step(&mut self, max_depth: usize, max_count: usize, budget: usize) -> (bool, usize) {
        let mut n = 0usize;
        while let Some((d, depth)) = self.stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for entry in rd.flatten() {
                n += 1;
                let Ok(ft) = entry.file_type() else { continue };
                let path = entry.path();
                if ft.is_dir() && !ft.is_symlink() {
                    if depth < max_depth {
                        self.stack.push((path, depth + 1));
                    }
                } else if ft.is_file() && is_program_entry(&path, &entry) {
                    self.found.push(path);
                    if self.found.len() >= max_count {
                        self.stack.clear();
                        return (true, n);
                    }
                }
            }
            if n >= budget {
                return (self.stack.is_empty(), n);
            }
        }
        (true, n)
    }
}

/// 一轮应用目录扫描（同目录模式）：依次走完每个根目录，可以分批进行。整轮完成后才替换旧结果。
struct AppDirScan {
    roots: Vec<(PathBuf, Roots)>,
    next: usize,
    walk: Option<DirWalk>,
    found: Vec<(PathBuf, Roots)>,
}

impl AppDirScan {
    fn new(roots: Vec<(PathBuf, Roots)>) -> Self {
        Self { roots, next: 0, walk: None, found: Vec::new() }
    }

    /// 走一批（最多大约 `budget` 个条目、`time` 时间）；返回是否整轮完成。
    fn step(&mut self, budget: usize, time: Duration) -> bool {
        let start = Instant::now();
        let mut left = budget;
        loop {
            if self.walk.is_none() {
                let Some((root, _)) = self.roots.get(self.next) else { return true };
                self.walk = Some(DirWalk::new(root));
            }
            let walk = self.walk.as_mut().unwrap();
            // macOS 应用包的辅助程序可能嵌套较深（Frameworks/…/Helpers/…app/Contents/MacOS）
            let (done, used) = walk.step(12, 1000, left);
            left = left.saturating_sub(used);
            if done {
                let owners = self.roots[self.next].1.clone();
                let walk = self.walk.take().unwrap();
                self.found.extend(walk.found.into_iter().map(|p| (p, owners.clone())));
                self.next += 1;
            }
            if left == 0 || start.elapsed() >= time {
                return self.next >= self.roots.len();
            }
        }
    }
}

/// 自动识别到的程序的来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    /// 受控应用启动的子进程。
    Child,
    /// 受控应用所在目录下的程序。
    AppDir,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtraApp {
    pub path: PathBuf,
    pub source: Source,
}

/// 已识别的子进程程序及其所属的受控应用，持久化为文本文件（每行"子程序路径<TAB>受控应用路径"，
/// 同一个子程序属于多个受控应用时有多行；与只有一个来源的旧文件兼容）。
/// 子程序只要还有一个所属应用在配置里就继续生效；全部移出配置后不再生效。
pub struct Learned {
    file: Option<PathBuf>,
    /// 规范路径 → (原始路径, 所属受控应用的规范路径)
    map: BTreeMap<String, (PathBuf, Roots)>,
}

impl Learned {
    pub fn load(file: Option<PathBuf>) -> Self {
        let mut map = BTreeMap::new();
        if let Some(text) = file.as_ref().and_then(|f| std::fs::read_to_string(f).ok()) {
            for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                // 没有所属应用的旧格式记录直接丢弃
                if let Some((child, root)) = line.split_once('\t') {
                    map.entry(normalize(child.trim()))
                        .or_insert_with(|| (PathBuf::from(child.trim()), Roots::new()))
                        .1
                        .insert(normalize(root.trim()));
                }
            }
        }
        Self { file, map }
    }

    /// 记下"这个子程序属于这个受控应用"，返回是否是新的关系。
    pub fn add(&mut self, path: &Path, root_norm: &str) -> bool {
        let key = normalize_path(path);
        let entry = self.map.entry(key).or_insert_with(|| (path.to_path_buf(), Roots::new()));
        if !entry.1.insert(root_norm.to_owned()) {
            return false;
        }
        self.save();
        true
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.save();
    }

    /// (规范路径, 原始路径, 所属受控应用的规范路径)
    pub fn iter(&self) -> impl Iterator<Item = (&String, &PathBuf, &Roots)> {
        self.map.iter().map(|(k, (p, r))| (k, p, r))
    }

    fn save(&self) {
        let Some(f) = &self.file else { return };
        let mut text = String::from("# egress-guard 自动识别的子进程程序：子程序路径<TAB>所属受控应用（可删除此文件以清空）\n");
        for (p, roots) in self.map.values() {
            for root in roots {
                text.push_str(&format!("{}\t{}\n", p.to_string_lossy(), root));
            }
        }
        // 原子替换：写到一半崩溃不会留下截断的记录
        if let Err(e) = crate::config::write_atomic(f, text.as_bytes(), None) {
            log::warn!("无法保存子进程记录 {}: {e}", f.display());
        }
    }
}

/// 识别线程使用的设置（随配置更新）。
#[derive(Debug, Clone, Default)]
pub struct WatchSettings {
    pub apps: Vec<PathBuf>,
    pub mode: ChildMode,
    pub include_app_dir: bool,
    pub exclude: Vec<PathBuf>,
    /// 设置版本号，变化时立即重扫目录。
    pub version: u64,
    /// 请求清空子进程记录。
    pub clear_learned: bool,
}

impl WatchSettings {
    pub fn from_config(cfg: &Config, version: u64) -> Self {
        Self {
            apps: cfg.apps.clone(),
            mode: cfg.children.mode,
            include_app_dir: cfg.children.include_app_dir,
            exclude: cfg.children.exclude.clone(),
            version,
            clear_learned: false,
        }
    }
}

/// 进程快照函数：Windows 上为真实实现，其他平台返回空。
pub type SnapshotFn = fn() -> Vec<ProcEntry>;

/// 子进程识别的扫描间隔：受控应用启动的子进程最多晚这么久被识别并加入阻断。
const POLL: Duration = Duration::from_secs(2);
/// 上一轮应用目录核对完成后，隔多久开始下一轮。
const DIR_RESCAN: Duration = Duration::from_secs(30);
/// 定期核对应用目录时，每次（每个扫描间隔）最多查看的条目数和花的时间：大目录分几秒走完，
/// 不会把同一线程里的子进程识别推迟几秒。
const DIR_STEP_ENTRIES: usize = 2000;
const DIR_STEP_TIME: Duration = Duration::from_millis(50);

/// 启动识别线程。识别结果变化时向引擎发送 `Event::ExtraApps`。
pub fn spawn(
    settings: Arc<Mutex<WatchSettings>>,
    learned_file: Option<PathBuf>,
    snapshot: SnapshotFn,
    system_dirs: Vec<String>,
    tx: Sender<Event>,
) {
    std::thread::Builder::new()
        .name("child-watch".into())
        .spawn(move || run(settings, learned_file, snapshot, system_dirs, tx))
        .expect("无法创建子进程识别线程");
}

/// 受控应用所在目录模式要扫描的根目录及其所属的受控应用（include_app_dir 开启时）。
/// `warn`：报告太宽泛、不整体扫描的目录（只在设置变化后报告一次）。
fn app_dir_roots(s: &WatchSettings, system_dirs: &[String], warn: bool) -> Vec<(PathBuf, Roots)> {
    if !s.include_app_dir {
        return Vec::new();
    }
    let mut dirs: BTreeMap<String, (PathBuf, Roots)> = BTreeMap::new();
    for app in &s.apps {
        let Some(root) = app_scan_root(app, system_dirs) else {
            if warn {
                log::warn!(
                    "目录太宽泛，不整体阻断: {}",
                    app.parent().map(|d| d.display().to_string()).unwrap_or_default()
                );
            }
            continue;
        };
        dirs.entry(normalize_path(&root)).or_insert_with(|| (root, Roots::new())).1.insert(normalize_path(app));
    }
    dirs.into_values().collect()
}

/// 一次扫描完受控应用所在的目录。返回 (exe, 所属受控应用规范路径)；
/// 几个受控应用在同一个目录里时，目录下的程序同时属于它们。
fn scan_app_dirs(roots: Vec<(PathBuf, Roots)>) -> Vec<(PathBuf, Roots)> {
    let mut scan = AppDirScan::new(roots);
    while !scan.step(usize::MAX, Duration::MAX) {}
    scan.found
}

/// 当前生效的目标程序：规范路径 → 所属受控应用（只算还在配置里的）。
/// 被忽略的、所属应用都已不在配置中的记录不计入。
fn targets(s: &WatchSettings, learned: &Learned, dir_exes: &[(PathBuf, Roots)]) -> HashMap<String, Roots> {
    let excluded: HashSet<String> = s.exclude.iter().map(|p| normalize_path(p)).collect();
    let apps: HashSet<String> = s.apps.iter().map(|p| normalize_path(p)).collect();
    let mut t: HashMap<String, Roots> = HashMap::new();
    for k in &apps {
        t.entry(k.clone()).or_default().insert(k.clone());
    }
    let mut add = |k: &String, roots: &Roots| {
        let active: Roots = roots.iter().filter(|r| apps.contains(*r)).cloned().collect();
        if !active.is_empty() && !excluded.contains(k) {
            t.entry(k.clone()).or_default().extend(active);
        }
    };
    if s.mode == ChildMode::Tree {
        for (k, _, roots) in learned.iter() {
            add(k, roots);
        }
    }
    for (p, roots) in dir_exes {
        add(&normalize_path(p), roots);
    }
    t
}

/// 汇总需要额外阻断的程序（去掉已配置的和被忽略的）。
fn collect(s: &WatchSettings, learned: &Learned, dir_exes: &[(PathBuf, Roots)]) -> Vec<ExtraApp> {
    let t = targets(s, learned, dir_exes);
    let mut seen: HashSet<String> = s.apps.iter().map(|p| normalize_path(p)).collect();
    let mut extra = Vec::new();
    for (k, p, _) in learned.iter() {
        if t.contains_key(k) && seen.insert(k.clone()) {
            extra.push(ExtraApp { path: p.clone(), source: Source::Child });
        }
    }
    for (p, _) in dir_exes {
        let k = normalize_path(p);
        if t.contains_key(&k) && seen.insert(k) {
            extra.push(ExtraApp { path: p.clone(), source: Source::AppDir });
        }
    }
    extra
}

/// 启动时同步计算一次（读取历史记录 + 目录扫描）。
pub fn initial_extra(s: &WatchSettings, learned_file: Option<PathBuf>, system_dirs: &[String]) -> Vec<ExtraApp> {
    let learned = Learned::load(learned_file);
    collect(s, &learned, &scan_app_dirs(app_dir_roots(s, system_dirs, false)))
}

/// 有没有目标进程（受控应用、已识别程序、同目录程序）正在运行。
fn any_target_running(procs: &[ProcEntry], targets: &HashMap<String, Roots>) -> bool {
    procs.iter().any(|p| !p.path.is_empty() && lookup_target(&normalize(&p.path), targets).is_some())
}

/// 根据一次进程快照记下受控应用（及已识别程序）启动的子程序和它们的来源。
/// 返回是否有目标进程正在运行（没有时不必找后代）。
fn learn_children(
    s: &WatchSettings,
    learned: &mut Learned,
    dir_exes: &[(PathBuf, Roots)],
    procs: &[ProcEntry],
    system_dirs: &[String],
) -> bool {
    let t = targets(s, learned, dir_exes);
    if !any_target_running(procs, &t) {
        return false;
    }
    let excluded: HashSet<String> = s.exclude.iter().map(|p| normalize_path(p)).collect();
    for (i, roots) in descendants_of_targets(procs, &t) {
        let p = &procs[i];
        if p.path.is_empty() {
            continue;
        }
        let norm = normalize(&p.path);
        if is_system_path(&norm, system_dirs) || excluded.contains(&norm) {
            continue;
        }
        // 已经是目标、而且已经属于这个受控应用（例如同目录扫描到的程序）：不用再记
        let have = lookup_target(&norm, &t).map(|(_, r)| r);
        let known = have.is_some();
        for root in &roots {
            if have.is_some_and(|r| r.contains(root)) {
                continue;
            }
            if learned.add(Path::new(&p.path), root) {
                if known {
                    log::info!("{} 也由 {root} 启动，记下这个来源 (PID {})", p.path, p.pid);
                } else {
                    log::warn!("识别到受控应用的子进程，加入阻断: {} (PID {})", p.path, p.pid);
                }
            }
        }
    }
    true
}

fn run(
    settings: Arc<Mutex<WatchSettings>>,
    learned_file: Option<PathBuf>,
    snapshot: SnapshotFn,
    system_dirs: Vec<String>,
    tx: Sender<Event>,
) {
    let mut learned = Learned::load(learned_file);
    let mut dir_exes: Vec<(PathBuf, Roots)> = Vec::new();
    // 目录结果对应的设置版本、上一轮核对完成的时刻、正在分批进行的这一轮核对
    let mut scanned_version: Option<u64> = None;
    let mut last_round = Instant::now();
    let mut round: Option<AppDirScan> = None;
    let mut last_sent: Option<Vec<ExtraApp>> = None;

    loop {
        // 引擎退出后只剩本线程持有设置，随之结束
        if Arc::strong_count(&settings) == 1 {
            return;
        }
        let s = {
            let mut g = settings.lock().unwrap();
            if std::mem::take(&mut g.clear_learned) {
                learned.clear();
                log::info!("已清空子进程识别记录");
            }
            g.clone()
        };

        // 第一次和设置变了时一次扫完（与以前一样立即生效）；之后每 DIR_RESCAN 完整核对一轮，
        // 分批进行，整轮完成后才替换旧结果
        if scanned_version != Some(s.version) {
            dir_exes = scan_app_dirs(app_dir_roots(&s, &system_dirs, true));
            scanned_version = Some(s.version);
            last_round = Instant::now();
            round = None;
        } else if s.include_app_dir {
            if round.is_none() && last_round.elapsed() >= DIR_RESCAN {
                round = Some(AppDirScan::new(app_dir_roots(&s, &system_dirs, false)));
            }
            if round.as_mut().is_some_and(|r| r.step(DIR_STEP_ENTRIES, DIR_STEP_TIME)) {
                dir_exes = round.take().unwrap().found;
                last_round = Instant::now();
            }
        }

        // 子进程识别
        if s.mode == ChildMode::Tree && !s.apps.is_empty() {
            learn_children(&s, &mut learned, &dir_exes, &snapshot(), &system_dirs);
        }

        let extra = collect(&s, &learned, &dir_exes);
        if last_sent.as_ref() != Some(&extra) {
            if tx.send(Event::ExtraApps(extra.clone())).is_err() {
                return; // 引擎已退出
            }
            last_sent = Some(extra);
        }

        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: u32, ppid: u32, created: u64, path: &str) -> ProcEntry {
        ProcEntry { pid, ppid, created, path: path.into() }
    }

    #[test]
    fn finds_descendants_across_exes() {
        let procs = vec![
            p(100, 1, 10, r"C:\Apps\Foo\foo.exe"),
            p(200, 100, 20, r"C:\Apps\Foo\helper.exe"),
            p(300, 200, 30, r"C:\Other\worker.exe"),
            p(400, 1, 40, r"C:\Apps\Bar\bar.exe"),
            p(500, 300, 50, ""),  // 路径未知，但仍可作为中间节点
            p(600, 500, 60, r"D:\x\deep.exe"),
        ];
        let root = normalize(r"C:\Apps\Foo\foo.exe");
        let targets: HashMap<String, Roots> = [(root.clone(), [root.clone()].into())].into();
        let found = descendants_of_targets(&procs, &targets);
        let mut pids: Vec<u32> = found.iter().map(|(i, _)| procs[*i].pid).collect();
        pids.sort();
        // 500 路径未知，但创建时间已知，可作为中间节点
        assert_eq!(pids, vec![200, 300, 500, 600]);
        assert!(found.iter().all(|(_, r)| r.len() == 1 && r.contains(&root)));
    }

    #[test]
    fn mac_bundle_processes_are_targets() {
        // 受控应用是 .app 包：包里的主程序、辅助程序都算目标本身，包外的子进程才需要识别
        let procs = vec![
            p(100, 1, 10, "/Applications/Foo.app/Contents/MacOS/Foo"),
            p(200, 100, 20, "/Applications/Foo.app/Contents/Frameworks/Foo Helper.app/Contents/MacOS/Foo Helper"),
            p(300, 200, 30, "/usr/local/bin/worker"),
            p(400, 1, 40, "/Applications/Foo.appx/Contents/MacOS/x"),
        ];
        let root = normalize("/Applications/Foo.app");
        let targets: HashMap<String, Roots> = [(root.clone(), [root.clone()].into())].into();
        assert_eq!(lookup_target(&normalize(&procs[1].path), &targets).map(|(k, _)| k), Some(&root));
        assert_eq!(lookup_target(&normalize(&procs[3].path), &targets), None);
        let found = descendants_of_targets(&procs, &targets);
        let pids: Vec<u32> = found.iter().map(|(i, _)| procs[*i].pid).collect();
        assert_eq!(pids, vec![300]);
    }

    #[test]
    fn pid_reuse_breaks_chain() {
        // 父 PID 100 已退出并被一个更晚创建的目标进程复用
        let procs = vec![p(100, 1, 99, r"C:\Apps\Foo\foo.exe"), p(200, 100, 20, r"C:\Other\x.exe")];
        let root = normalize(r"C:\Apps\Foo\foo.exe");
        let targets: HashMap<String, Roots> = [(root.clone(), [root].into())].into();
        assert!(descendants_of_targets(&procs, &targets).is_empty());
        // 父进程创建时间未知时，也不认定父子关系
        let procs = vec![p(100, 1, 0, r"C:\Apps\Foo\foo.exe"), p(200, 100, 20, r"C:\Other\x.exe")];
        assert!(descendants_of_targets(&procs, &targets).is_empty());
    }

    #[test]
    fn system_and_broad_dirs() {
        let win = vec![normalize(r"C:\Windows")];
        assert!(is_system_path(&normalize(r"C:\Windows\System32\cmd.exe"), &win));
        assert!(!is_system_path(&normalize(r"C:\WindowsApps\x.exe"), &win));
        assert!(is_too_broad_dir(&normalize(r"C:\"), &win));
        assert!(is_too_broad_dir(&normalize(r"C:\Program Files"), &win));
        assert!(is_too_broad_dir(&normalize(r"C:\Users\me\AppData\Local"), &win));
        assert!(is_too_broad_dir(&normalize(r"C:\Users\me\Downloads"), &win));
        assert!(is_too_broad_dir(&normalize(r"C:\Tools"), &win));
        assert!(is_too_broad_dir(&normalize(r"C:\Program Files\Common Files"), &win));
        assert!(is_too_broad_dir(&normalize(r"C:\Users\me\AppData\Local\Microsoft\WindowsApps"), &win));
        assert!(!is_too_broad_dir(&normalize(r"C:\Program Files\Common Files\Vendor"), &win));
        assert!(!is_too_broad_dir(&normalize(r"C:\Program Files\Google\Chrome\Application"), &win));
        assert!(!is_too_broad_dir(&normalize(r"C:\Users\me\AppData\Local\Programs\Telegram"), &win));
    }

    #[test]
    fn mac_bundle_scan_root() {
        let sys: Vec<String> = ["/System", "/usr/bin"].iter().map(|d| normalize(d)).collect();
        let root = |p: &str| app_scan_root(Path::new(p), &sys);
        assert_eq!(
            root("/Applications/Foo.app/Contents/MacOS/foo"),
            Some(PathBuf::from("/Applications/Foo.app"))
        );
        // 嵌套的辅助程序包：取最外层的 .app
        assert_eq!(
            root("/Applications/Foo.app/Contents/Frameworks/H.app/Contents/MacOS/h"),
            Some(PathBuf::from("/Applications/Foo.app"))
        );
        assert_eq!(root("/Applications/Foo.app"), Some(PathBuf::from("/Applications/Foo.app")));
        assert_eq!(root("/usr/local/bin/tool"), None);
        assert_eq!(root("/System/Applications/Safari.app/Contents/MacOS/Safari"), None);
        // Windows 路径仍按目录规则
        assert_eq!(root(r"C:\Tools\x.exe"), None);
        assert!(root(r"C:\Program Files\Vendor\App\app.exe").is_some());
    }

    #[test]
    fn learned_persists() {
        let dir = std::env::temp_dir().join(format!("eg-learned-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("learned-apps.txt");
        let mut l = Learned::load(Some(f.clone()));
        assert!(l.add(Path::new(r"C:\A\b.exe"), "c:\\a\\root.exe"));
        assert!(!l.add(Path::new(r"c:/a/B.EXE"), "c:\\a\\root.exe"));
        let l2 = Learned::load(Some(f.clone()));
        assert_eq!(l2.iter().count(), 1);
        assert!(l2.iter().next().unwrap().2.contains("c:\\a\\root.exe"));
        // 同一个子程序还属于另一个受控应用：多一行，重新载入后两个来源都在
        assert!(l.add(Path::new(r"C:\A\b.exe"), "c:\\other\\two.exe"));
        let l3 = Learned::load(Some(f.clone()));
        assert_eq!(l3.iter().next().unwrap().2.len(), 2);
        assert_eq!(std::fs::read_to_string(&f).unwrap().lines().filter(|l| !l.starts_with('#')).count(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// 没有目标进程在运行时直接返回（不找后代）；受控应用或已识别程序在运行时照常识别。
    #[test]
    fn reports_whether_any_target_is_running() {
        let sys = vec![normalize(r"C:\Windows")];
        let s = WatchSettings { apps: vec![PathBuf::from(r"C:\Apps\A\a.exe")], mode: ChildMode::Tree, ..Default::default() };
        let mut learned = Learned::load(None);
        let others = [p(10, 1, 1, r"C:\Other\x.exe"), p(11, 10, 2, r"C:\Other\y.exe")];
        assert!(!learn_children(&s, &mut learned, &[], &others, &sys));
        assert_eq!(learned.iter().count(), 0);
        assert!(learn_children(&s, &mut learned, &[], &[p(20, 1, 3, r"C:\Apps\A\A.EXE"), p(21, 20, 4, r"D:\h.exe")], &sys));
        assert_eq!(learned.iter().count(), 1);
        // 只剩已识别的辅助程序在运行：它的子进程也要识别
        assert!(learn_children(&s, &mut learned, &[], &[p(30, 1, 5, r"D:\h.exe")], &sys));
    }

    /// 两个独立的受控应用先后启动同一个（在两者目录之外的）辅助程序：两个来源都记下，
    /// 重启后仍在；移除任一个仍受控，移除最后一个才解除；显式忽略始终有效。
    #[test]
    fn shared_helper_keeps_all_roots() {
        let dir = std::env::temp_dir().join(format!("eg-shared-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("learned-apps.txt");
        let sys = vec![normalize(r"C:\Windows")];
        let (a, b, h) = (r"C:\Apps\A\a.exe", r"C:\Apps\B\b.exe", r"D:\Shared\helper.exe");
        let settings = |apps: &[&str]| WatchSettings {
            apps: apps.iter().map(PathBuf::from).collect(),
            mode: ChildMode::Tree,
            ..Default::default()
        };
        let both = settings(&[a, b]);
        let mut learned = Learned::load(Some(f.clone()));
        // A 启动 helper
        learn_children(&both, &mut learned, &[], &[p(10, 1, 1, a), p(11, 10, 2, h)], &sys);
        // B 启动同一个 helper（这时 helper 已经是目标，也要补记 B）
        learn_children(&both, &mut learned, &[], &[p(20, 1, 3, b), p(21, 20, 4, h)], &sys);
        let roots: Vec<&String> = learned.iter().next().unwrap().2.iter().collect();
        assert_eq!(roots, vec![&normalize(a), &normalize(b)]);

        // 重启后仍在
        let learned = Learned::load(Some(f.clone()));
        let paths = |s: &WatchSettings| -> Vec<String> {
            collect(s, &learned, &[]).iter().map(|e| e.path.to_string_lossy().into_owned()).collect()
        };
        assert_eq!(paths(&both), vec![h.to_string()]);
        assert_eq!(paths(&settings(&[b])), vec![h.to_string()], "移除 A 后 B 仍在使用");
        assert_eq!(paths(&settings(&[a])), vec![h.to_string()], "移除 B 后 A 仍在使用");
        assert!(paths(&settings(&[])).is_empty(), "两个都移除才解除");
        let mut excl = settings(&[a, b]);
        excl.exclude = vec![PathBuf::from(h)];
        assert!(paths(&excl).is_empty(), "显式忽略仍生效");

        // PID 复用：父进程比子进程晚创建，不继承来源
        let mut learned = Learned::load(None);
        learn_children(&both, &mut learned, &[], &[p(30, 1, 9, a), p(31, 30, 5, r"D:\X\other.exe")], &sys);
        assert_eq!(learned.iter().count(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn scans_exes() {
        let dir = std::env::temp_dir().join(format!("eg-scan-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.exe"), b"").unwrap();
        std::fs::write(dir.join("sub").join("b.EXE"), b"").unwrap();
        std::fs::write(dir.join("c.dll"), b"").unwrap();
        let mut found = scan_dir_exes(&dir, 8, 100);
        found.sort();
        assert_eq!(found.len(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// 分批扫描：每批只看一部分条目，下次接着走；整轮结果与一次扫完相同，深层新增的程序下一轮能找到。
    #[test]
    fn app_dir_scan_in_batches() {
        let dir = std::env::temp_dir().join(format!("eg-batch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["a", "b/c", "b/d/e"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
            for i in 0..5 {
                std::fs::write(dir.join(d).join(format!("{i}.exe")), b"").unwrap();
            }
        }
        let roots = || vec![(dir.clone(), Roots::from([String::from("app")]))];
        let sorted = |mut v: Vec<(PathBuf, Roots)>| {
            v.sort();
            v
        };
        let whole = sorted(scan_app_dirs(roots()));
        assert_eq!(whole.len(), 15);
        let mut scan = AppDirScan::new(roots());
        let mut steps = 1;
        while !scan.step(3, Duration::MAX) {
            steps += 1;
            assert!(steps < 100);
        }
        assert!(steps > 2, "应当分了几批：{steps}");
        assert_eq!(sorted(scan.found), whole);
        // 深层目录里新增程序：根目录和一级子目录的修改时间可能不变，下一轮仍能找到
        std::fs::write(dir.join("b/d/e/new.exe"), b"").unwrap();
        assert_eq!(scan_app_dirs(roots()).len(), 16);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn fake_snapshot() -> Vec<ProcEntry> {
        vec![
            p(100, 1, 10, r"C:\Apps\Foo\foo.exe"),
            p(200, 100, 20, r"C:\Apps\Foo\helper.exe"),
            p(300, 200, 30, r"D:\Tools\worker.exe"),
            p(310, 100, 31, r"C:\Windows\System32\cmd.exe"),
            p(320, 310, 32, r"C:\Windows\System32\conhost.exe"),
            p(400, 1, 40, r"C:\Other\unrelated.exe"),
        ]
    }

    fn recv_extra(rx: &std::sync::mpsc::Receiver<Event>) -> Vec<ExtraApp> {
        loop {
            match rx.recv_timeout(Duration::from_secs(5)).expect("没有收到识别结果") {
                Event::ExtraApps(x) => return x,
                _ => continue,
            }
        }
    }

    #[test]
    fn watcher_end_to_end() {
        let dir = std::env::temp_dir().join(format!("eg-watch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let learned = dir.join("learned-apps.txt");

        // 应用目录：用于测试 include_app_dir
        let app_dir = dir.join("Vendor").join("App.app"); // macOS/Linux 上按 .app 包扫描
        std::fs::create_dir_all(app_dir.join("bin")).unwrap();
        std::fs::write(app_dir.join("app.exe"), b"").unwrap();
        std::fs::write(app_dir.join("bin").join("updater.exe"), b"").unwrap();

        let settings = Arc::new(Mutex::new(WatchSettings {
            apps: vec![PathBuf::from(r"C:\Apps\Foo\foo.exe")],
            mode: ChildMode::Tree,
            ..Default::default()
        }));
        let (tx, rx) = std::sync::mpsc::channel();
        spawn(settings.clone(), Some(learned.clone()), fake_snapshot, vec![normalize(r"C:\Windows")], tx);

        // 首次结果：子进程识别（系统目录下的 cmd/conhost 被排除，无关进程不受影响）
        let mut x = recv_extra(&rx);
        if x.is_empty() {
            x = recv_extra(&rx);
        }
        let mut names: Vec<String> = x.iter().map(|e| e.path.to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, vec![r"C:\Apps\Foo\helper.exe".to_string(), r"D:\Tools\worker.exe".to_string()]);
        assert!(x.iter().all(|e| e.source == Source::Child));
        // 已持久化
        let text = std::fs::read_to_string(&learned).unwrap();
        assert!(text.contains("worker.exe") && !text.contains("cmd.exe"));

        // 忽略 worker.exe
        {
            let mut g = settings.lock().unwrap();
            g.exclude = vec![PathBuf::from(r"d:\tools\WORKER.EXE")];
            g.version = 1;
        }
        let x = recv_extra(&rx);
        assert_eq!(x.len(), 1);
        assert!(x[0].path.to_string_lossy().ends_with("helper.exe"));

        // 同目录模式 + 关闭子进程
        {
            let mut g = settings.lock().unwrap();
            g.apps = vec![app_dir.join("app.exe")];
            g.mode = ChildMode::Off;
            g.include_app_dir = true;
            g.version = 2;
        }
        let x = recv_extra(&rx);
        assert_eq!(x.len(), 1, "{x:?}");
        assert_eq!(x[0].source, Source::AppDir);
        assert!(x[0].path.ends_with("bin/updater.exe") || x[0].path.to_string_lossy().contains("updater.exe"));

        // 清空记录
        settings.lock().unwrap().clear_learned = true;
        let t = Instant::now();
        while std::fs::read_to_string(&learned).unwrap().contains("helper.exe") && t.elapsed() < Duration::from_secs(6) {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!std::fs::read_to_string(&learned).unwrap().contains("helper.exe"));

        std::fs::remove_dir_all(dir).unwrap();
    }
}
