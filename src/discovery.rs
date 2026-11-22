//! 自动识别受控应用的关联程序：
//!
//! - **子进程**：周期性扫描进程树，受控应用（及已识别程序）的后代进程，即使是不同的 exe，
//!   也会被记录并加入阻断。识别结果写入 `learned-apps.txt`，下次启动时立即生效。
//! - **同目录**（可选）：受控应用 exe 所在目录（含子目录）下的全部 exe。
//!
//! Windows 系统目录（%WINDIR%）下的程序永远不会被自动加入，以免误伤系统组件
//! （例如应用调用 cmd.exe、powershell.exe、conhost.exe）。

use std::collections::{BTreeMap, HashMap, HashSet};
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

/// 是否位于 Windows 系统目录下。
pub fn is_system_path(norm: &str, windir_norm: &str) -> bool {
    !windir_norm.is_empty() && (norm == windir_norm || norm.starts_with(&format!("{windir_norm}\\")))
}

/// 目录是否太宽泛，不能整体扫描（盘符根目录及一级目录、Program Files、Common Files、AppData 等）。
pub fn is_too_broad_dir(dir_norm: &str, windir_norm: &str) -> bool {
    if is_system_path(dir_norm, windir_norm) {
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

/// 找出所有“祖先链上有目标进程”且自身不是目标的进程。
/// `targets`：目标程序的规范路径 → 它所属的受控应用（规范路径）。
/// 返回 (进程下标, 所属受控应用)。
pub fn descendants_of_targets(procs: &[ProcEntry], targets: &HashMap<String, String>) -> Vec<(usize, String)> {
    let by_pid: HashMap<u32, usize> = procs.iter().enumerate().map(|(i, p)| (p.pid, i)).collect();
    let target_of = |p: &ProcEntry| {
        if p.path.is_empty() {
            None
        } else {
            targets.get(&normalize(&p.path))
        }
    };
    let mut out = Vec::new();
    for (i, p) in procs.iter().enumerate() {
        if p.pid <= 4 || target_of(p).is_some() {
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
            if let Some(root) = target_of(parent) {
                out.push((i, root.clone()));
                break;
            }
            cur = parent;
        }
    }
    out
}

/// 递归列出目录下的 exe（限制深度和数量）。
pub fn scan_dir_exes(dir: &Path, max_depth: usize, max_count: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    while let Some((d, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let path = entry.path();
            if ft.is_dir() && !ft.is_symlink() {
                if depth < max_depth {
                    stack.push((path, depth + 1));
                }
            } else if ft.is_file()
                && path.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe"))
            {
                out.push(path);
                if out.len() >= max_count {
                    return out;
                }
            }
        }
    }
    out
}

/// 自动识别到的程序的来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    /// 受控应用启动的子进程。
    Child,
    /// 受控应用所在目录下的程序。
    AppDir,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraApp {
    pub path: PathBuf,
    pub source: Source,
}

/// 已识别的子进程程序及其所属的受控应用，持久化为文本文件（每行"子程序路径<TAB>受控应用路径"）。
/// 受控应用被移出配置后，它名下的记录不再生效。
pub struct Learned {
    file: Option<PathBuf>,
    /// 规范路径 → (原始路径, 所属受控应用的规范路径)
    map: BTreeMap<String, (PathBuf, String)>,
}

impl Learned {
    pub fn load(file: Option<PathBuf>) -> Self {
        let mut map = BTreeMap::new();
        if let Some(text) = file.as_ref().and_then(|f| std::fs::read_to_string(f).ok()) {
            for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                // 没有所属应用的旧格式记录直接丢弃
                if let Some((child, root)) = line.split_once('\t') {
                    map.insert(normalize(child.trim()), (PathBuf::from(child.trim()), normalize(root.trim())));
                }
            }
        }
        Self { file, map }
    }

    /// 新增一项，返回是否为新项。
    pub fn add(&mut self, path: &Path, root_norm: &str) -> bool {
        let key = normalize_path(path);
        if self.map.contains_key(&key) {
            return false;
        }
        self.map.insert(key, (path.to_path_buf(), root_norm.to_owned()));
        self.save();
        true
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.save();
    }

    /// (规范路径, 原始路径, 所属受控应用的规范路径)
    pub fn iter(&self) -> impl Iterator<Item = (&String, &PathBuf, &String)> {
        self.map.iter().map(|(k, (p, r))| (k, p, r))
    }

    fn save(&self) {
        let Some(f) = &self.file else { return };
        let mut text = String::from("# egress-guard 自动识别的子进程程序：子程序路径<TAB>所属受控应用（可删除此文件以清空）\n");
        for (p, root) in self.map.values() {
            text.push_str(&format!("{}\t{}\n", p.to_string_lossy(), root));
        }
        if let Err(e) = std::fs::write(f, text) {
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

const POLL: Duration = Duration::from_millis(1000);
const DIR_RESCAN: Duration = Duration::from_secs(30);

/// 启动识别线程。识别结果变化时向引擎发送 `Event::ExtraApps`。
pub fn spawn(
    settings: Arc<Mutex<WatchSettings>>,
    learned_file: Option<PathBuf>,
    snapshot: SnapshotFn,
    windir: String,
    tx: Sender<Event>,
) {
    std::thread::Builder::new()
        .name("child-watch".into())
        .spawn(move || run(settings, learned_file, snapshot, normalize(&windir), tx))
        .expect("无法创建子进程识别线程");
}

/// 扫描受控应用所在目录（include_app_dir 开启时）。返回 (exe, 所属受控应用规范路径)。
fn scan_app_dirs(s: &WatchSettings, windir: &str) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    if !s.include_app_dir {
        return out;
    }
    let mut seen = HashSet::new();
    for app in &s.apps {
        let norm = normalize_path(app);
        let Some(dir_norm) = parent_dir(&norm) else { continue };
        if is_too_broad_dir(dir_norm, windir) {
            log::warn!(
                "目录太宽泛，不整体阻断: {}",
                app.parent().map(|d| d.display().to_string()).unwrap_or_default()
            );
            continue;
        }
        if seen.insert(dir_norm.to_owned()) {
            if let Some(dir) = app.parent() {
                out.extend(scan_dir_exes(dir, 8, 1000).into_iter().map(|p| (p, norm.clone())));
            }
        }
    }
    out
}

/// 当前生效的目标程序：规范路径 → 所属受控应用。被忽略的、所属应用已不在配置中的记录不计入。
fn targets(s: &WatchSettings, learned: &Learned, dir_exes: &[(PathBuf, String)]) -> HashMap<String, String> {
    let excluded: HashSet<String> = s.exclude.iter().map(|p| normalize_path(p)).collect();
    let mut t: HashMap<String, String> = HashMap::new();
    for app in &s.apps {
        let k = normalize_path(app);
        t.insert(k.clone(), k);
    }
    if s.mode == ChildMode::Tree {
        for (k, _, root) in learned.iter() {
            if t.get(root).is_some_and(|r| r == root) && !excluded.contains(k) {
                t.entry(k.clone()).or_insert_with(|| root.clone());
            }
        }
    }
    for (p, root) in dir_exes {
        let k = normalize_path(p);
        if !excluded.contains(&k) {
            t.entry(k).or_insert_with(|| root.clone());
        }
    }
    t
}

/// 汇总需要额外阻断的程序（去掉已配置的和被忽略的）。
fn collect(s: &WatchSettings, learned: &Learned, dir_exes: &[(PathBuf, String)]) -> Vec<ExtraApp> {
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
pub fn initial_extra(s: &WatchSettings, learned_file: Option<PathBuf>, windir: &str) -> Vec<ExtraApp> {
    let learned = Learned::load(learned_file);
    collect(s, &learned, &scan_app_dirs(s, &normalize(windir)))
}

fn run(
    settings: Arc<Mutex<WatchSettings>>,
    learned_file: Option<PathBuf>,
    snapshot: SnapshotFn,
    windir: String,
    tx: Sender<Event>,
) {
    let mut learned = Learned::load(learned_file);
    let mut dir_exes: Vec<(PathBuf, String)> = Vec::new();
    let mut last_scan: Option<(Instant, u64)> = None;
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

        let rescan = match last_scan {
            None => true,
            Some((t, v)) => v != s.version || t.elapsed() >= DIR_RESCAN,
        };
        if rescan {
            dir_exes = scan_app_dirs(&s, &windir);
            last_scan = Some((Instant::now(), s.version));
        }

        // 子进程识别
        if s.mode == ChildMode::Tree && !s.apps.is_empty() {
            let excluded: HashSet<String> = s.exclude.iter().map(|p| normalize_path(p)).collect();
            let t = targets(&s, &learned, &dir_exes);
            let procs = snapshot();
            for (i, root) in descendants_of_targets(&procs, &t) {
                let p = &procs[i];
                if p.path.is_empty() {
                    continue;
                }
                let norm = normalize(&p.path);
                if is_system_path(&norm, &windir) || excluded.contains(&norm) || t.contains_key(&norm) {
                    continue;
                }
                if learned.add(Path::new(&p.path), &root) {
                    log::warn!("识别到受控应用的子进程，加入阻断: {} (PID {})", p.path, p.pid);
                }
            }
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
        let targets: HashMap<String, String> = [(root.clone(), root.clone())].into();
        let found = descendants_of_targets(&procs, &targets);
        let mut pids: Vec<u32> = found.iter().map(|(i, _)| procs[*i].pid).collect();
        pids.sort();
        // 500 路径未知，但创建时间已知，可作为中间节点
        assert_eq!(pids, vec![200, 300, 500, 600]);
        assert!(found.iter().all(|(_, r)| r == &root));
    }

    #[test]
    fn pid_reuse_breaks_chain() {
        // 父 PID 100 已退出并被一个更晚创建的目标进程复用
        let procs = vec![p(100, 1, 99, r"C:\Apps\Foo\foo.exe"), p(200, 100, 20, r"C:\Other\x.exe")];
        let root = normalize(r"C:\Apps\Foo\foo.exe");
        let targets: HashMap<String, String> = [(root.clone(), root)].into();
        assert!(descendants_of_targets(&procs, &targets).is_empty());
        // 父进程创建时间未知时，也不认定父子关系
        let procs = vec![p(100, 1, 0, r"C:\Apps\Foo\foo.exe"), p(200, 100, 20, r"C:\Other\x.exe")];
        assert!(descendants_of_targets(&procs, &targets).is_empty());
    }

    #[test]
    fn system_and_broad_dirs() {
        let win = normalize(r"C:\Windows");
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
    fn learned_persists() {
        let dir = std::env::temp_dir().join(format!("eg-learned-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("learned-apps.txt");
        let mut l = Learned::load(Some(f.clone()));
        assert!(l.add(Path::new(r"C:\A\b.exe"), "c:\\a\\root.exe"));
        assert!(!l.add(Path::new(r"c:/a/B.EXE"), "c:\\a\\root.exe"));
        let l2 = Learned::load(Some(f.clone()));
        assert_eq!(l2.iter().count(), 1);
        assert_eq!(l2.iter().next().unwrap().2, "c:\\a\\root.exe");
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
        let app_dir = dir.join("Vendor").join("App");
        std::fs::create_dir_all(app_dir.join("bin")).unwrap();
        std::fs::write(app_dir.join("app.exe"), b"").unwrap();
        std::fs::write(app_dir.join("bin").join("updater.exe"), b"").unwrap();

        let settings = Arc::new(Mutex::new(WatchSettings {
            apps: vec![PathBuf::from(r"C:\Apps\Foo\foo.exe")],
            mode: ChildMode::Tree,
            ..Default::default()
        }));
        let (tx, rx) = std::sync::mpsc::channel();
        spawn(settings.clone(), Some(learned.clone()), fake_snapshot, r"C:\Windows".into(), tx);

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
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!std::fs::read_to_string(&learned).unwrap().contains("helper.exe"));

        std::fs::remove_dir_all(dir).unwrap();
    }
}
