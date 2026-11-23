//! 网络持续抖动时，防抖不能无限期推迟检测（否则一直停在阻断状态）。
//! macOS 上检测走降权子进程，测试环境里不一定能运行，只在其他平台跑。
#![cfg(not(target_os = "macos"))]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use egress_guard::config::{Config, RawConfig};
use egress_guard::engine::{self, Event, Status};

#[test]
fn continuous_network_changes_still_get_checked() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut b = [0u8; 2048];
            let _ = s.read(&mut b);
            h.fetch_add(1, Ordering::SeqCst);
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n203.0.113.9\n");
        }
    });
    let mut raw = RawConfig { whitelist: vec!["203.0.113.0/24".into()], ..Default::default() };
    raw.detect.services = vec![format!("http://127.0.0.1:{port}/")];
    raw.behavior.debounce_ms = 500;
    let eng = engine::spawn(Config::from_raw(raw).unwrap(), true, false, None, Arc::new(|_: &Status| {}));
    // 等启动时的那次检测完成
    let t = Instant::now();
    while hits.load(Ordering::SeqCst) == 0 && t.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    let before = hits.load(Ordering::SeqCst);

    // 每 300ms 一次网络变化（比 500ms 的防抖短），持续 12 秒：上限是 10 秒，期间至少要检测一次
    let tx = eng.sender();
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(12) {
        let _ = tx.send(Event::NetworkChanged);
        std::thread::sleep(Duration::from_millis(300));
    }
    let during = hits.load(Ordering::SeqCst) - before;
    let _ = eng.shutdown();
    assert!(during >= 1, "网络持续变化的 12 秒里一次检测都没有");
}
