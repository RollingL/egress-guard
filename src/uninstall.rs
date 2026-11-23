//! macOS 卸载后台服务的步骤（与平台无关，便于用模拟的系统操作测试）。
//!
//! 分两个阶段：先停止服务并确认它确实已经卸载，再取得 pf 锚点的独占锁；两者都确认之后才开始删除文件、
//! 清空规则。服务仍在运行、查询服务状态失败、或者另有实例（例如单独运行的命令行版本）持有锚点时，
//! 什么都不改动，报告原因，可以稍后重试。紧急解除（`egress-guard unblock`）不走这里，语义不变。

use anyhow::{bail, Result};

/// launchd 里服务的状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    Loaded,
    NotLoaded,
    /// 查询失败（不是「找不到服务」）：不能当作已经卸载。
    Unknown(String),
}

/// 卸载时要删除的东西。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item {
    Plist,
    BinDir,
    Socket,
    RunMarker,
}

/// 卸载用到的系统操作。
pub trait Ops {
    /// 锚点的独占锁，持有期间其他实例打不开 pf 后端。
    type Lock;
    fn bootout(&mut self) -> Result<()>;
    fn state(&mut self) -> ServiceState;
    /// 等一会儿再查（bootout 是异步的）。
    fn wait(&mut self);
    /// 取得锚点的独占锁；已被其他进程持有时返回 Ok(None)。
    fn lock_anchor(&mut self) -> Result<Option<Self::Lock>>;
    fn flush_anchor(&mut self) -> Result<()>;
    /// 删除；不存在不算错误。
    fn remove(&mut self, item: Item) -> Result<()>;
}

/// 等服务卸载最多查询的次数（每次之间 `wait`）。
const POLLS: usize = 20;

pub fn uninstall<O: Ops>(ops: &mut O) -> Result<()> {
    // 阶段一：停止服务，并确认它已经卸载
    let bootout = ops.bootout();
    let mut stopped = false;
    for i in 0..POLLS {
        match ops.state() {
            ServiceState::NotLoaded => {
                stopped = true;
                break;
            }
            ServiceState::Unknown(e) => {
                bail!("无法确认后台服务是否已经停止（{e}），没有删除任何文件或规则，请稍后重试");
            }
            ServiceState::Loaded if i + 1 < POLLS => ops.wait(),
            ServiceState::Loaded => {}
        }
    }
    if !stopped {
        match bootout {
            Err(e) => bail!("后台服务没有停止（{e:#}），没有删除任何文件或规则，请稍后重试"),
            Ok(()) => bail!("后台服务没有停止，没有删除任何文件或规则，请稍后重试"),
        }
    }
    // 阶段二：取得 pf 锚点的独占锁（正常运行的实例都持有它）
    let Some(lock) = ops.lock_anchor()? else {
        bail!(
            "另一个 egress-guard 实例（例如单独运行的命令行版本）正在管理 pf 规则，没有删除任何文件或规则；\
             请先结束它再卸载"
        );
    };
    // 阶段三：持锁清理
    let mut problems = Vec::new();
    for item in [Item::Plist] {
        if let Err(e) = ops.remove(item) {
            problems.push(format!("{e:#}"));
        }
    }
    if let Err(e) = ops.flush_anchor() {
        problems.push(format!("没能移除 pf 规则：{e:#}"));
    }
    for item in [Item::BinDir, Item::Socket, Item::RunMarker] {
        if let Err(e) = ops.remove(item) {
            problems.push(format!("{e:#}"));
        }
    }
    drop(lock);
    if !problems.is_empty() {
        bail!("卸载没有全部完成：{}", problems.join("；"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[derive(Default)]
    struct Fake {
        /// 依次返回的状态；用完后一直返回最后一个。
        states: Vec<ServiceState>,
        polled: usize,
        lock_held_elsewhere: bool,
        calls: Vec<String>,
    }

    impl Ops for Fake {
        type Lock = ();
        fn bootout(&mut self) -> Result<()> {
            self.calls.push("bootout".into());
            Ok(())
        }
        fn state(&mut self) -> ServiceState {
            let s = self.states.get(self.polled).or(self.states.last()).cloned().unwrap_or(ServiceState::NotLoaded);
            self.polled += 1;
            s
        }
        fn wait(&mut self) {}
        fn lock_anchor(&mut self) -> Result<Option<()>> {
            Ok((!self.lock_held_elsewhere).then_some(()))
        }
        fn flush_anchor(&mut self) -> Result<()> {
            self.calls.push("flush".into());
            Ok(())
        }
        fn remove(&mut self, item: Item) -> Result<()> {
            self.calls.push(format!("remove {item:?}"));
            Ok(())
        }
    }

    fn modified(f: &Fake) -> bool {
        f.calls.iter().any(|c| c != "bootout")
    }

    #[test]
    fn service_that_never_stops_changes_nothing() {
        let mut f = Fake { states: vec![ServiceState::Loaded], ..Default::default() };
        let e = uninstall(&mut f).unwrap_err();
        assert!(format!("{e:#}").contains("没有停止"), "{e:#}");
        assert!(!modified(&f), "{:?}", f.calls);
        assert_eq!(f.polled, POLLS);
    }

    #[test]
    fn failed_status_query_changes_nothing() {
        let mut f = Fake { states: vec![ServiceState::Loaded, ServiceState::Unknown("launchctl 崩溃".into())], ..Default::default() };
        let e = uninstall(&mut f).unwrap_err();
        assert!(format!("{e:#}").contains("无法确认"), "{e:#}");
        assert!(!modified(&f));
    }

    #[test]
    fn standalone_cli_holding_the_anchor_changes_nothing() {
        let mut f = Fake { lock_held_elsewhere: true, ..Default::default() };
        let e = uninstall(&mut f).unwrap_err();
        assert!(format!("{e:#}").contains("另一个 egress-guard 实例"), "{e:#}");
        assert!(!modified(&f));
    }

    #[test]
    fn normal_uninstall_is_repeatable() {
        for _ in 0..2 {
            let mut f = Fake { states: vec![ServiceState::Loaded, ServiceState::NotLoaded], ..Default::default() };
            uninstall(&mut f).unwrap();
            assert_eq!(
                f.calls,
                ["bootout", "remove Plist", "flush", "remove BinDir", "remove Socket", "remove RunMarker"]
            );
        }
    }

    #[test]
    fn cleanup_problems_are_reported_after_trying_everything() {
        struct Failing(Fake);
        impl Ops for Failing {
            type Lock = ();
            fn bootout(&mut self) -> Result<()> {
                Err(anyhow!("服务没有加载"))
            }
            fn state(&mut self) -> ServiceState {
                ServiceState::NotLoaded
            }
            fn wait(&mut self) {}
            fn lock_anchor(&mut self) -> Result<Option<()>> {
                Ok(Some(()))
            }
            fn flush_anchor(&mut self) -> Result<()> {
                Err(anyhow!("pfctl 失败"))
            }
            fn remove(&mut self, item: Item) -> Result<()> {
                self.0.calls.push(format!("{item:?}"));
                Ok(())
            }
        }
        let mut f = Failing(Fake::default());
        let e = uninstall(&mut f).unwrap_err();
        assert!(format!("{e:#}").contains("pf 规则"), "{e:#}");
        assert_eq!(f.0.calls, ["Plist", "BinDir", "Socket", "RunMarker"]);
    }
}
