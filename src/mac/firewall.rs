//! macOS 拦截后端：pf 负责全局断网，网络扩展负责按应用阻断（规则经本地套接字推送，见 filterfeed）。

use std::sync::mpsc::Sender;

use anyhow::Result;

use super::pf::PfFirewall;
use crate::engine::Event;
use crate::filterfeed::{self, FeedFirewall};

pub struct MacFirewall;

impl MacFirewall {
    pub fn open(tx: Sender<Event>) -> Result<FeedFirewall> {
        let pf = PfFirewall::open()?;
        let hub = filterfeed::hub();
        // 扩展连上或断开时刷新界面上的状态
        let tx = std::sync::Mutex::new(tx);
        hub.set_notify(move || {
            let _ = tx.lock().unwrap().send(Event::Refresh);
        });
        Ok(FeedFirewall::new(Box::new(pf), hub))
    }
}
