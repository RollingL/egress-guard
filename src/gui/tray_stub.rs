//! Linux 等平台的托盘空实现（仅用于开发预览）。

use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use super::backend::Backend;
use super::icons::Shade;

#[allow(dead_code)]
pub struct TrayState {
    pub shade: Shade,
    pub tooltip: String,
}

#[allow(dead_code)]
pub struct TrayCtx {
    pub egui_ctx: eframe::egui::Context,
    pub show_requested: Arc<AtomicBool>,
    pub backend: Arc<dyn Backend>,
    pub window_title: String,
}

pub fn spawn(_t: TrayCtx, _rx: Receiver<TrayState>) {}
