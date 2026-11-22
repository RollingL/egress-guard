//! 非 Windows 平台的托盘空实现（仅用于开发预览）。

use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use super::icons::Shade;
use crate::engine::EngineHandle;

#[allow(dead_code)]
pub struct TrayState {
    pub shade: Shade,
    pub tooltip: String,
}

#[allow(dead_code)]
pub struct TrayCtx {
    pub egui_ctx: eframe::egui::Context,
    pub show_requested: Arc<AtomicBool>,
    pub engine: Arc<EngineHandle>,
    pub window_title: String,
}

pub fn spawn(_t: TrayCtx, _rx: Receiver<TrayState>) {}
