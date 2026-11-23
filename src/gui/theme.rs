//! 苹果风格的配色、样式和自绘控件（开关、卡片、分组行、图标等）。

use std::sync::atomic::{AtomicBool, Ordering};

use eframe::egui::{
    self, epaint::Shadow, Align, Align2, Color32, CornerRadius, FontFamily, FontId, Layout, Margin,
    Pos2, Rect, Response, RichText, Sense, Shape, Stroke, Theme, Ui, Vec2,
};

/// 一套配色（浅色或深色）。颜色取自苹果人机界面指南的系统色。
#[derive(Clone, Copy)]
pub struct Palette {
    pub dark: bool,
    /// 内容区背景（分组背景）。
    pub bg: Color32,
    /// 卡片背景。
    pub card: Color32,
    /// 侧边栏背景。
    pub sidebar: Color32,
    /// 分隔线。
    pub separator: Color32,
    /// 主要文字。
    pub label: Color32,
    /// 次要文字。
    pub secondary: Color32,
    /// 三级文字（占位、提示）。
    pub tertiary: Color32,
    /// 填充色（灰色按钮、输入框）。
    pub fill: Color32,
    pub fill_hover: Color32,
    pub accent: Color32,
    pub green: Color32,
    pub red: Color32,
    pub orange: Color32,
    pub indigo: Color32,
    pub gray: Color32,
    pub teal: Color32,
    pub purple: Color32,
}

impl Palette {
    pub const LIGHT: Palette = Palette {
        dark: false,
        bg: Color32::from_rgb(0xF3, 0xF3, 0xF6),
        card: Color32::from_rgb(0xFF, 0xFF, 0xFF),
        sidebar: Color32::from_rgb(0xEA, 0xEA, 0xEE),
        separator: Color32::from_rgb(0xE3, 0xE3, 0xE8),
        label: Color32::from_rgb(0x17, 0x18, 0x1C),
        secondary: Color32::from_rgb(0x6B, 0x6E, 0x76),
        tertiary: Color32::from_rgb(0xB0, 0xB2, 0xB8),
        fill: Color32::from_rgb(0xEE, 0xEE, 0xF2),
        fill_hover: Color32::from_rgb(0xE2, 0xE2, 0xE8),
        accent: Color32::from_rgb(0x00, 0x6E, 0xE6),
        // 状态色比 iOS 系统色略深，作为文字时在白底上更易读
        green: Color32::from_rgb(0x1F, 0xA8, 0x4F),
        red: Color32::from_rgb(0xE5, 0x3A, 0x30),
        orange: Color32::from_rgb(0xE8, 0x8A, 0x00),
        indigo: Color32::from_rgb(0x58, 0x56, 0xD6),
        gray: Color32::from_rgb(0x8E, 0x8E, 0x93),
        teal: Color32::from_rgb(0x30, 0xB0, 0xC7),
        purple: Color32::from_rgb(0xA2, 0x4E, 0xD6),
    };

    pub const DARK: Palette = Palette {
        dark: true,
        bg: Color32::from_rgb(0x1B, 0x1B, 0x1E),
        card: Color32::from_rgb(0x2A, 0x2A, 0x2E),
        sidebar: Color32::from_rgb(0x22, 0x22, 0x25),
        separator: Color32::from_rgb(0x3A, 0x3A, 0x3C),
        label: Color32::from_rgb(0xF5, 0xF5, 0xF7),
        secondary: Color32::from_rgb(0x98, 0x98, 0x9D),
        tertiary: Color32::from_rgb(0x63, 0x63, 0x66),
        fill: Color32::from_rgb(0x3A, 0x3A, 0x3C),
        fill_hover: Color32::from_rgb(0x48, 0x48, 0x4A),
        accent: Color32::from_rgb(0x0A, 0x84, 0xFF),
        green: Color32::from_rgb(0x30, 0xD1, 0x58),
        red: Color32::from_rgb(0xFF, 0x45, 0x3A),
        orange: Color32::from_rgb(0xFF, 0x9F, 0x0A),
        indigo: Color32::from_rgb(0x5E, 0x5C, 0xE6),
        gray: Color32::from_rgb(0x8E, 0x8E, 0x93),
        teal: Color32::from_rgb(0x40, 0xC8, 0xE0),
        purple: Color32::from_rgb(0xBF, 0x5A, 0xF2),
    };

    pub fn of(ui: &Ui) -> Palette {
        if ui.visuals().dark_mode {
            Self::DARK
        } else {
            Self::LIGHT
        }
    }
}

// ---------------- 动效 ----------------

static REDUCED_MOTION: AtomicBool = AtomicBool::new(false);

/// 系统关闭了动画（Windows“设置 → 辅助功能 → 视觉效果 → 动画效果”，
/// macOS“辅助功能 → 显示 → 减弱动态效果”）时不播放动效。
pub fn reduced_motion() -> bool {
    REDUCED_MOTION.load(Ordering::Relaxed)
}

#[cfg(windows)]
fn system_animations_enabled() -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{
        SystemParametersInfoW, SPI_GETCLIENTAREAANIMATION, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
    };
    let mut on: i32 = 1;
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETCLIENTAREAANIMATION,
            0,
            Some(&mut on as *mut i32 as *mut std::ffi::c_void),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    }
    .is_ok();
    !ok || on != 0
}

#[cfg(target_os = "macos")]
fn system_animations_enabled() -> bool {
    let reduce = objc2_app_kit::NSWorkspace::sharedWorkspace().accessibilityDisplayShouldReduceMotion();
    !reduce && std::env::var_os("EGRESS_GUARD_REDUCED_MOTION").is_none()
}

#[cfg(not(any(windows, target_os = "macos")))]
fn system_animations_enabled() -> bool {
    std::env::var_os("EGRESS_GUARD_REDUCED_MOTION").is_none()
}

/// 0→1 的缓出动画进度；系统关闭动画时直接取终点。
pub fn ease(ctx: &egui::Context, id: egui::Id, on: bool, secs: f32) -> f32 {
    if reduced_motion() {
        return if on { 1.0 } else { 0.0 };
    }
    ctx.animate_bool_with_time_and_easing(id, on, secs, egui::emath::easing::cubic_out)
}

/// 粗体字体族名称（Windows 上为微软雅黑 Bold，macOS 上为冬青黑体 W6）。
pub const BOLD: &str = "bold";

pub fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(BOLD.into()))
}

/// 系统字体：(字体文件内容, 字形序号)。
type Face = (Vec<u8>, u32);

struct SystemFonts {
    regular: Option<Face>,
    bold: Option<Face>,
    mono: Option<Face>,
}

#[cfg(not(target_os = "macos"))]
fn system_fonts() -> SystemFonts {
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let fonts_dir = std::path::Path::new(&windir).join("Fonts");
    let read = |names: &[&str]| names.iter().find_map(|n| std::fs::read(fonts_dir.join(n)).ok());
    // msyh.ttc 的第 2 个字形是 Microsoft YaHei UI：行距更紧凑，专为界面设计
    let ui = if cfg!(windows) { 1 } else { 0 };
    SystemFonts {
        regular: read(&["msyh.ttc", "msyh.ttf", "Deng.ttf", "simhei.ttf", "simsun.ttc"]).map(|b| (b, ui)),
        bold: read(&["msyhbd.ttc", "msyhbd.ttf", "Dengb.ttf"]).map(|b| (b, ui)),
        mono: read(&["consola.ttf"]).map(|b| (b, 0)),
    }
}

/// macOS：冬青黑体简体中文（Hiragino Sans GB，W3 / W6 两个字重在同一个 ttc 里），
/// 找不到时退回华文黑体；等宽字体用 Menlo。
#[cfg(target_os = "macos")]
fn system_fonts() -> SystemFonts {
    let read = |cands: &[(&str, u32)]| cands.iter().find_map(|(p, i)| std::fs::read(p).ok().map(|b| (b, *i)));
    SystemFonts {
        regular: read(&[
            ("/System/Library/Fonts/Hiragino Sans GB.ttc", 0),
            ("/System/Library/Fonts/STHeiti Light.ttc", 0),
        ]),
        bold: read(&[
            ("/System/Library/Fonts/Hiragino Sans GB.ttc", 1),
            ("/System/Library/Fonts/STHeiti Medium.ttc", 0),
        ]),
        mono: read(&[("/System/Library/Fonts/Menlo.ttc", 0)]),
    }
}

/// 加载中文字体（常规 + 粗体）。egui 自带字体不含中文。
pub fn setup_fonts(ctx: &egui::Context) {
    load_fonts(ctx, 0.0, 0.0);
}

/// 中文字体的上升高度通常比下降大很多，egui 按行框排版时字形整体偏上：按钮、标签、
/// 输入框里的文字看起来不在正中。首帧（字体已载入）时量出字形相对行框中心的偏移，
/// 用 FontTweak 把常规、粗体两种字形各自移回中心。只在第一次调用时生效，返回是否调整了。
pub fn center_glyphs(ctx: &egui::Context) -> bool {
    static DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if DONE.swap(true, Ordering::Relaxed) {
        return false;
    }
    let regular = glyph_offset_factor(ctx, FontId::proportional(64.0));
    let bold_off = glyph_offset_factor(ctx, bold(64.0));
    log::debug!("字形垂直偏移：常规 {regular:.3} em，粗体 {bold_off:.3} em");
    if regular.abs() < 0.005 && bold_off.abs() < 0.005 {
        return false;
    }
    load_fonts(ctx, regular, bold_off);
    true
}

/// 「中」字的墨迹中心比行框中心高出多少（以字号为单位，正数表示需要下移）。
fn glyph_offset_factor(ctx: &egui::Context, font: FontId) -> f32 {
    let size = font.size;
    let g = ctx.fonts_mut(|f| f.layout_no_wrap("中".into(), font, Color32::WHITE));
    if !g.mesh_bounds.is_positive() {
        return 0.0;
    }
    ((g.rect.center().y - g.mesh_bounds.center().y) / size).clamp(-0.4, 0.4)
}

fn load_fonts(ctx: &egui::Context, regular_offset: f32, bold_offset: f32) {
    let mut fonts = egui::FontDefinitions::default();
    let defaults = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();

    let SystemFonts { regular, bold: bold_font, mono } = system_fonts();
    let ui_face = |(bytes, index): Face| {
        let mut d = egui::FontData::from_owned(bytes);
        d.index = index;
        d
    };
    let shifted = |mut d: egui::FontData, factor: f32| {
        d.tweak.y_offset_factor = factor;
        d
    };
    if let Some(face) = mono {
        fonts.font_data.insert("consolas".into(), ui_face(face).into());
        fonts.families.entry(FontFamily::Monospace).or_default().insert(0, "consolas".into());
    }
    if let Some(bytes) = regular {
        fonts.font_data.insert("cjk".into(), shifted(ui_face(bytes), regular_offset).into());
        fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "cjk".into());
        fonts.families.entry(FontFamily::Monospace).or_default().push("cjk".into());
    }
    let mut bold_family = Vec::new();
    if let Some(bytes) = bold_font {
        fonts.font_data.insert("cjk-bold".into(), shifted(ui_face(bytes), bold_offset).into());
        bold_family.push("cjk-bold".to_owned());
    } else if fonts.font_data.contains_key("cjk") {
        bold_family.push("cjk".to_owned());
    }
    bold_family.extend(defaults);
    fonts.families.insert(FontFamily::Name(BOLD.into()), bold_family);
    ctx.set_fonts(fonts);
}

/// 为浅色、深色两套主题设置苹果风格的样式；跟随系统切换。
pub fn apply_style(ctx: &egui::Context) {
    REDUCED_MOTION.store(!system_animations_enabled(), Ordering::Relaxed);
    let animation_time = if reduced_motion() { 0.0 } else { 0.14 };
    for (theme, p) in [(Theme::Light, Palette::LIGHT), (Theme::Dark, Palette::DARK)] {
        ctx.style_mut_of(theme, |style| {
            use egui::TextStyle;
            style.text_styles = [
                (TextStyle::Small, FontId::proportional(12.0)),
                (TextStyle::Body, FontId::proportional(14.0)),
                (TextStyle::Button, FontId::proportional(14.0)),
                (TextStyle::Heading, bold(22.0)),
                (TextStyle::Monospace, FontId::monospace(13.0)),
            ]
            .into();

            style.animation_time = animation_time;
            let s = &mut style.spacing;
            s.item_spacing = Vec2::new(8.0, 8.0);
            s.button_padding = Vec2::new(14.0, 5.0);
            s.interact_size = Vec2::new(40.0, 28.0);
            s.window_margin = Margin::same(16);

            let v = &mut style.visuals;
            v.dark_mode = p.dark;
            v.override_text_color = None;
            v.panel_fill = p.bg;
            v.window_fill = p.card;
            v.window_stroke = Stroke::new(1.0, p.separator);
            v.window_corner_radius = CornerRadius::same(12);
            v.window_shadow = Shadow {
                offset: [0, 8],
                blur: 28,
                spread: 0,
                color: Color32::from_black_alpha(if p.dark { 110 } else { 40 }),
            };
            v.popup_shadow = Shadow {
                offset: [0, 4],
                blur: 16,
                spread: 0,
                color: Color32::from_black_alpha(if p.dark { 90 } else { 30 }),
            };
            v.menu_corner_radius = CornerRadius::same(8);
            v.extreme_bg_color = p.fill;
            v.text_edit_bg_color = Some(p.fill);
            v.faint_bg_color = p.fill;
            v.hyperlink_color = p.accent;
            v.warn_fg_color = p.orange;
            v.error_fg_color = p.red;
            v.selection.bg_fill = p.accent.gamma_multiply(0.35);
            v.selection.stroke = Stroke::new(1.5, p.accent);

            let r = CornerRadius::same(7);
            let w = &mut v.widgets;
            w.noninteractive.bg_fill = p.card;
            w.noninteractive.weak_bg_fill = p.card;
            w.noninteractive.bg_stroke = Stroke::new(1.0, p.separator);
            w.noninteractive.fg_stroke = Stroke::new(1.0, p.label);
            w.noninteractive.corner_radius = r;

            for (wv, fill, fg) in [
                (&mut w.inactive, p.fill, p.label),
                (&mut w.hovered, p.fill_hover, p.label),
                (&mut w.active, p.fill_hover, p.label),
                (&mut w.open, p.fill_hover, p.label),
            ] {
                wv.bg_fill = fill;
                wv.weak_bg_fill = fill;
                wv.bg_stroke = Stroke::NONE;
                wv.fg_stroke = Stroke::new(1.0, fg);
                wv.corner_radius = r;
                wv.expansion = 0.0;
            }
            w.hovered.bg_stroke = Stroke::new(1.0, p.separator);
            w.active.bg_stroke = Stroke::new(1.5, p.accent);
        });
    }
}

// ---------------- 布局积木 ----------------

/// 大标题 + 副标题（类似"系统设置"每个页面的顶部）。
pub fn page_title(ui: &mut Ui, p: &Palette, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).font(bold(26.0)).color(p.label));
    if !subtitle.is_empty() {
        ui.label(RichText::new(subtitle).color(p.secondary));
    }
    ui.add_space(10.0);
}

/// 分组标题（卡片上方的灰色小字）。
pub fn section(ui: &mut Ui, p: &Palette, text: &str) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add_space(12.0);
        ui.label(RichText::new(text).size(12.5).color(p.secondary));
    });
    ui.add_space(-2.0);
}

/// 分组下方的说明文字。
pub fn footnote(ui: &mut Ui, p: &Palette, text: &str) {
    egui::Frame::new().inner_margin(Margin { left: 12, right: 12, top: 0, bottom: 0 }).show(ui, |ui| {
        ui.label(RichText::new(text).size(12.0).color(p.secondary));
    });
}

/// 白色圆角卡片，宽度撑满。
pub fn card<R>(ui: &mut Ui, p: &Palette, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(p.card)
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(16, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// 卡片内行与行之间的细分隔线。
pub fn hairline(ui: &mut Ui, p: &Palette) {
    hairline_inset(ui, p, 0.0);
}

/// 左侧缩进的分隔线：行首有图标时从文字处开始画（与 macOS 列表一致）。
pub fn hairline_inset(ui: &mut Ui, p: &Palette, inset: f32) {
    let rect = ui.available_rect_before_wrap();
    let y = ui.cursor().top() + 1.0;
    ui.painter().line_segment(
        [Pos2::new(rect.left() + inset, y), Pos2::new(rect.right() + 16.0, y)],
        Stroke::new(0.7, p.separator),
    );
    ui.add_space(3.0);
}

/// 列表行首图标的宽度 + 间距，用于缩进分隔线。
pub const ICON_INSET: f32 = 38.0;

/// 一行：左侧标题（可带说明），右侧控件。
pub fn row(ui: &mut Ui, p: &Palette, title: &str, sub: Option<&str>, right: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        ui.set_min_height(if sub.is_some() { 44.0 } else { 36.0 });
        ui.vertical(|ui| {
            ui.add_space(if sub.is_some() { 4.0 } else { 8.0 });
            ui.label(RichText::new(title).color(p.label));
            if let Some(s) = sub {
                ui.add_space(-6.0);
                ui.label(RichText::new(s).size(12.0).color(p.secondary));
            }
        });
        ui.with_layout(Layout::right_to_left(Align::Center), right);
    });
}

// ---------------- 控件 ----------------

/// iOS 风格开关。
pub fn toggle(ui: &mut Ui, p: &Palette, on: &mut bool) -> Response {
    let size = Vec2::new(42.0, 25.0);
    let (rect, mut resp) = ui.allocate_exact_size(size, Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let t = ui.ctx().animate_bool_responsive(resp.id, *on);
    let off_fill = if p.dark { Color32::from_rgb(0x39, 0x39, 0x3D) } else { Color32::from_rgb(0xE5, 0xE5, 0xEA) };
    let fill = lerp_color(off_fill, p.green, t);
    let radius = rect.height() / 2.0;
    ui.painter().rect_filled(rect, CornerRadius::same(radius as u8), fill);
    let knob_r = radius - 2.0;
    let x = egui::lerp((rect.left() + radius)..=(rect.right() - radius), t);
    let c = Pos2::new(x, rect.center().y);
    ui.painter().circle_filled(c + Vec2::new(0.0, 1.0), knob_r, Color32::from_black_alpha(30));
    ui.painter().circle_filled(c, knob_r, Color32::WHITE);
    resp
}

/// 带悬停与按下反馈的填充按钮：悬停时颜色渐变，按下时略微收缩、变暗。
fn push_button(
    ui: &mut Ui,
    text: &str,
    font: FontId,
    text_color: Color32,
    fill: Color32,
    hover_fill: Color32,
    enabled: bool,
) -> Response {
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, text_color);
    let pad = ui.spacing().button_padding;
    let size = Vec2::new(galley.size().x + pad.x * 2.0, (galley.size().y + pad.y * 2.0).max(28.0));
    let (rect, resp) = ui.allocate_exact_size(size, if enabled { Sense::click() } else { Sense::hover() });
    if ui.is_rect_visible(rect) {
        let ctx = ui.ctx();
        let h = ease(ctx, resp.id.with("hover"), enabled && resp.hovered(), 0.12);
        let pr = ease(ctx, resp.id.with("press"), enabled && resp.is_pointer_button_down_on(), 0.08);
        let mut bg = lerp_color(lerp_color(fill, hover_fill, h), Color32::BLACK, 0.10 * pr);
        let mut fg = text_color;
        if !enabled {
            bg = bg.gamma_multiply(0.45);
            fg = fg.gamma_multiply(0.7);
        }
        let r = rect.shrink(pr * 1.2);
        let painter = ui.painter();
        painter.rect_filled(r, CornerRadius::same(7), bg);
        painter.galley_with_override_text_color(r.center() - galley.size() / 2.0, galley, fg);
        if resp.has_focus() {
            painter.rect_stroke(rect.expand(2.0), CornerRadius::same(9), Stroke::new(2.0, ACCENT_FOCUS), egui::StrokeKind::Outside);
        }
    }
    if enabled {
        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        resp
    }
}

/// 键盘焦点环颜色。
const ACCENT_FOCUS: Color32 = Color32::from_rgb(0x4C, 0x9A, 0xFF);

/// 实心强调色按钮（主要操作）。
pub fn accent_button(ui: &mut Ui, p: &Palette, text: &str, enabled: bool) -> Response {
    let hover = lerp_color(p.accent, if p.dark { Color32::WHITE } else { Color32::BLACK }, 0.12);
    push_button(ui, text, bold(14.0), Color32::WHITE, p.accent, hover, enabled)
}

/// 灰色填充按钮（次要操作）。
pub fn gray_button(ui: &mut Ui, p: &Palette, text: &str) -> Response {
    push_button(ui, text, FontId::proportional(14.0), p.label, p.fill, p.fill_hover, true)
}

/// 无边框的文字按钮（链接样式）：悬停时颜色渐淡。
pub fn text_button(ui: &mut Ui, color: Color32, text: &str) -> Response {
    let galley = ui.painter().layout_no_wrap(text.to_owned(), FontId::proportional(14.0), color);
    // 文字按钮几乎不留横向内边距，与行内其他文字对齐
    let size = Vec2::new(galley.size().x + 4.0, (galley.size().y + 10.0).max(28.0));
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    if ui.is_rect_visible(rect) {
        let h = ease(ui.ctx(), resp.id.with("hover"), resp.hovered(), 0.12);
        let pr = ease(ui.ctx(), resp.id.with("press"), resp.is_pointer_button_down_on(), 0.08);
        let c = color.gamma_multiply(1.0 - 0.28 * h - 0.2 * pr);
        ui.painter().galley_with_override_text_color(rect.center() - galley.size() / 2.0, galley, c);
        if resp.has_focus() {
            ui.painter().rect_stroke(rect, CornerRadius::same(7), Stroke::new(2.0, ACCENT_FOCUS), egui::StrokeKind::Inside);
        }
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// 红色圆形减号按钮（删除一行）。
pub fn minus_button(ui: &mut Ui, p: &Palette) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::click());
    let c = rect.center();
    let h = ease(ui.ctx(), resp.id.with("hover"), resp.hovered(), 0.12);
    let col = lerp_color(p.red, Color32::BLACK, 0.18 * h);
    ui.painter().circle_filled(c, 9.0 + h * 0.8, col);
    ui.painter().line_segment([c - Vec2::new(4.5, 0.0), c + Vec2::new(4.5, 0.0)], Stroke::new(2.0, Color32::WHITE));
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// 胶囊标签（固定高度，不随行高拉伸）。
pub fn chip(ui: &mut Ui, color: Color32, text: &str) -> Response {
    let galley = ui.painter().layout_no_wrap(text.to_owned(), FontId::proportional(12.0), color);
    let size = Vec2::new(galley.size().x + 16.0, 20.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::same(10), color.gamma_multiply(0.16));
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, color);
    resp
}

fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()))
}

// ---------------- 图标 ----------------

#[derive(Clone, Copy, PartialEq)]
pub enum Glyph {
    Shield,
    Check,
    Grid,
    Gear,
    Lines,
    Globe,
    Laptop,
    /// 禁行标志里的横杠。
    Bar,
    /// 水滴（泄露测试）。
    Drop,
    /// 时钟（连接记录）。
    Clock,
}

/// 盾牌轮廓的多边形（凸多边形，坐标归一化到 0..1）。
fn shield_points(rect: Rect) -> Vec<Pos2> {
    let mut pts = vec![(0.20, 0.14), (0.50, 0.08), (0.80, 0.14), (0.80, 0.50)];
    for i in 1..8 {
        let k = i as f32 / 8.0;
        pts.push((0.5 + 0.30 * (1.0 - k * k), 0.50 + 0.42 * k));
    }
    pts.push((0.50, 0.92));
    for i in (1..8).rev() {
        let k = i as f32 / 8.0;
        pts.push((0.5 - 0.30 * (1.0 - k * k), 0.50 + 0.42 * k));
    }
    pts.push((0.20, 0.50));
    pts.into_iter()
        .map(|(x, y)| Pos2::new(rect.left() + x * rect.width(), rect.top() + y * rect.height()))
        .collect()
}

/// 在 rect 内画白色图形符号。
pub fn paint_glyph(painter: &egui::Painter, rect: Rect, glyph: Glyph, color: Color32) {
    let s = rect.width();
    let at = |x: f32, y: f32| Pos2::new(rect.left() + x * s, rect.top() + y * s);
    match glyph {
        Glyph::Shield => {
            painter.add(Shape::convex_polygon(shield_points(rect), color, Stroke::NONE));
        }
        Glyph::Check => {
            let st = Stroke::new(s * 0.12, color);
            painter.line_segment([at(0.24, 0.52), at(0.43, 0.70)], st);
            painter.line_segment([at(0.43, 0.70), at(0.78, 0.32)], st);
        }
        Glyph::Grid => {
            for (x, y) in [(0.2, 0.2), (0.54, 0.2), (0.2, 0.54), (0.54, 0.54)] {
                let r = Rect::from_min_size(at(x, y), Vec2::splat(s * 0.26));
                painter.rect_filled(r, CornerRadius::same((s * 0.06) as u8), color);
            }
        }
        Glyph::Gear => {
            let c = rect.center();
            for i in 0..8 {
                let a = i as f32 * std::f32::consts::TAU / 8.0;
                let d = Vec2::new(a.cos(), a.sin());
                painter.line_segment([c + d * s * 0.22, c + d * s * 0.36], Stroke::new(s * 0.13, color));
            }
            painter.circle_stroke(c, s * 0.20, Stroke::new(s * 0.11, color));
        }
        Glyph::Globe => {
            let c = rect.center();
            let st = Stroke::new(s * 0.08, color);
            painter.circle_stroke(c, s * 0.32, st);
            painter.add(Shape::ellipse_stroke(c, Vec2::new(s * 0.13, s * 0.32), st));
            painter.line_segment([at(0.18, 0.5), at(0.82, 0.5)], st);
        }
        Glyph::Laptop => {
            let st = Stroke::new(s * 0.09, color);
            let screen = Rect::from_min_max(at(0.20, 0.22), at(0.80, 0.64));
            painter.rect_stroke(screen, CornerRadius::same((s * 0.05) as u8), st, egui::StrokeKind::Middle);
            painter.line_segment([at(0.14, 0.74), at(0.86, 0.74)], Stroke::new(s * 0.09, color));
        }
        Glyph::Drop => {
            // 顶端一个尖、下面一段圆弧：尖点到圆的两条切线 + 圆弧，组成凸多边形
            let c = Vec2::new(0.5, 0.60);
            let (r, d) = (0.25f32, 0.46f32);
            let a = (r / d).acos();
            let up = -std::f32::consts::FRAC_PI_2;
            let (from, to) = (up + a, up - a + std::f32::consts::TAU);
            let mut pts = vec![at(c.x, c.y - d)];
            for i in 0..=20 {
                let t = from + (to - from) * i as f32 / 20.0;
                pts.push(at(c.x + r * t.cos(), c.y + r * t.sin()));
            }
            painter.add(Shape::convex_polygon(pts, color, Stroke::NONE));
        }
        Glyph::Bar => {
            painter.line_segment([at(0.26, 0.5), at(0.74, 0.5)], Stroke::new(s * 0.14, color));
        }
        Glyph::Clock => {
            let c = rect.center();
            let st = Stroke::new(s * 0.10, color);
            painter.circle_stroke(c, s * 0.32, st);
            painter.line_segment([c, at(0.5, 0.30)], st);
            painter.line_segment([c, at(0.64, 0.58)], st);
        }
        Glyph::Lines => {
            for (i, w) in [0.56, 0.44, 0.56].iter().enumerate() {
                let y = 0.30 + i as f32 * 0.20;
                painter.line_segment([at(0.22, y), at(0.22 + w, y)], Stroke::new(s * 0.10, color));
            }
        }
    }
}

/// 彩色圆角方块 + 白色符号（类似"系统设置"侧边栏图标）。
pub fn app_icon(ui: &mut Ui, size: f32, bg: Color32, glyph: Glyph) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    paint_app_icon(ui.painter(), rect, bg, glyph);
    resp
}

pub fn paint_app_icon(painter: &egui::Painter, rect: Rect, bg: Color32, glyph: Glyph) {
    painter.rect_filled(rect, CornerRadius::same((rect.width() * 0.24) as u8), bg);
    let inner = rect.shrink(rect.width() * 0.18);
    paint_glyph(painter, inner, glyph, Color32::WHITE);
}

/// 出口通路的状态。
#[derive(Clone, Copy, PartialEq)]
pub enum Route {
    /// 出口 IP 在白名单内，闸门打开。
    Open,
    /// 已阻断，闸门关闭。
    Closed,
    /// 正在确认出口 IP。
    Checking,
}

/// 概览页的主视觉：本机 ── 闸门 ── 互联网。
/// 放行时整条线贯通；阻断时闸门之后变成虚线；检测中有一个点沿线移动。
/// `labels`：三个节点下方的(主文字, 次文字)。
pub fn route_diagram(ui: &mut Ui, p: &Palette, route: Route, color: Color32, labels: [(&str, &str); 3]) {
    let h = 112.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), h), Sense::hover());
    let painter = ui.painter();
    let y = rect.top() + 34.0;
    let (r_end, r_gate) = (20.0, 27.0);
    let left = Pos2::new(rect.left() + 8.0 + r_end + 30.0, y);
    let gate = Pos2::new(rect.center().x, y);
    let right = Pos2::new(rect.right() - 8.0 - r_end - 30.0, y);
    let idle = if p.dark { p.tertiary } else { p.separator };
    let line_w = 3.0;

    // 状态切换时：闸门颜色从旧色渐变到新色，彩色线从本机一侧重新"流"过去。
    // 首次显示时不播放。
    let ctx = ui.ctx().clone();
    let now = ctx.input(|i| i.time);
    let mem_id = egui::Id::unique("route-transition");
    let (prev_color, since) = ctx.data_mut(|d| {
        let entry = d.get_temp_mut_or_insert_with(mem_id, || (route, color, color, f64::NEG_INFINITY));
        if entry.0 != route || entry.2 != color {
            // 从当前正在显示的颜色出发，避免连续切换时跳色
            let shown_t = ((now - entry.3) / 0.5).clamp(0.0, 1.0) as f32;
            let shown = lerp_color(entry.1, entry.2, egui::emath::easing::cubic_out(shown_t));
            *entry = (route, shown, color, now);
        }
        (entry.1, entry.3)
    });
    let raw = if reduced_motion() { 1.0 } else { ((now - since) / 0.5).clamp(0.0, 1.0) as f32 };
    if raw < 1.0 {
        ctx.request_repaint();
    }
    let k = egui::emath::easing::cubic_out(raw);
    // 红绿直接混合会经过一段浑浊的褐色，所以先褪到中性灰再变成新颜色
    let color = if prev_color == color || k >= 1.0 {
        color
    } else if k < 0.5 {
        lerp_color(prev_color, p.gray, k * 2.0)
    } else {
        lerp_color(p.gray, color, (k - 0.5) * 2.0)
    };
    // 彩色线可见到的最右位置
    let reveal_x = left.x + (right.x - left.x) * k;
    let clip = |a: Pos2, b: Pos2| -> Option<[Pos2; 2]> {
        (reveal_x > a.x).then(|| [a, Pos2::new(b.x.min(reveal_x), b.y)])
    };

    // 本机 → 闸门：流量总能到达闸门
    let (n0, n1) = (left + Vec2::X * r_end, gate - Vec2::X * r_gate);
    painter.line_segment([n0, n1], Stroke::new(2.0, idle));
    if route != Route::Checking {
        if let Some(seg) = clip(n0, n1) {
            painter.line_segment(seg, Stroke::new(line_w, color));
        }
    }
    // 闸门 → 互联网
    let (a, b) = (gate + Vec2::X * r_gate, right - Vec2::X * r_end);
    match route {
        Route::Open => {
            painter.line_segment([a, b], Stroke::new(2.0, idle));
            if let Some(seg) = clip(a, b) {
                painter.line_segment(seg, Stroke::new(line_w, color));
            }
        }
        Route::Closed => {
            painter.extend(Shape::dashed_line(&[a + Vec2::X * 8.0, b], Stroke::new(2.0, idle), 6.0, 6.0));
        }
        Route::Checking => {
            painter.line_segment([a, b], Stroke::new(2.0, idle));
        }
    }
    if route == Route::Checking {
        // 唯一的动效：检测时一个点从本机流向互联网
        let t = (ui.input(|i| i.time) % 1.6 / 1.6) as f32;
        let start = left + Vec2::X * r_end;
        let end = right - Vec2::X * r_end;
        let pos = start + (end - start) * t;
        if (pos.x - gate.x).abs() > r_gate {
            painter.circle_filled(pos, 4.0, p.accent);
        }
        ui.ctx().request_repaint();
    }

    // 两端节点
    let end_bg = p.fill;
    for (c, glyph) in [(left, Glyph::Laptop), (right, Glyph::Globe)] {
        painter.circle_filled(c, r_end, end_bg);
        let g = Rect::from_center_size(c, Vec2::splat(r_end * 1.45));
        paint_glyph(painter, g, glyph, p.secondary);
    }
    // 闸门：外圈淡色光晕 + 实心圆 + 白色符号
    painter.circle_filled(gate, r_gate + 7.0 * k, color.gamma_multiply(0.14));
    painter.circle_filled(gate, r_gate, color);
    let g = Rect::from_center_size(gate, Vec2::splat(r_gate * 1.15));
    match route {
        Route::Open => paint_glyph(painter, g, Glyph::Check, Color32::WHITE),
        Route::Closed => paint_glyph(painter, g, Glyph::Bar, Color32::WHITE),
        Route::Checking => {
            let t = ui.input(|i| i.time) as f32 * 4.0;
            let pts: Vec<Pos2> = (0..=24)
                .map(|i| {
                    let a = t + i as f32 / 24.0 * std::f32::consts::PI * 1.4;
                    gate + Vec2::new(a.cos(), a.sin()) * r_gate * 0.45
                })
                .collect();
            painter.add(Shape::line(pts, Stroke::new(2.5, Color32::WHITE)));
        }
    }

    // 节点下方的文字
    let ty = y + r_gate + 14.0;
    for (i, c) in [left, gate, right].into_iter().enumerate() {
        let (main, sub) = labels[i];
        let is_ip = i == 2;
        let main_font = if is_ip { bold(17.0) } else { FontId::proportional(13.5) };
        painter.text(Pos2::new(c.x, ty), Align2::CENTER_TOP, main, main_font, p.label);
        let sub_y = ty + if is_ip { 24.0 } else { 20.0 };
        let sub_color = if i == 1 { color } else { p.secondary };
        painter.text(Pos2::new(c.x, sub_y), Align2::CENTER_TOP, sub, FontId::proportional(12.0), sub_color);
    }
}

/// 侧边栏导航项。
pub struct NavItem<'a> {
    pub glyph: Glyph,
    pub icon_bg: Color32,
    pub text: &'a str,
    pub badge: Option<&'a str>,
}

/// 侧边栏导航列表。选中项的蓝色高亮会从旧位置滑到新位置，文字颜色随之过渡。
/// 返回被点击的序号。
pub fn nav_list(ui: &mut Ui, p: &Palette, items: &[NavItem], selected: usize) -> Option<usize> {
    let w = ui.available_width();
    let mut rects = Vec::with_capacity(items.len());
    let mut clicked = None;
    for (i, _) in items.iter().enumerate() {
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, 32.0), Sense::click());
        let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
        if resp.clicked() {
            clicked = Some(i);
        }
        rects.push((rect, resp));
        ui.add_space(-4.0);
    }
    let ctx = ui.ctx().clone();
    let target = rects[selected.min(rects.len() - 1)].0;
    let y = if reduced_motion() {
        target.top()
    } else {
        ctx.animate_value_with_time(egui::Id::unique("nav-highlight"), target.top(), 0.18)
    };
    let hl = Rect::from_min_size(Pos2::new(target.left(), y), target.size());

    let painter = ui.painter();
    for (i, (rect, resp)) in rects.iter().enumerate() {
        let h = ease(&ctx, resp.id.with("hover"), resp.hovered() && i != selected, 0.12);
        if h > 0.0 {
            painter.rect_filled(*rect, CornerRadius::same(7), p.fill_hover.gamma_multiply(0.7 * h));
        }
    }
    painter.rect_filled(hl, CornerRadius::same(7), p.accent);
    for (item, (rect, _)) in items.iter().zip(&rects) {
        // 高亮覆盖本行的比例决定文字颜色，滑动时平滑过渡
        let cover = (1.0 - (hl.top() - rect.top()).abs() / rect.height()).clamp(0.0, 1.0);
        let icon = Rect::from_min_size(Pos2::new(rect.left() + 8.0, rect.center().y - 10.0), Vec2::splat(20.0));
        paint_app_icon(painter, icon, item.icon_bg, item.glyph);
        let fg = lerp_color(p.label, Color32::WHITE, cover);
        painter.text(Pos2::new(icon.right() + 9.0, rect.center().y), Align2::LEFT_CENTER, item.text, FontId::proportional(14.0), fg);
        if let Some(b) = item.badge {
            let col = lerp_color(p.secondary, Color32::from_gray(235), cover);
            painter.text(Pos2::new(rect.right() - 10.0, rect.center().y), Align2::RIGHT_CENTER, b, FontId::proportional(12.5), col);
        }
    }
    clicked
}

/// 分段控件（类似 macOS 的 NSSegmentedControl）。返回是否改变。
pub fn segmented<T: PartialEq + Copy>(ui: &mut Ui, p: &Palette, value: &mut T, options: &[(T, &str)]) -> bool {
    let mut changed = false;
    egui::Frame::new()
        .fill(p.fill)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(2))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            ui.horizontal(|ui| {
                for (v, label) in options {
                    let selected = *value == *v;
                    let galley = ui.painter().layout_no_wrap(label.to_string(), FontId::proportional(13.0), p.label);
                    let size = Vec2::new(galley.size().x + 24.0, 24.0);
                    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
                    if selected {
                        let bg = if p.dark { Color32::from_rgb(0x63, 0x63, 0x66) } else { Color32::WHITE };
                        ui.painter().rect_filled(rect.translate(Vec2::new(0.0, 0.5)), CornerRadius::same(6), Color32::from_black_alpha(20));
                        ui.painter().rect_filled(rect, CornerRadius::same(6), bg);
                    } else if resp.hovered() {
                        ui.painter().rect_filled(rect, CornerRadius::same(6), p.fill_hover);
                    }
                    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, p.label);
                    if resp.clicked() && !selected {
                        *value = *v;
                        changed = true;
                    }
                }
            });
        });
    changed
}
