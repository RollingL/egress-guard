//! 苹果风格的配色、样式和自绘控件（开关、卡片、分组行、图标等）。

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
}

impl Palette {
    pub const LIGHT: Palette = Palette {
        dark: false,
        bg: Color32::from_rgb(0xF2, 0xF2, 0xF7),
        card: Color32::from_rgb(0xFF, 0xFF, 0xFF),
        sidebar: Color32::from_rgb(0xE9, 0xE9, 0xEE),
        separator: Color32::from_rgb(0xE0, 0xE0, 0xE5),
        label: Color32::from_rgb(0x1D, 0x1D, 0x1F),
        secondary: Color32::from_rgb(0x6E, 0x6E, 0x73),
        tertiary: Color32::from_rgb(0xAE, 0xAE, 0xB2),
        fill: Color32::from_rgb(0xEC, 0xEC, 0xF0),
        fill_hover: Color32::from_rgb(0xE0, 0xE0, 0xE6),
        accent: Color32::from_rgb(0x00, 0x7A, 0xFF),
        green: Color32::from_rgb(0x34, 0xC7, 0x59),
        red: Color32::from_rgb(0xFF, 0x3B, 0x30),
        orange: Color32::from_rgb(0xFF, 0x95, 0x00),
        indigo: Color32::from_rgb(0x58, 0x56, 0xD6),
        gray: Color32::from_rgb(0x8E, 0x8E, 0x93),
        teal: Color32::from_rgb(0x30, 0xB0, 0xC7),
    };

    pub const DARK: Palette = Palette {
        dark: true,
        bg: Color32::from_rgb(0x1C, 0x1C, 0x1E),
        card: Color32::from_rgb(0x2C, 0x2C, 0x2E),
        sidebar: Color32::from_rgb(0x24, 0x24, 0x26),
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
    };

    pub fn of(ui: &Ui) -> Palette {
        if ui.visuals().dark_mode {
            Self::DARK
        } else {
            Self::LIGHT
        }
    }
}

/// 粗体字体族名称（Windows 上为微软雅黑 Bold）。
pub const BOLD: &str = "bold";

pub fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(BOLD.into()))
}

/// 加载中文字体（常规 + 粗体）。egui 自带字体不含中文。
pub fn setup_fonts(ctx: &egui::Context) {
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let fonts_dir = std::path::Path::new(&windir).join("Fonts");
    let read = |names: &[&str]| names.iter().find_map(|n| std::fs::read(fonts_dir.join(n)).ok());

    let mut fonts = egui::FontDefinitions::default();
    let defaults = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();

    let regular = read(&["msyh.ttc", "msyh.ttf", "Deng.ttf", "simhei.ttf", "simsun.ttc"]);
    let bold_font = read(&["msyhbd.ttc", "msyhbd.ttf", "Dengb.ttf"]);

    if let Some(bytes) = regular {
        fonts.font_data.insert("cjk".into(), egui::FontData::from_owned(bytes).into());
        fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "cjk".into());
        fonts.families.entry(FontFamily::Monospace).or_default().push("cjk".into());
    }
    let mut bold_family = Vec::new();
    if let Some(bytes) = bold_font {
        fonts.font_data.insert("cjk-bold".into(), egui::FontData::from_owned(bytes).into());
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
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(16, 10))
        .stroke(if p.dark { Stroke::NONE } else { Stroke::new(0.5, p.separator) })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// 卡片内行与行之间的细分隔线。
pub fn hairline(ui: &mut Ui, p: &Palette) {
    let rect = ui.available_rect_before_wrap();
    let y = ui.cursor().top() + 1.0;
    ui.painter().line_segment([Pos2::new(rect.left(), y), Pos2::new(rect.right(), y)], Stroke::new(0.7, p.separator));
    ui.add_space(3.0);
}

/// 一行：左侧标题（可带说明），右侧控件。
pub fn row(ui: &mut Ui, p: &Palette, title: &str, sub: Option<&str>, right: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        ui.set_min_height(34.0);
        ui.vertical(|ui| {
            ui.add_space(if sub.is_some() { 2.0 } else { 7.0 });
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

/// 实心强调色按钮（主要操作）。
pub fn accent_button(ui: &mut Ui, p: &Palette, text: &str, enabled: bool) -> Response {
    let fill = if enabled { p.accent } else { p.accent.gamma_multiply(0.4) };
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(text).color(Color32::WHITE).font(bold(14.0)))
            .fill(fill)
            .corner_radius(CornerRadius::same(7)),
    )
}

/// 灰色填充按钮（次要操作）。
pub fn gray_button(ui: &mut Ui, p: &Palette, text: &str) -> Response {
    ui.add(egui::Button::new(RichText::new(text).color(p.label)).fill(p.fill).corner_radius(CornerRadius::same(7)))
}

/// 无边框的文字按钮（链接样式）。
pub fn text_button(ui: &mut Ui, color: Color32, text: &str) -> Response {
    ui.add(egui::Button::new(RichText::new(text).color(color)).frame(false))
}

/// 红色圆形减号按钮（删除一行）。
pub fn minus_button(ui: &mut Ui, p: &Palette) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::click());
    let c = rect.center();
    let col = if resp.hovered() { p.red.gamma_multiply(0.8) } else { p.red };
    ui.painter().circle_filled(c, 9.0, col);
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

/// 大号状态徽章：浅色圆底 + 彩色盾牌 + 白点。
pub fn status_badge(ui: &mut Ui, size: f32, color: Color32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let painter = ui.painter();
    painter.circle_filled(rect.center(), size / 2.0, color.gamma_multiply(0.15));
    let inner = rect.shrink(size * 0.2);
    paint_glyph(painter, inner, Glyph::Shield, color);
    painter.circle_filled(Pos2::new(inner.center().x, inner.top() + inner.height() * 0.46), inner.width() * 0.13, Color32::WHITE);
    resp
}

/// 侧边栏导航项。返回是否被点击。
pub fn nav_item(ui: &mut Ui, p: &Palette, selected: bool, glyph: Glyph, icon_bg: Color32, text: &str, badge: Option<&str>) -> bool {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 32.0), Sense::click());
    let painter = ui.painter();
    if selected {
        painter.rect_filled(rect, CornerRadius::same(7), p.accent);
    } else if resp.hovered() {
        painter.rect_filled(rect, CornerRadius::same(7), p.fill_hover.gamma_multiply(0.7));
    }
    let icon = Rect::from_min_size(Pos2::new(rect.left() + 8.0, rect.center().y - 10.0), Vec2::splat(20.0));
    paint_app_icon(painter, icon, icon_bg, glyph);
    let fg = if selected { Color32::WHITE } else { p.label };
    painter.text(Pos2::new(icon.right() + 9.0, rect.center().y), Align2::LEFT_CENTER, text, FontId::proportional(14.0), fg);
    if let Some(b) = badge {
        let col = if selected { Color32::WHITE.gamma_multiply(0.85) } else { p.secondary };
        painter.text(Pos2::new(rect.right() - 10.0, rect.center().y), Align2::RIGHT_CENTER, b, FontId::proportional(12.5), col);
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked()
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
