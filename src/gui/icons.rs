//! 运行时生成的图标（RGBA），用于托盘和窗口。

/// 状态圆点颜色。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shade {
    Green,
    Red,
    Gray,
    Amber,
}

impl Shade {
    pub fn rgb(self) -> [u8; 3] {
        match self {
            Shade::Green => [0x2e, 0xa0, 0x43],
            Shade::Red => [0xd1, 0x24, 0x2f],
            Shade::Gray => [0x8b, 0x94, 0x9e],
            Shade::Amber => [0xd2, 0x99, 0x22],
        }
    }
}

/// 生成 size×size 的盾牌形状图标，中间是白色圆点。
pub fn shield_rgba(size: u32, shade: Shade) -> Vec<u8> {
    let [r, g, b] = shade.rgb();
    let s = size as f32;
    let mut out = vec![0u8; (size * size * 4) as usize];
    // 超采样抗锯齿
    const SS: u32 = 4;
    for y in 0..size {
        for x in 0..size {
            let mut cov = 0.0f32;
            let mut dot = 0.0f32;
            for sy in 0..SS {
                for sx in 0..SS {
                    let px = (x as f32 + (sx as f32 + 0.5) / SS as f32) / s;
                    let py = (y as f32 + (sy as f32 + 0.5) / SS as f32) / s;
                    if in_shield(px, py) {
                        cov += 1.0;
                        let (dx, dy) = (px - 0.5, py - 0.46);
                        if dx * dx + dy * dy < 0.15 * 0.15 {
                            dot += 1.0;
                        }
                    }
                }
            }
            let n = (SS * SS) as f32;
            let a = cov / n;
            let w = if cov > 0.0 { dot / cov } else { 0.0 };
            let i = ((y * size + x) * 4) as usize;
            let mix = |c: u8| (c as f32 * (1.0 - w) + 255.0 * w).round() as u8;
            out[i] = mix(r);
            out[i + 1] = mix(g);
            out[i + 2] = mix(b);
            out[i + 3] = (a * 255.0).round() as u8;
        }
    }
    out
}

/// 盾牌轮廓：上半部分为圆角矩形，下半部分收成尖角。坐标归一化到 0..1。
fn in_shield(x: f32, y: f32) -> bool {
    let (l, r, t) = (0.12, 0.88, 0.06);
    if y < t || x < l || x > r {
        return false;
    }
    if y <= 0.55 {
        // 顶部两角圆角
        let rad = 0.12;
        for cx in [l + rad, r - rad] {
            let cy = t + rad;
            if y < cy && ((x < l + rad && cx < 0.5) || (x > r - rad && cx > 0.5)) {
                let (dx, dy) = (x - cx, y - cy);
                return dx * dx + dy * dy <= rad * rad;
            }
        }
        return true;
    }
    // 下半部分：两侧二次曲线收向底部尖点 (0.5, 0.96)
    let k = (y - 0.55) / (0.96 - 0.55);
    if k > 1.0 {
        return false;
    }
    let half = 0.38 * (1.0 - k * k);
    (x - 0.5).abs() <= half
}
