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

/// macOS 应用图标（size×size RGBA）：按苹果图标网格留边的圆角方块，绿色渐变底、白色盾牌。
pub fn app_icon_rgba(size: u32) -> Vec<u8> {
    let s = size as f32;
    let mut out = vec![0u8; (size * size * 4) as usize];
    // 1024 网格里内容区 824×824，圆角约 185
    let (inset, rad) = (100.0 / 1024.0, 185.0 / 1024.0);
    let (top, bottom) = ([0x3a, 0xd0, 0x6a], [0x16, 0x9b, 0x45]);
    const SS: u32 = 4;
    let in_square = |x: f32, y: f32| {
        let (lo, hi) = (inset, 1.0 - inset);
        if x < lo || x > hi || y < lo || y > hi {
            return false;
        }
        let cx = x.clamp(lo + rad, hi - rad);
        let cy = y.clamp(lo + rad, hi - rad);
        (x - cx).powi(2) + (y - cy).powi(2) <= rad * rad
    };
    for y in 0..size {
        for x in 0..size {
            let (mut cov, mut white) = (0.0f32, 0.0f32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let px = (x as f32 + (sx as f32 + 0.5) / SS as f32) / s;
                    let py = (y as f32 + (sy as f32 + 0.5) / SS as f32) / s;
                    if in_square(px, py) {
                        cov += 1.0;
                        // 盾牌占内容区中间约 52%
                        let (qx, qy) = ((px - 0.5) / 0.52 + 0.5, (py - 0.5) / 0.52 + 0.5);
                        if in_shield(qx, qy) {
                            white += 1.0;
                        }
                    }
                }
            }
            let i = ((y * size + x) * 4) as usize;
            let t = ((y as f32 / s - inset) / (1.0 - 2.0 * inset)).clamp(0.0, 1.0);
            let w = if cov > 0.0 { white / cov } else { 0.0 };
            for c in 0..3 {
                let bg = top[c] as f32 * (1.0 - t) + bottom[c] as f32 * t;
                out[i + c] = (bg * (1.0 - w) + 255.0 * w).round() as u8;
            }
            out[i + 3] = (cov / (SS * SS) as f32 * 255.0).round() as u8;
        }
    }
    out
}

/// 把 RGBA 编码成 PNG（不压缩的 deflate 块，足够用于生成图标文件）。
pub fn encode_png(rgba: &[u8], w: u32, h: u32) -> Vec<u8> {
    fn crc32(data: &[u8]) -> u32 {
        let mut c = 0xffff_ffffu32;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            }
        }
        !c
    }
    fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut body = kind.to_vec();
        body.extend_from_slice(data);
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc32(&body).to_be_bytes());
    }
    // 每行前加过滤类型 0
    let mut raw = Vec::with_capacity((w * h * 4 + h) as usize);
    for row in rgba.chunks((w * 4) as usize) {
        raw.push(0);
        raw.extend_from_slice(row);
    }
    let mut z = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = raw.chunks(65535).collect();
    for (i, b) in blocks.iter().enumerate() {
        z.push(u8::from(i + 1 == blocks.len()));
        z.extend_from_slice(&(b.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(b.len() as u16)).to_le_bytes());
        z.extend_from_slice(b);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for &x in &raw {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    z.extend_from_slice(&((b << 16) | a).to_be_bytes());

    let mut out = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    out
}
