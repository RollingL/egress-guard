//! WFP（Windows Filtering Platform）用户态阻断：底层调用。
//!
//! - 使用动态会话（FWPM_SESSION_FLAG_DYNAMIC）：本进程退出、崩溃或被结束时，
//!   本会话添加的子层和过滤器全部由系统自动删除，不会残留规则。
//! - 按应用 ID（FWPM_CONDITION_ALE_APP_ID）在 ALE 连接/接受层阻断 IPv4 与 IPv6。
//! - 全局断网时再加一条不带条件的兜底阻断，以及若干放行例外。
//!
//! 什么时候加、删哪些过滤器、过滤器归谁所有在 [`crate::wfpcore`]（与平台无关，有模拟事务的测试）；
//! 这里只把它要的过滤器翻译成 WFP 调用。

use std::ffi::c_void;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{bail, Result};
use ipnet::IpNet;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::tcpkill;
use crate::blockall::DNS_PORT;
use crate::wfpcore::{Api, Filter, Kill, Layer, Wfp};

/// 本工具子层的固定 GUID。固定值便于识别"已有实例在运行"。
const SUBLAYER_KEY: GUID = GUID::from_u128(0x6a1e_93c4_2b7d_4f0e_9c51_3e8a_d4b2_7f10);

/// [`crate::wfpcore::LAYERS`] 各层对应的 WFP 层。
const LAYER_KEYS: [GUID; 4] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
];

const IPPROTO_UDP: u8 = 17;

const ERROR_ACCESS_DENIED: u32 = 5;
const E_ACCESSDENIED: u32 = 0x8007_0005;
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

pub type WfpFirewall = Wfp<WinApi>;

/// 打开的 WFP 动态会话。
pub struct WinApi {
    engine: HANDLE,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check(code: u32, what: &str) -> Result<()> {
    match code {
        0 => Ok(()),
        ERROR_ACCESS_DENIED | E_ACCESSDENIED => {
            bail!("{what} 失败：拒绝访问，请以管理员身份运行")
        }
        FWP_E_ALREADY_EXISTS => {
            bail!("{what} 失败：对象已存在，可能已有另一个 egress-guard 实例在运行")
        }
        c => bail!("{what} 失败：0x{c:08X}"),
    }
}

impl WinApi {
    fn open() -> Result<Self> {
        let mut session_name = wide("egress-guard");
        let mut session_desc = wide("Egress IP based app network control (dynamic session)");
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(session_name.as_mut_ptr()),
                description: PWSTR(session_desc.as_mut_ptr()),
            },
            ..Default::default()
        };

        let mut engine = HANDLE::default();
        check(
            unsafe {
                FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, Some(&session), &mut engine)
            },
            "FwpmEngineOpen0",
        )?;
        let api = Self { engine };

        let mut sl_name = wide("egress-guard sublayer");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(sl_name.as_mut_ptr()),
                description: PWSTR::null(),
            },
            weight: 0xFFFF, // 最高子层权重
            ..Default::default()
        };
        check(unsafe { FwpmSubLayerAdd0(api.engine, &sublayer, None) }, "FwpmSubLayerAdd0")?;
        Ok(api)
    }

    /// 添加一个过滤器。权限阻断会清除动作权限，低优先级子层的放行无法覆盖。
    fn add_raw(&self, layer: &Layer, f: &Filter<'_>, conds: &mut [FWPM_FILTER_CONDITION0]) -> Result<u64> {
        let what = f.describe();
        let permit = f.permit();
        let mut name = wide(&format!("egress-guard {what} {}", layer.name));
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 { name: PWSTR(name.as_mut_ptr()), description: PWSTR::null() },
            flags: if permit { FWPM_FILTER_FLAG_NONE } else { FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT },
            layerKey: LAYER_KEYS[layer.index],
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_VALUE0_0 { uint8: f.weight() } },
            numFilterConditions: conds.len() as u32,
            filterCondition: if conds.is_empty() { std::ptr::null_mut() } else { conds.as_mut_ptr() },
            action: FWPM_ACTION0 {
                r#type: if permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK },
                ..Default::default()
            },
            ..Default::default()
        };
        let mut id = 0u64;
        check(
            unsafe { FwpmFilterAdd0(self.engine, &filter, None, Some(&mut id)) },
            &format!("FwpmFilterAdd0({what}, {})", layer.name),
        )?;
        Ok(id)
    }
}

impl Api for WinApi {
    fn begin(&mut self) -> Result<()> {
        check(unsafe { FwpmTransactionBegin0(self.engine, 0) }, "FwpmTransactionBegin0")
    }

    fn commit(&mut self) -> Result<()> {
        check(unsafe { FwpmTransactionCommit0(self.engine) }, "FwpmTransactionCommit0")
    }

    fn abort(&mut self) {
        unsafe { FwpmTransactionAbort0(self.engine) };
    }

    fn add(&mut self, layer: &Layer, f: &Filter<'_>) -> Result<u64> {
        match f {
            Filter::Loopback => self.add_raw(layer, f, &mut [cond_flags(FWP_CONDITION_FLAG_IS_LOOPBACK)]),
            Filter::Dhcp { client, server } => self.add_raw(
                layer,
                f,
                &mut [
                    cond_u8(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_UDP),
                    cond_u16(FWPM_CONDITION_IP_LOCAL_PORT, *client),
                    cond_u16(FWPM_CONDITION_IP_REMOTE_PORT, *server),
                ],
            ),
            Filter::Dns => self.add_raw(layer, f, &mut [cond_u16(FWPM_CONDITION_IP_REMOTE_PORT, DNS_PORT)]),
            // 同一字段的多个条件之间是"或"关系
            Filter::Remote(nets) => {
                let mut v4: Vec<FWP_V4_ADDR_AND_MASK> = Vec::new();
                let mut v6: Vec<FWP_V6_ADDR_AND_MASK> = Vec::new();
                for net in nets.iter() {
                    match net {
                        IpNet::V4(n) if !layer.v6 => v4.push(FWP_V4_ADDR_AND_MASK {
                            addr: u32::from(n.network()),
                            mask: if n.prefix_len() == 0 { 0 } else { u32::MAX << (32 - n.prefix_len()) },
                        }),
                        IpNet::V6(n) if layer.v6 => v6.push(FWP_V6_ADDR_AND_MASK {
                            addr: n.network().octets(),
                            prefixLength: n.prefix_len(),
                        }),
                        _ => {}
                    }
                }
                let mut c: Vec<FWPM_FILTER_CONDITION0> =
                    if layer.v6 { v6.iter_mut().map(cond_v6).collect() } else { v4.iter_mut().map(cond_v4).collect() };
                if c.is_empty() {
                    bail!("没有 {} 的例外地址", layer.name);
                }
                self.add_raw(layer, f, &mut c)
            }
            Filter::BlockAll => self.add_raw(layer, f, &mut []),
            Filter::App { path, .. } => {
                let path_w = wide(&path.to_string_lossy());
                let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
                check(
                    unsafe { FwpmGetAppIdFromFileName0(PCWSTR(path_w.as_ptr()), &mut app_id) },
                    &format!("FwpmGetAppIdFromFileName0({})", path.display()),
                )?;
                let mut cond = [FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_ALE_APP_ID,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_BLOB_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
                    },
                }];
                let r = self.add_raw(layer, f, &mut cond);
                let mut p = app_id as *mut c_void;
                unsafe { FwpmFreeMemory0(&mut p) };
                r
            }
        }
    }

    fn delete(&mut self, id: u64) -> Result<()> {
        check(unsafe { FwpmFilterDeleteById0(self.engine, id) }, "FwpmFilterDeleteById0")
    }

    fn kill(&self, k: Kill) {
        let result = match &k {
            Kill::Apps(apps) => tcpkill::kill_tcp_connections(apps),
            Kill::Global { .. } => tcpkill::kill_tcp_where(|path, ip, port| k.matches(path, IpAddr::V4(ip), port)),
        };
        match result {
            Ok(0) => {}
            Ok(n) => log::info!("已断开 {n} 条现有 IPv4 TCP 连接"),
            Err(e) => log::warn!("断开现有 TCP 连接失败: {e:#}"),
        }
    }
}

impl Drop for WinApi {
    fn drop(&mut self) {
        // 关闭动态会话后，系统自动删除本会话的全部子层与过滤器
        unsafe { FwpmEngineClose0(self.engine) };
        log::info!("WFP 会话已关闭，所有阻断规则已移除");
    }
}

/// 打开 WFP 动态会话。
pub fn open() -> Result<WfpFirewall> {
    let self_exe: Option<PathBuf> = std::env::current_exe().ok();
    Ok(Wfp::new(WinApi::open()?, self_exe))
}

fn cond_u8(field: GUID, v: u8) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_CONDITION_VALUE0_0 { uint8: v } },
    }
}

fn cond_u16(field: GUID, v: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 { r#type: FWP_UINT16, Anonymous: FWP_CONDITION_VALUE0_0 { uint16: v } },
    }
}

fn cond_flags(flags: u32) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_FLAGS,
        matchType: FWP_MATCH_FLAGS_ALL_SET,
        conditionValue: FWP_CONDITION_VALUE0 { r#type: FWP_UINT32, Anonymous: FWP_CONDITION_VALUE0_0 { uint32: flags } },
    }
}

fn cond_v4(m: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: m },
        },
    }
}

fn cond_v6(m: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V6_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: m },
        },
    }
}
