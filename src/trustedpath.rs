//! 以最高权限自动运行的程序必须放在普通账户改不了的位置，否则任何能改写这个位置的程序
//! 都可以借开机自启拿到管理员权限。
//!
//! 这里只有与平台无关的判断规则：Windows 读出所有者和 ACL 后交给 [`check`]，方便在任何平台上测试。

/// 本地系统账户
pub const SYSTEM: &str = "S-1-5-18";
/// 本地 Administrators 组
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
/// NT SERVICE\TrustedInstaller
pub const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// OWNER RIGHTS：权限归对象所有者（所有者本身已要求可信）
pub const OWNER_RIGHTS: &str = "S-1-3-4";

/// 被检查的对象
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// 程序本身、配置文件：不能被改写、删除或改权限
    File,
    /// 程序所在目录、配置所在目录：还不能往里放文件（例如同名 DLL）或删除其中的文件
    Dir,
    /// 更上层的目录：不能被改名、删除或改权限（新建其他子目录无妨）
    Ancestor,
}

const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_WRITE_DATA: u32 = 0x0002; // 目录上是 FILE_ADD_FILE
const FILE_APPEND_DATA: u32 = 0x0004; // 目录上是 FILE_ADD_SUBDIRECTORY
const FILE_DELETE_CHILD: u32 = 0x0040;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 11;
const INHERIT_ONLY_ACE: u8 = 0x08;

/// 对这类对象来说算作"能改写"的权限
pub fn risky_rights(kind: Kind) -> u32 {
    let base = DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
    match kind {
        Kind::File => base | GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA,
        Kind::Dir => base | GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD,
        Kind::Ancestor => base | FILE_DELETE_CHILD,
    }
}

/// ACL 里的一项（只需要类型、标志、权限和 SID）
#[derive(Clone, Debug)]
pub struct Ace {
    pub ace_type: u8,
    pub flags: u8,
    pub mask: u32,
    /// 允许类 ACE 的 SID（字符串形式）；其他类型可以为 None
    pub sid: Option<String>,
}

impl Ace {
    pub fn allow(sid: &str, mask: u32) -> Ace {
        Ace { ace_type: ACCESS_ALLOWED_ACE_TYPE, flags: 0, mask, sid: Some(sid.into()) }
    }
}

pub fn trusted_sid(sid: &str) -> bool {
    [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER, OWNER_RIGHTS].contains(&sid)
}

/// 常见账户 / 组的名称，便于在提示里看懂
pub fn sid_label(sid: &str) -> String {
    let name = match sid {
        "S-1-1-0" => "Everyone",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-32-545" => "Users",
        "S-1-5-4" => "INTERACTIVE",
        "S-1-3-0" => "CREATOR OWNER",
        _ if sid.starts_with("S-1-5-21-") => return format!("普通账户 {sid}"),
        _ => return sid.to_owned(),
    };
    name.to_owned()
}

/// 判断对象是否只有 SYSTEM、管理员组和 TrustedInstaller 能改。
/// `dacl` 为 None 表示没有 DACL（任何人都有全部权限）。Err 说明是谁能改。
pub fn check(kind: Kind, owner: &str, dacl: Option<&[Ace]>) -> Result<(), String> {
    // 所有者总能修改权限，所以必须可信
    if !trusted_sid(owner) {
        return Err(format!("所有者是 {}", sid_label(owner)));
    }
    let Some(dacl) = dacl else {
        return Err("没有设置访问权限（任何人都能修改）".into());
    };
    let risky = risky_rights(kind);
    for ace in dacl {
        if ace.flags & INHERIT_ONLY_ACE != 0 || ace.mask & risky == 0 {
            continue;
        }
        match ace.ace_type {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                let sid = ace.sid.as_deref().unwrap_or("");
                if !trusted_sid(sid) {
                    return Err(format!("{} 可以修改", sid_label(sid)));
                }
            }
            ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                return Err("包含无法确认的权限项".into());
            }
            // 拒绝项只会收紧权限；审计等其他类型不影响访问
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "S-1-5-21-1-2-3-1001";
    const USERS: &str = "S-1-5-32-545";
    const AUTH_USERS: &str = "S-1-5-11";
    const RX: u32 = 0x0012_00a9;
    const MODIFY: u32 = 0x0013_01bf;
    const FULL: u32 = 0x001f_01ff;

    fn program_files_like() -> Vec<Ace> {
        vec![
            Ace::allow(TRUSTED_INSTALLER, FULL),
            Ace::allow(SYSTEM, MODIFY),
            Ace::allow(ADMINISTRATORS, MODIFY),
            Ace::allow(USERS, RX),
            // CREATOR OWNER：只给子对象继承
            Ace { ace_type: 0, flags: 0x0b, mask: GENERIC_ALL, sid: Some("S-1-3-0".into()) },
        ]
    }

    #[test]
    fn program_files_is_trusted() {
        for kind in [Kind::File, Kind::Dir, Kind::Ancestor] {
            assert_eq!(check(kind, TRUSTED_INSTALLER, Some(&program_files_like())), Ok(()));
        }
    }

    #[test]
    fn user_owner_is_rejected() {
        let err = check(Kind::Dir, USER, Some(&program_files_like())).unwrap_err();
        assert!(err.contains("所有者"), "{err}");
    }

    #[test]
    fn missing_dacl_is_rejected() {
        assert!(check(Kind::File, ADMINISTRATORS, None).is_err());
    }

    #[test]
    fn writable_by_users_is_rejected() {
        let mut dacl = program_files_like();
        dacl.push(Ace::allow(AUTH_USERS, MODIFY));
        let err = check(Kind::Dir, ADMINISTRATORS, Some(&dacl)).unwrap_err();
        assert!(err.contains("Authenticated Users"), "{err}");
        // 当前账户自己（未提升时也能用）的写权限同样不行
        let dacl = vec![Ace::allow(ADMINISTRATORS, FULL), Ace::allow(USER, FULL)];
        assert!(check(Kind::File, ADMINISTRATORS, Some(&dacl)).is_err());
    }

    #[test]
    fn create_folder_right_on_ancestor_is_fine() {
        // C:\ 允许已验证用户新建文件夹（只对 C:\ 本身），这不影响已有目录
        let dacl = vec![
            Ace::allow(ADMINISTRATORS, FULL),
            Ace::allow(SYSTEM, FULL),
            Ace::allow(USERS, RX),
            Ace::allow(AUTH_USERS, FILE_APPEND_DATA),
            Ace { ace_type: 0, flags: 0x0b, mask: MODIFY, sid: Some(AUTH_USERS.into()) },
        ];
        assert_eq!(check(Kind::Ancestor, TRUSTED_INSTALLER, Some(&dacl)), Ok(()));
        // 但程序所在目录不能让普通账户放文件
        assert!(check(Kind::Dir, TRUSTED_INSTALLER, Some(&dacl)).is_err());
    }

    #[test]
    fn delete_child_on_ancestor_is_rejected() {
        let dacl = vec![Ace::allow(ADMINISTRATORS, FULL), Ace::allow(USERS, FILE_DELETE_CHILD)];
        assert!(check(Kind::Ancestor, ADMINISTRATORS, Some(&dacl)).is_err());
    }

    #[test]
    fn deny_and_object_aces() {
        let deny = Ace { ace_type: 1, flags: 0, mask: FULL, sid: Some(USERS.into()) };
        assert_eq!(check(Kind::File, ADMINISTRATORS, Some(&[deny])), Ok(()));
        let object = Ace { ace_type: 5, flags: 0, mask: FILE_WRITE_DATA, sid: None };
        assert!(check(Kind::File, ADMINISTRATORS, Some(&[object])).is_err());
    }
}
