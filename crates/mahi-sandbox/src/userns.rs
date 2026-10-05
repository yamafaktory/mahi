use std::{
    fmt,
    path::Path,
};

#[cfg(target_os = "linux")]
const RESTRICT: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
#[cfg(target_os = "linux")]
const CLONE: &str = "/proc/sys/kernel/unprivileged_userns_clone";
#[cfg(target_os = "linux")]
const MAX: &str = "/proc/sys/user/max_user_namespaces";
#[cfg(target_os = "linux")]
const STATUS: &str = "/proc/self/status";
#[cfg(target_os = "linux")]
const LABELS: [&str; 2] = [
    "/proc/self/attr/apparmor/current",
    "/proc/self/attr/current",
];
#[cfg(any(target_os = "linux", test))]
const UNCONFINED: &str = "unconfined";
#[cfg(any(target_os = "linux", test))]
const RESTRICTED_LABEL: &str = "unprivileged_userns";
#[cfg(any(target_os = "linux", test))]
const CAP_SYS_ADMIN: u32 = 21;
const PATTERN_CHARACTERS: &[char] = &[
    '*', '?', '[', ']', '{', '}', '^', '"', '\\', '@', '#', '\'', ' ', '!', '<', '>', ',',
];

/// Why the Linux sandbox cannot create the user namespaces it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsernsBlocked {
    /// AppArmor gives unconfined processes no capabilities in a user namespace they create,
    /// as Ubuntu does from 23.10 on; holds this mahi's path, when it is known and can be named
    /// in a profile.
    AppArmor(Option<String>),
    /// Unprivileged user namespaces are turned off by the named setting.
    Disabled(&'static str),
}

/// An AppArmor profile for one mahi binary, and the file it goes in under `/etc/apparmor.d`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppArmorProfile {
    /// The file name, which is also the profile's name: the binary's path without its leading
    /// `/` and with each `/` turned into `.`, as Ubuntu names profiles, such as `usr.bin.mahi`.
    pub file_name: String,
    /// The profile itself.
    pub text: String,
}

impl fmt::Display for UsernsBlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppArmor(profile) => {
                f.write_str(
                    "AppArmor stops mahi from using the user namespaces its sandbox needs \
                     (kernel.apparmor_restrict_unprivileged_userns is 1); ",
                )?;
                let everyone = "sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0";
                match profile {
                    Some(binary) => {
                        let name = profile_name(binary);
                        write!(
                            f,
                            "allow this mahi alone with: {binary} apparmor | sudo tee \
                             /etc/apparmor.d/{name} && sudo apparmor_parser -r \
                             /etc/apparmor.d/{name} (or every program with {everyone})"
                        )
                    }
                    None => write!(
                        f,
                        "this mahi's path is unknown or cannot be named in an AppArmor profile, \
                         so allow every program with {everyone}"
                    ),
                }
            }
            Self::Disabled("user.max_user_namespaces") => f.write_str(
                "user namespaces, which mahi's sandbox needs, are turned off \
                 (user.max_user_namespaces is 0); turn them on with sudo sysctl \
                 user.max_user_namespaces=10000",
            ),
            Self::Disabled(setting) => write!(
                f,
                "user namespaces, which mahi's sandbox needs, are turned off ({setting} is 0); \
                 turn them on with sudo sysctl {setting}=1"
            ),
        }
    }
}

impl std::error::Error for UsernsBlocked {}

/// Checks that the Linux sandbox of the mahi at `binary` can create the user namespaces it
/// needs; anywhere else there is nothing to check.
///
/// # Errors
///
/// Returns [`UsernsBlocked`] when a setting of the system keeps it from doing so.
pub fn check_user_namespaces(binary: Option<&Path>) -> Result<(), UsernsBlocked> {
    #[cfg(target_os = "linux")]
    {
        let read = |path: &str| std::fs::read_to_string(path).ok();
        let label = LABELS.iter().find_map(|path| read(path));
        let privileged = read(STATUS).is_some_and(|status| may_administer(&status));
        if let Some(blocked) = blocked(
            (
                read(RESTRICT).as_deref(),
                read(CLONE).as_deref(),
                read(MAX).as_deref(),
            ),
            (label.as_deref(), privileged),
            binary,
        ) {
            return Err(blocked);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = binary;
    Ok(())
}

/// Returns an AppArmor profile that lets the program at `binary` create user namespaces and
/// confines it in no other way, named after its path so that two installs never share one,
/// or `None` when the path is not absolute or holds a space or a character AppArmor would
/// read as a pattern.
#[must_use]
pub fn apparmor_profile(binary: &Path) -> Option<AppArmorProfile> {
    let path = binary.to_str()?;
    let plain = binary.is_absolute()
        && path
            .chars()
            .all(|character| !character.is_control() && !PATTERN_CHARACTERS.contains(&character));
    let file_name = profile_name(path);
    if !plain || file_name.is_empty() || file_name.starts_with('.') {
        return None;
    }
    let text = format!(
        "abi <abi/4.0>,\ninclude <tunables/global>\n\nprofile {file_name} {path} \
         flags=(unconfined) {{\n  userns,\n\n  include if exists <local/{file_name}>\n}}\n"
    );
    Some(AppArmorProfile { file_name, text })
}

fn profile_name(path: &str) -> String {
    path.trim_start_matches('/').replace('/', ".")
}

#[cfg(any(target_os = "linux", test))]
fn may_administer(status: &str) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|bits| u64::from_str_radix(bits.trim(), 16).ok())
        .is_some_and(|bits| bits & (1 << CAP_SYS_ADMIN) != 0)
}

#[cfg(any(target_os = "linux", test))]
fn blocked(
    (restrict, clone, max): (Option<&str>, Option<&str>, Option<&str>),
    (label, privileged): (Option<&str>, bool),
    binary: Option<&Path>,
) -> Option<UsernsBlocked> {
    let zero = |value: Option<&str>| value.is_some_and(|value| value.trim() == "0");
    if zero(max) {
        return Some(UsernsBlocked::Disabled("user.max_user_namespaces"));
    }
    if privileged {
        return None;
    }
    if zero(clone) {
        return Some(UsernsBlocked::Disabled("kernel.unprivileged_userns_clone"));
    }
    let restricted = restrict.is_some_and(|value| value.trim() == "1");
    let unconfined = label.is_some_and(|label| {
        let label = label.trim_end_matches(['\n', '\0']);
        label == UNCONFINED || label.starts_with(RESTRICTED_LABEL)
    });
    (restricted && unconfined).then(|| {
        UsernsBlocked::AppArmor(
            binary
                .filter(|binary| apparmor_profile(binary).is_some())
                .and_then(Path::to_str)
                .map(str::to_owned),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_restriction_on_an_unconfined_mahi_or_disabled_namespaces_block_the_sandbox() {
        let ubuntu = (Some("1\n"), Some("1\n"), Some("63791\n"));
        let user = |label| (Some(label), false);
        let mahi = Some(Path::new("/usr/bin/mahi"));
        assert_eq!(
            blocked(ubuntu, user("unconfined\n"), mahi),
            Some(UsernsBlocked::AppArmor(Some("/usr/bin/mahi".to_owned())))
        );
        assert_eq!(
            blocked(ubuntu, user("unprivileged_userns (enforce)\n"), None),
            Some(UsernsBlocked::AppArmor(None))
        );
        assert_eq!(blocked(ubuntu, (Some("unconfined\n"), true), mahi), None);
        assert_eq!(
            blocked(ubuntu, user("usr.bin.mahi (unconfined)\n"), mahi),
            None
        );
        assert_eq!(blocked(ubuntu, (None, false), mahi), None);
        assert_eq!(
            blocked(
                (Some("0\n"), Some("1\n"), Some("9\n")),
                user("unconfined\n"),
                mahi
            ),
            None
        );
        assert_eq!(blocked((None, None, None), (None, false), mahi), None);
        assert_eq!(
            blocked((None, Some("0\n"), Some("9\n")), (None, false), mahi),
            Some(UsernsBlocked::Disabled("kernel.unprivileged_userns_clone"))
        );
        assert_eq!(
            blocked((None, Some("0\n"), Some("9\n")), (None, true), mahi),
            None
        );
        assert_eq!(
            blocked((None, None, Some("0\n")), (None, true), mahi),
            Some(UsernsBlocked::Disabled("user.max_user_namespaces"))
        );
    }

    #[test]
    fn the_messages_name_the_profile_file_or_the_setting_to_change() {
        let named = UsernsBlocked::AppArmor(Some("/opt/mahi/bin/mahi".to_owned())).to_string();
        assert!(
            named.contains(
                "allow this mahi alone with: /opt/mahi/bin/mahi apparmor | sudo tee \
                 /etc/apparmor.d/opt.mahi.bin.mahi && sudo apparmor_parser -r \
                 /etc/apparmor.d/opt.mahi.bin.mahi (or every program with sudo \
                 sysctl kernel.apparmor_restrict_unprivileged_userns=0)"
            ),
            "{named}"
        );
        assert!(UsernsBlocked::AppArmor(None).to_string().ends_with(
            "is unknown or cannot be named in an AppArmor profile, so allow every program with sudo \
                 sysctl kernel.apparmor_restrict_unprivileged_userns=0"
        ));
        assert!(
            UsernsBlocked::Disabled("user.max_user_namespaces")
                .to_string()
                .contains("user.max_user_namespaces=10000")
        );
        assert!(
            UsernsBlocked::Disabled("kernel.unprivileged_userns_clone")
                .to_string()
                .contains("sudo sysctl kernel.unprivileged_userns_clone=1")
        );
    }

    #[test]
    fn only_a_process_that_may_administer_counts_as_privileged() {
        assert!(may_administer("Name:\tmahi\nCapEff:\t000001ffffffffff\n"));
        assert!(may_administer("CapEff:\t0000000000200000\n"));
        assert!(!may_administer("CapEff:\t0000000000000000\n"));
        assert!(!may_administer("CapEff:\tnot hex\n"));
        assert!(!may_administer("no capabilities here\n"));
    }

    #[test]
    fn the_profile_is_named_after_mahis_path_and_only_allows_user_namespaces() {
        let profile = apparmor_profile(Path::new("/home/a/.cargo/bin/mahi")).unwrap();
        assert_eq!(profile.file_name, "home.a..cargo.bin.mahi");
        assert_eq!(
            profile.text,
            "abi <abi/4.0>,\ninclude <tunables/global>\n\nprofile home.a..cargo.bin.mahi \
             /home/a/.cargo/bin/mahi flags=(unconfined) {\n  userns,\n\n  include if exists \
             <local/home.a..cargo.bin.mahi>\n}\n"
        );
        assert_eq!(
            apparmor_profile(Path::new("/usr/bin/mahi"))
                .unwrap()
                .file_name,
            "usr.bin.mahi"
        );
        assert_eq!(
            apparmor_profile(Path::new("/usr/bin/mahi")).unwrap().text,
            include_str!("../../../packaging/deb/usr.bin.mahi")
        );
        for refused in [
            "relative/mahi",
            "/",
            "/opt/*/mahi",
            "/opt/{a,b}/mahi",
            "/opt/\"q\"/mahi",
            "/opt/a\nb",
            "/opt/a b/mahi",
            "/opt/it's/mahi",
            "/opt/@{HOME}/mahi",
            "/opt/a!b/mahi",
            "/opt/<a>/mahi",
            "/opt/mahi,",
        ] {
            assert_eq!(apparmor_profile(Path::new(refused)), None, "{refused}");
        }
    }
}
