use std::{
    io,
    path::{
        Path,
        PathBuf,
    },
};

use rustix::{
    fs::{
        Mode,
        OFlags,
    },
    io::Errno,
};
use thiserror::Error;

const APP: &str = "mahi";
const IDENTITY_FILE: &str = "identity.age";
const RECIPIENT_FILE: &str = "identity.pub";
const SIGNING_KEY_FILE: &str = "signing-key.pub";
const NODE_KEY_FILE: &str = "node.key";
const SETTINGS_FILE: &str = "config.toml";
const PROFILES_DIR: &str = "profiles";

/// mahi's per-user configuration directory.
///
/// On macOS it is `~/Library/Application Support/mahi`. Elsewhere it is `$XDG_CONFIG_HOME/mahi`,
/// or `~/.config/mahi` when `XDG_CONFIG_HOME` is unset, empty or relative, as the XDG base
/// directory specification requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDir(PathBuf);

/// The configuration directory cannot be determined.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// The home directory is unknown or not an absolute path.
    #[error("home directory is unknown or not absolute")]
    NoHome,
}

impl ConfigDir {
    /// Resolves the directory from the values of `HOME` and `XDG_CONFIG_HOME`, read once at
    /// startup by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::NoHome`] if `home` is missing or relative.
    pub fn resolve(
        home: Option<&Path>,
        xdg_config_home: Option<&Path>,
    ) -> Result<Self, ConfigError> {
        let home = home
            .filter(|home| home.is_absolute())
            .ok_or(ConfigError::NoHome)?;
        Ok(Self(platform_dir(home, xdg_config_home)))
    }

    /// Makes the directory private when it is one the user owns that its group or others may
    /// write to, as an installer that creates it with the user's umask can leave it, and returns
    /// whether it did. A missing directory, a link or one owned by someone else is left as it
    /// is, for the checks on reading and writing to refuse.
    ///
    /// # Errors
    ///
    /// Returns the error of opening, inspecting or changing the directory.
    pub fn make_private(&self) -> io::Result<bool> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let dir = match rustix::fs::open(&self.0, flags, Mode::empty()) {
            Ok(dir) => dir,
            Err(Errno::NOENT | Errno::LOOP | Errno::NOTDIR) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let stat = rustix::fs::fstat(&dir)?;
        let owned = stat.st_uid == rustix::process::geteuid().as_raw();
        let writable = Mode::from_raw_mode(stat.st_mode).intersects(Mode::WGRP | Mode::WOTH);
        if !owned || !writable {
            return Ok(false);
        }
        rustix::fs::fchmod(&dir, Mode::RWXU)?;
        Ok(true)
    }

    /// Returns the directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Returns the path of the encrypted identity file.
    #[must_use]
    pub fn identity_file(&self) -> PathBuf {
        self.0.join(IDENTITY_FILE)
    }

    /// Returns the path of the public half of the identity.
    #[must_use]
    pub fn recipient_file(&self) -> PathBuf {
        self.0.join(RECIPIENT_FILE)
    }

    /// Returns the path of the SSH public key that signs thread `meta` documents.
    #[must_use]
    pub fn signing_key_file(&self) -> PathBuf {
        self.0.join(SIGNING_KEY_FILE)
    }

    /// Returns the path of the secret key of the user's iroh node.
    #[must_use]
    pub fn node_key_file(&self) -> PathBuf {
        self.0.join(NODE_KEY_FILE)
    }

    /// Returns the path of the user's settings, `config.toml`.
    #[must_use]
    pub fn settings_file(&self) -> PathBuf {
        self.0.join(SETTINGS_FILE)
    }

    /// Returns the directory of the user's agent profiles, `profiles`.
    #[must_use]
    pub fn profiles_dir(&self) -> PathBuf {
        self.0.join(PROFILES_DIR)
    }
}

#[cfg(target_os = "macos")]
fn platform_dir(home: &Path, _xdg_config_home: Option<&Path>) -> PathBuf {
    home.join("Library").join("Application Support").join(APP)
}

#[cfg(not(target_os = "macos"))]
fn platform_dir(home: &Path, xdg_config_home: Option<&Path>) -> PathBuf {
    xdg_config_home
        .filter(|dir| dir.is_absolute())
        .map_or_else(|| home.join(".config"), Path::to_path_buf)
        .join(APP)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{
            PermissionsExt,
            symlink,
        },
    };

    use super::*;

    #[test]
    fn needs_an_absolute_home() {
        assert_eq!(ConfigDir::resolve(None, None), Err(ConfigError::NoHome));
        assert_eq!(
            ConfigDir::resolve(Some(Path::new("relative")), None),
            Err(ConfigError::NoHome)
        );
    }

    #[test]
    fn the_identity_file_is_inside_the_directory() {
        let dir = ConfigDir::resolve(Some(Path::new("/home/alice")), None).unwrap();
        assert_eq!(dir.identity_file(), dir.path().join("identity.age"));
        assert_eq!(dir.settings_file(), dir.path().join("config.toml"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_uses_application_support_and_ignores_xdg() {
        let dir = ConfigDir::resolve(Some(Path::new("/Users/alice")), Some(Path::new("/tmp/xdg")))
            .unwrap();
        assert_eq!(
            dir.path(),
            Path::new("/Users/alice/Library/Application Support/mahi")
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn linux_follows_xdg_config_home() {
        let home = Some(Path::new("/home/alice"));
        assert_eq!(
            ConfigDir::resolve(home, None).unwrap().path(),
            Path::new("/home/alice/.config/mahi")
        );
        assert_eq!(
            ConfigDir::resolve(home, Some(Path::new("/srv/cfg")))
                .unwrap()
                .path(),
            Path::new("/srv/cfg/mahi")
        );
        for ignored in ["", "relative/cfg"] {
            assert_eq!(
                ConfigDir::resolve(home, Some(Path::new(ignored)))
                    .unwrap()
                    .path(),
                Path::new("/home/alice/.config/mahi"),
                "{ignored:?}"
            );
        }
    }

    #[test]
    fn a_config_directory_others_may_write_to_is_made_private_once() {
        let home = tempfile::tempdir().unwrap();
        let config = ConfigDir::resolve(Some(home.path()), Some(&home.path().join("xdg"))).unwrap();
        assert!(!config.make_private().unwrap());
        fs::create_dir_all(config.path()).unwrap();
        fs::set_permissions(config.path(), fs::Permissions::from_mode(0o775)).unwrap();
        assert!(config.make_private().unwrap());
        let mode = fs::metadata(config.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(!config.make_private().unwrap());
        fs::set_permissions(config.path(), fs::Permissions::from_mode(0o702)).unwrap();
        assert!(config.make_private().unwrap());
        let mode = fs::metadata(config.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        let elsewhere = home.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o777)).unwrap();
        fs::remove_dir(config.path()).unwrap();
        symlink(&elsewhere, config.path()).unwrap();
        assert!(!config.make_private().unwrap());
        let mode = fs::metadata(&elsewhere).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o777);
    }
}
