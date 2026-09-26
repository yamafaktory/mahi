use std::path::{
    Path,
    PathBuf,
};

use thiserror::Error;

const APP: &str = "mahi";
const IDENTITY_FILE: &str = "identity.age";

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
}
