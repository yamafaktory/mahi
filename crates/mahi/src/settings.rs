use std::{
    fs::File,
    io::{
        self,
        Read,
    },
    path::{
        Path,
        PathBuf,
    },
};

use mahi_identity::ConfigDir;
use mahi_term::{
    PaletteKey,
    PaletteKeyError,
};
use serde::Deserialize;
use thiserror::Error;

const MAX_SETTINGS_BYTES: u64 = 64 * 1024;

/// What the user set in `config.toml`, in mahi's configuration directory.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) palette_key: PaletteKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct SettingsFile {
    palette_key: Option<String>,
}

/// `config.toml` cannot be used.
#[derive(Debug, Error)]
pub(crate) enum SettingsError {
    #[error("cannot read {0}: {1}")]
    Read(PathBuf, #[source] io::Error),
    #[error("{0} is larger than 64 KiB")]
    TooLarge(PathBuf),
    #[error("{0} is not valid: {1}")]
    Invalid(PathBuf, String),
    #[error("palette-key in {0}: {1}")]
    PaletteKey(PathBuf, #[source] PaletteKeyError),
}

impl Settings {
    /// Reads `config.toml` in `config`; a missing file gives the defaults.
    pub(crate) fn load(config: &ConfigDir) -> Result<Self, SettingsError> {
        Self::read(&config.settings_file())
    }

    fn read(path: &Path) -> Result<Self, SettingsError> {
        let failed = |error| SettingsError::Read(path.to_path_buf(), error);
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(failed(error)),
        };
        let mut text = String::new();
        file.take(MAX_SETTINGS_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(failed)?;
        if u64::try_from(text.len()).map_or(true, |length| length > MAX_SETTINGS_BYTES) {
            return Err(SettingsError::TooLarge(path.to_path_buf()));
        }
        let file: SettingsFile = toml::from_str(&text).map_err(|error| {
            SettingsError::Invalid(path.to_path_buf(), error.message().to_owned())
        })?;
        let palette_key = file
            .palette_key
            .map(|name| name.parse())
            .transpose()
            .map_err(|error| SettingsError::PaletteKey(path.to_path_buf(), error))?
            .unwrap_or_default();
        Ok(Self { palette_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(text: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, text).unwrap();
        (dir, path)
    }

    #[test]
    fn a_missing_or_empty_file_gives_ctrl_space() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Settings::read(&dir.path().join("config.toml")).unwrap(),
            Settings::default()
        );
        let (_dir, path) = written("");
        assert_eq!(
            Settings::read(&path).unwrap().palette_key,
            PaletteKey::CTRL_SPACE
        );
    }

    #[test]
    fn palette_key_chooses_the_key() {
        let (_dir, path) = written("palette-key = \"f5\"\n");
        assert_eq!(
            Settings::read(&path).unwrap().palette_key,
            "f5".parse().unwrap()
        );
    }

    #[test]
    fn unknown_settings_bad_keys_bad_toml_and_huge_files_are_refused() {
        for (text, wanted) in [
            ("palette_key = \"f5\"\n", "Invalid"),
            ("palette-key = 5\n", "Invalid"),
            ("palette-key = \"ctrl-m\"\n", "PaletteKey"),
            ("palette-key = ", "Invalid"),
            ("colour = \"red\"\n", "Invalid"),
        ] {
            let (_dir, path) = written(text);
            let error = Settings::read(&path).unwrap_err();
            assert!(
                format!("{error:?}").starts_with(wanted),
                "{text:?}: {error:?}"
            );
            assert!(error.to_string().contains("config.toml"), "{error}");
        }
        let huge = format!("# {}\n", "x".repeat(64 * 1024));
        let (_dir, path) = written(&huge);
        assert!(matches!(
            Settings::read(&path),
            Err(SettingsError::TooLarge(_))
        ));
    }
}
