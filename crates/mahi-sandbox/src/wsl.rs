#[cfg(target_os = "linux")]
const RELEASE: &str = "/proc/sys/kernel/osrelease";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wsl {
    One,
    Two,
}

impl Wsl {
    pub(crate) fn from_release(release: &str) -> Option<Self> {
        if release.trim_end().ends_with("-Microsoft") {
            Some(Self::One)
        } else if release.contains("microsoft") {
            Some(Self::Two)
        } else {
            None
        }
    }

    pub(crate) fn kernel_hint(self) -> &'static str {
        match self {
            Self::One => "",
            Self::Two => {
                "; update WSL's kernel in Windows with wsl --update, and remove any custom \
                 kernel set in .wslconfig"
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn current() -> Option<Self> {
        std::fs::read_to_string(RELEASE)
            .ok()
            .and_then(|release| Self::from_release(&release))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernel_release_tells_wsl_1_from_wsl_2_and_from_other_kernels() {
        assert_eq!(Wsl::from_release("4.4.0-19041-Microsoft\n"), Some(Wsl::One));
        assert_eq!(
            Wsl::from_release("6.6.87.2-microsoft-standard-WSL2\n"),
            Some(Wsl::Two)
        );
        assert_eq!(
            Wsl::from_release("5.15.167.4-microsoft-standard-WSL2+\n"),
            Some(Wsl::Two)
        );
        assert_eq!(Wsl::from_release("6.6.0-Microsoft-custom\n"), None);
        assert_eq!(Wsl::from_release("5.15.0-1057-azure\n"), None);
        assert_eq!(Wsl::from_release("7.2.9-1-cachyos\n"), None);
        assert_eq!(Wsl::from_release(""), None);
    }

    #[test]
    fn only_wsl_2_is_told_how_to_update_its_kernel() {
        assert!(Wsl::Two.kernel_hint().contains("wsl --update"));
        assert_eq!(Wsl::One.kernel_hint(), "");
    }
}
