//! Adds remotes with `Store::add_remote` and reads them back with the `git` program, so it
//! needs `git` and runs with `just test-git`.

#[cfg(test)]
mod tests {
    use std::process::Command;

    use mahi_store::Store;

    fn git(dir: &std::path::Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    }

    #[test]
    fn git_reads_an_added_remotes_url_and_refspec_even_with_quotes_and_backslashes() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let url = "ssh://git@example.org/a;b#c\\d\"e.git";
        store.add_remote("odd", url).unwrap();
        store
            .add_remote("origin", "git@github.com:org/repo.git")
            .unwrap();
        assert_eq!(
            git(dir.path(), &["remote", "get-url", "odd"]),
            format!("{url}\n")
        );
        assert_eq!(git(dir.path(), &["remote"]), "odd\norigin\n");
        assert_eq!(
            git(dir.path(), &["config", "remote.origin.fetch"]),
            "+refs/heads/*:refs/remotes/origin/*\n"
        );
    }
}
