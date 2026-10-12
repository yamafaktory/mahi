//! Creates, lists, fetches and deletes pairing refs through gix's local transport, which runs
//! the real `git receive-pack` and `git upload-pack`, so it needs `git` and runs with
//! `just test-git`.

#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        process::Command,
        sync::atomic::AtomicBool,
    };

    use gix::protocol::transport::{
        Protocol,
        client::blocking_io::file,
    };
    use mahi_store::{
        Pushed,
        Store,
        StoreError,
    };

    fn git(repository: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(["-c", "user.name=test", "-c", "user.email=test@example.org"])
            .args(args)
            .output()
            .expect("git is installed");
        assert!(output.status.success(), "git {args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn remote(path: &Path) -> file::SpawnProcessOnDemand {
        file::connect(path.as_os_str().as_encoded_bytes(), Protocol::V1, false).unwrap()
    }

    fn store(path: &Path) -> Store {
        gix::init(path).unwrap();
        Store::open(path).unwrap()
    }

    #[test]
    fn a_pairing_ref_is_created_once_fetched_without_a_local_ref_and_deleted_only_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("remote.git");
        std::fs::create_dir(&bare).unwrap();
        git(&bare, &["init", "-q", "--bare"]);
        let owner = store(&dir.path().join("owner"));
        let joiner_path = dir.path().join("joiner");
        let joiner = store(&joiner_path);
        let never = AtomicBool::new(false);

        assert!(owner.remote_pairings(remote(&bare)).unwrap().is_empty());
        assert_eq!(
            joiner.fetch_pairing(remote(&bare), 412, &never).unwrap(),
            None
        );
        let commit = owner.write_pairing(b"node relay").unwrap();
        assert_eq!(
            owner
                .push_pairing(remote(&bare), 412, commit, &never)
                .unwrap(),
            Pushed::Updated
        );
        assert_eq!(
            owner.remote_pairings(remote(&bare)).unwrap(),
            [(412, commit)]
        );
        let other = owner.write_pairing(b"someone else").unwrap();
        assert_eq!(
            owner
                .push_pairing(remote(&bare), 412, other, &never)
                .unwrap(),
            Pushed::Behind
        );

        assert_eq!(
            joiner
                .fetch_pairing(remote(&bare), 412, &never)
                .unwrap()
                .as_deref(),
            Some(&b"node relay"[..])
        );
        assert_eq!(git(&joiner_path, &["for-each-ref"]), "");

        assert_eq!(
            owner
                .delete_pairing(remote(&bare), 412, other, &never)
                .unwrap(),
            Pushed::Behind
        );
        assert_eq!(
            owner
                .delete_pairing(remote(&bare), 412, commit, &never)
                .unwrap(),
            Pushed::Updated
        );
        assert_eq!(
            owner
                .delete_pairing(remote(&bare), 412, commit, &never)
                .unwrap(),
            Pushed::UpToDate
        );
        assert!(owner.remote_pairings(remote(&bare)).unwrap().is_empty());
    }

    #[test]
    fn a_pairing_ref_of_another_shape_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("remote.git");
        std::fs::create_dir(&bare).unwrap();
        git(&bare, &["init", "-q", "--bare"]);
        let work = dir.path().join("work");
        std::fs::create_dir(&work).unwrap();
        git(&work, &["init", "-q"]);
        std::fs::write(work.join("where"), "place").unwrap();
        std::fs::write(work.join("extra"), "more").unwrap();
        git(&work, &["add", "."]);
        git(&work, &["commit", "-q", "-m", "not a pairing"]);
        git(
            &work,
            &[
                "push",
                "-q",
                bare.to_str().unwrap(),
                "HEAD:refs/mahi/pair/7",
            ],
        );
        let joiner = store(&dir.path().join("joiner"));
        assert!(matches!(
            joiner.fetch_pairing(remote(&bare), 7, &AtomicBool::new(false)),
            Err(StoreError::WrongObject { .. })
        ));

        std::fs::remove_file(work.join("extra")).unwrap();
        git(&work, &["add", "-A"]);
        git(&work, &["commit", "-q", "-m", "a pairing with history"]);
        git(
            &work,
            &[
                "push",
                "-q",
                bare.to_str().unwrap(),
                "HEAD:refs/mahi/pair/8",
            ],
        );
        assert!(matches!(
            joiner.fetch_pairing(remote(&bare), 8, &AtomicBool::new(false)),
            Err(StoreError::WrongObject { .. })
        ));
        for name in [
            "refs/mahi/pair/0412",
            "refs/mahi/pair/0",
            "refs/mahi/pair/x",
        ] {
            git(
                &work,
                &[
                    "push",
                    "-q",
                    bare.to_str().unwrap(),
                    &format!("HEAD:{name}"),
                ],
            );
        }
        let listed: Vec<u16> = joiner
            .remote_pairings(remote(&bare))
            .unwrap()
            .into_iter()
            .map(|(slot, _)| slot)
            .collect();
        assert_eq!(listed, [7, 8]);
    }
}
