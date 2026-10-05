//! Fetches and pushes with gix through `SshTransport` against OpenSSH's `sshd`, which runs the
//! real `git upload-pack` and `git receive-pack`, with keys from a real `ssh-agent`; it needs
//! OpenSSH and `git`, and runs with `just test-git`.

#[cfg(test)]
#[path = "openssh/mod.rs"]
mod openssh;

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fmt::Write as _,
        path::{
            Path,
            PathBuf,
        },
        process::Command,
        sync::atomic::AtomicBool,
    };

    use mahi_ssh::SshTransport;

    use crate::openssh::{
        self,
        OpenSsh,
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

    fn source(server: &OpenSsh) -> (PathBuf, String) {
        let source = server.dir.path().join("source");
        std::fs::create_dir(&source).unwrap();
        git(&source, &["init", "-q", "-b", "main"]);
        std::fs::write(source.join("README"), "hello\n").unwrap();
        git(&source, &["add", "README"]);
        git(&source, &["commit", "-q", "-m", "first"]);
        let head = git(&source, &["rev-parse", "HEAD"]);
        git(&source, &["update-ref", "refs/threads/t1/meta", &head]);
        (source, head)
    }

    fn fetch(server: &OpenSsh, path: &Path) -> Result<gix::Repository, Box<dyn Error>> {
        let target = server.dir.path().join("target");
        let repository = gix::init_bare(&target)?;
        let url = server.url(path);
        let transport = SshTransport::connect(
            server.remote(path),
            &server.known_hosts,
            &server.agent,
            "nobody",
            None,
        )?;
        let remote = repository.remote_at(url.as_str())?.with_refspecs(
            [
                "+refs/heads/*:refs/heads/*",
                "+refs/threads/*:refs/threads/*",
            ],
            gix::remote::Direction::Fetch,
        )?;
        remote
            .to_connection_with_transport(transport)
            .prepare_fetch(
                gix::progress::Discard,
                gix::remote::ref_map::Options::default(),
            )?
            .receive(gix::progress::Discard, &AtomicBool::new(false))?;
        Ok(gix::open(&target)?)
    }

    #[test]
    fn gix_fetches_heads_and_thread_refs_over_ssh_with_protocol_version_2() {
        let server = openssh::start("ssh-ed25519", &[]);
        let (source, head) = source(&server);
        let fetched =
            fetch(&server, &source).unwrap_or_else(|error| panic!("{error}: {}", server.log()));
        for name in ["refs/heads/main", "refs/threads/t1/meta"] {
            let reference = fetched.find_reference(name).unwrap();
            assert_eq!(reference.id().to_string(), head, "{name}");
        }
        let commit = fetched
            .find_object(gix::ObjectId::from_hex(head.as_bytes()).unwrap())
            .unwrap()
            .into_commit();
        let readme = commit.tree().unwrap().find_entry("README").unwrap().id();
        assert_eq!(&*fetched.find_object(readme).unwrap().data, b"hello\n");
        assert_eq!(server.protocols(), ["version=2"]);
    }

    #[test]
    fn thread_refs_are_pushed_over_ssh_with_git_receive_pack() {
        let server = openssh::start("ssh-ed25519", &[]);
        let remote = server.dir.path().join("remote.git");
        std::fs::create_dir(&remote).unwrap();
        git(&remote, &["init", "-q", "--bare"]);
        let local = server.dir.path().join("local");
        gix::init(&local).unwrap();
        let store = mahi_store::Store::open(&local).unwrap();
        let meta = mahi_core::ThreadRef::new(
            mahi_core::ThreadId::random().unwrap(),
            mahi_core::RefKind::Meta,
        );
        let blob = store.write_blob(b"meta").unwrap();
        let tree = store
            .write_tree(&[("meta", mahi_store::EntryKind::Blob, blob)])
            .unwrap();
        let commit = store.append(&meta, None, tree, "meta").unwrap();
        let transport = SshTransport::connect(
            server.remote(&remote),
            &server.known_hosts,
            &server.agent,
            "nobody",
            None,
        )
        .unwrap();
        let pushed = store
            .push_refs(
                transport,
                std::slice::from_ref(&meta),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(pushed, [(meta.clone(), mahi_store::Pushed::Updated)]);
        assert_eq!(
            git(&remote, &["rev-parse", &meta.to_string()]),
            commit.to_string()
        );
        git(&remote, &["fsck", "--strict", "--no-dangling"]);
        assert_eq!(server.protocols(), [""]);
    }

    #[test]
    fn a_missing_repository_reports_what_the_remote_said() {
        let server = openssh::start("ssh-ed25519", &[]);
        let missing = server.dir.path().join("missing");
        let error = fetch(&server, &missing).unwrap_err();
        let mut chain = String::new();
        let mut cause: Option<&dyn Error> = Some(&*error);
        while let Some(error) = cause {
            write!(chain, "{error}: ").unwrap();
            cause = error.source();
        }
        assert!(chain.contains("the remote said: "), "{chain}");
        assert!(chain.contains("missing"), "{chain}");
    }

    #[test]
    fn a_spent_read_budget_stops_a_fetch_and_nothing_is_fetched() {
        let server = openssh::start("ssh-ed25519", &[]);
        let (source, head) = source(&server);
        let local = server.dir.path().join("local");
        gix::init(&local).unwrap();
        let store = mahi_store::Store::open(&local).unwrap();
        let thread: mahi_core::ThreadId = "00000000000000000000000000000001".parse().unwrap();
        git(
            &source,
            &["update-ref", &format!("refs/threads/{thread}/meta"), &head],
        );
        let connect = |budget: &mahi_core::ReadBudget| {
            SshTransport::connect(
                server.remote(&source),
                &server.known_hosts,
                &server.agent,
                "nobody",
                None,
            )
            .unwrap_or_else(|error| panic!("{error}: {}", server.log()))
            .with_read_budget(budget.clone())
        };
        let small = mahi_core::ReadBudget::new(200);
        assert!(
            store
                .fetch_thread(connect(&small), thread, &AtomicBool::new(false))
                .is_err()
        );
        assert!(small.exceeded());
        assert!(store.fetched_refs(thread).unwrap().is_empty());
        let enough = mahi_core::ReadBudget::new(1 << 20);
        store
            .fetch_thread(connect(&enough), thread, &AtomicBool::new(false))
            .unwrap_or_else(|error| panic!("{error}: {}", server.log()));
        assert!(!enough.exceeded());
        assert_eq!(store.fetched_refs(thread).unwrap().len(), 1);
    }
}
