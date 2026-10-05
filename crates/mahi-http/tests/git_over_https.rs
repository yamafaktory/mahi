//! Pushes and fetches thread refs through an HTTPS server in the test that runs the real
//! `git http-backend`, so it needs `git` and runs with `just test-git`.

#[cfg(test)]
#[path = "support/tls.rs"]
mod tls;

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        path::{
            Path,
            PathBuf,
        },
        process::{
            Command,
            Stdio,
        },
        sync::{
            Arc,
            atomic::AtomicBool,
        },
    };

    use mahi_core::{
        ReadBudget,
        RefKind,
        ThreadId,
        ThreadRef,
    };
    use mahi_http::{
        HttpsAccess,
        HttpsRemote,
        Roots,
        Token,
        connect,
        connect_within,
    };
    use mahi_store::{
        EntryKind,
        Pushed,
        Store,
    };

    use crate::tls::{
        CA,
        Reply,
        Request,
        server,
    };

    const TOKEN: &str = "Basic eC1hY2Nlc3MtdG9rZW46c2VjcmV0";

    fn git(directory: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(arguments)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git is installed");
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn http_backend(root: &Path, request: &Request) -> Reply {
        if request.header("authorization") != Some(TOKEN) {
            return (401, Vec::new(), Vec::new());
        }
        let mut parts = request.line.split(' ');
        let method = parts.next().unwrap_or_default().to_owned();
        let target = parts.next().unwrap_or_default();
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let mut child = Command::new("git")
            .arg("http-backend")
            .env_clear()
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_PROJECT_ROOT", root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("REMOTE_USER", "mahi")
            .env("REQUEST_METHOD", method)
            .env("PATH_INFO", path)
            .env("QUERY_STRING", query)
            .env(
                "CONTENT_TYPE",
                request.header("content-type").unwrap_or_default(),
            )
            .env("CONTENT_LENGTH", request.body.len().to_string())
            .env(
                "GIT_PROTOCOL",
                request.header("git-protocol").unwrap_or_default(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("git is installed");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&request.body)
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let text = output.stdout;
        let split = text
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|at| (at, 4))
            .or_else(|| {
                text.windows(2)
                    .position(|window| window == b"\n\n")
                    .map(|at| (at, 2))
            })
            .unwrap();
        let head = String::from_utf8_lossy(&text[..split.0]).into_owned();
        let body = text[split.0 + split.1..].to_vec();
        let mut status = 200;
        let mut headers = Vec::new();
        for line in head.lines() {
            let (name, value) = line.split_once(':').unwrap();
            if name.eq_ignore_ascii_case("status") {
                status = value.trim()[..3].parse().unwrap();
            } else if name.eq_ignore_ascii_case("content-type") {
                headers.push(("Content-Type", value.trim().to_owned()));
            }
        }
        (status, headers, body)
    }

    fn access(token: Option<&str>) -> HttpsAccess {
        HttpsAccess {
            proxy: None,
            roots: Roots::Only(vec![CA.to_vec()]),
            token: token.map(|token| Token::new(token.to_owned())),
        }
    }

    fn store_at(path: &Path) -> Store {
        std::fs::create_dir_all(path).unwrap();
        gix::init(path).unwrap();
        Store::open(path).unwrap()
    }

    #[test]
    fn thread_refs_are_pushed_and_fetched_over_https_with_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let root: PathBuf = dir.path().to_path_buf();
        let remote = root.join("remote.git");
        std::fs::create_dir(&remote).unwrap();
        git(&remote, &["init", "-q", "--bare"]);
        git(&remote, &["config", "http.receivepack", "true"]);
        let projects = root.clone();
        let backend = server(Arc::new(move |request: &Request| {
            http_backend(&projects, request)
        }));
        let url =
            HttpsRemote::parse(&format!("https://localhost:{}/remote.git", backend.port)).unwrap();

        let local = store_at(&root.join("local"));
        let thread = ThreadId::random().unwrap();
        let meta = ThreadRef::new(thread, RefKind::Meta);
        let blob = local.write_blob(b"meta").unwrap();
        let tree = local
            .write_tree(&[("meta", EntryKind::Blob, blob)])
            .unwrap();
        let commit = local.append(&meta, None, tree, "meta").unwrap();

        let refused = connect(&url, &access(None)).map(|transport| {
            local.push_refs(
                transport,
                std::slice::from_ref(&meta),
                &AtomicBool::new(false),
            )
        });
        assert!(matches!(refused, Ok(Err(_))), "{refused:?}");
        let pushed = local
            .push_refs(
                connect(&url, &access(Some("secret"))).unwrap(),
                std::slice::from_ref(&meta),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(pushed, [(meta.clone(), Pushed::Updated)]);
        assert_eq!(
            git(&remote, &["rev-parse", &meta.to_string()]),
            commit.to_string()
        );
        git(&remote, &["fsck", "--strict", "--no-dangling"]);

        let other = store_at(&root.join("other"));
        other
            .fetch_thread(
                connect(&url, &access(Some("secret"))).unwrap(),
                thread,
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(other.fetched_refs(thread).unwrap(), [(meta, commit)]);
        let last = backend.requests.lock().unwrap().last().cloned().unwrap();
        assert_eq!(last.header("authorization"), Some(TOKEN));

        let budget = ReadBudget::new(100);
        let starved = store_at(&root.join("starved"));
        assert!(
            starved
                .fetch_thread(
                    connect_within(&url, &access(Some("secret")), budget.clone()).unwrap(),
                    thread,
                    &AtomicBool::new(false),
                )
                .is_err()
        );
        assert!(budget.exceeded());
        assert!(starved.fetched_refs(thread).unwrap().is_empty());
    }
}
