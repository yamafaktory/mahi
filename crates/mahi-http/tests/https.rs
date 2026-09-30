//! Talks to an HTTPS server in the test, signed by a test authority, directly and through an
//! HTTP `CONNECT` proxy in the test.

#[cfg(test)]
#[path = "support/tls.rs"]
mod tls;

#[cfg(test)]
mod tests {
    use std::{
        io::{
            Read,
            Write,
        },
        net::{
            Shutdown,
            TcpListener,
            TcpStream,
        },
        sync::{
            Arc,
            Mutex,
        },
        thread,
    };

    use gix_transport::{
        Service,
        client::blocking_io::{
            Transport,
            http::{
                Http,
                PostBodyDataKind,
            },
        },
    };
    use mahi_http::{
        HttpsAccess,
        HttpsRemote,
        ProxySetting,
        Roots,
        Token,
        client,
        connect,
    };

    use crate::tls::{
        CA,
        Request,
        read_request,
        server,
    };

    struct Proxy {
        port: u16,
        targets: Arc<Mutex<Vec<String>>>,
        headers: Arc<Mutex<Vec<String>>>,
    }

    fn proxy() -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let targets = Arc::new(Mutex::new(Vec::new()));
        let headers = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&targets);
        let seen_headers = Arc::clone(&headers);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut downstream) = stream else { return };
                let Some(request) = read_request(&mut downstream) else {
                    continue;
                };
                seen_headers
                    .lock()
                    .unwrap()
                    .extend(request.headers.iter().cloned());
                let target = request
                    .line
                    .strip_prefix("CONNECT ")
                    .and_then(|rest| rest.split(' ').next())
                    .unwrap()
                    .to_owned();
                seen.lock().unwrap().push(target.clone());
                let port = target.rsplit_once(':').unwrap().1;
                let upstream =
                    TcpStream::connect(("127.0.0.1", port.parse::<u16>().unwrap())).unwrap();
                downstream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .unwrap();
                let (mut up_read, mut up_write) = (upstream.try_clone().unwrap(), upstream);
                let (mut down_read, mut down_write) = (downstream.try_clone().unwrap(), downstream);
                thread::spawn(move || {
                    let _ = std::io::copy(&mut down_read, &mut up_write);
                    let _ = up_write.shutdown(Shutdown::Write);
                });
                thread::spawn(move || {
                    let _ = std::io::copy(&mut up_read, &mut down_write);
                    let _ = down_write.shutdown(Shutdown::Write);
                });
            }
        });
        Proxy {
            port,
            targets,
            headers,
        }
    }

    fn access(proxy: Option<ProxySetting>) -> HttpsAccess {
        HttpsAccess {
            proxy,
            roots: Roots::Only(vec![CA.to_vec()]),
            token: None,
        }
    }

    fn answer(request: &Request) -> (u16, Vec<(&'static str, String)>, Vec<u8>) {
        match request.line.split(' ').nth(1).unwrap_or_default() {
            "/ok" => (
                200,
                vec![("Content-Type", "application/x-test".to_owned())],
                b"hello".to_vec(),
            ),
            "/echo" => (200, Vec::new(), request.body.clone()),
            "/app.git/info/refs?service=git-upload-pack" => (
                200,
                vec![(
                    "Content-Type",
                    "application/x-git-upload-pack-advertisement".to_owned(),
                )],
                b"000eversion 2\n0000".to_vec(),
            ),
            "/private" => (401, Vec::new(), Vec::new()),
            "/moved" => (
                301,
                vec![("Location", "https://elsewhere.example/".to_owned())],
                Vec::new(),
            ),
            _ => (404, Vec::new(), Vec::new()),
        }
    }

    fn read_all(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
        let mut all = Vec::new();
        reader.read_to_end(&mut all)?;
        Ok(all)
    }

    #[test]
    fn requests_reach_the_server_with_their_headers_and_answers_come_back() {
        let server = server(Arc::new(answer));
        let base = format!("https://localhost:{}", server.port);
        let mut http = client("localhost", &access(None)).unwrap();
        let got = http
            .get(&format!("{base}/ok"), &base, ["Git-Protocol: version=2"])
            .unwrap();
        let headers = read_all(got.headers).unwrap();
        assert!(String::from_utf8_lossy(&headers).contains("content-type: application/x-test"));
        assert_eq!(read_all(got.body).unwrap(), b"hello");
        let seen = server.requests.lock().unwrap()[0].clone();
        assert_eq!(seen.header("git-protocol"), Some("version=2"));

        let mut posted = http
            .post(
                &format!("{base}/echo"),
                &base,
                ["Content-Type: application/x-git-upload-pack-request"],
                PostBodyDataKind::Unbounded,
            )
            .unwrap();
        let payload: Vec<u8> = (0..300_000_u32).map(|index| (index % 251) as u8).collect();
        posted.post_body.write_all(&payload).unwrap();
        drop(posted.post_body);
        assert!(read_all(posted.headers).is_ok());
        assert_eq!(read_all(posted.body).unwrap(), payload);
    }

    #[test]
    fn refused_access_redirects_and_unknown_authorities_are_errors() {
        let server = server(Arc::new(answer));
        let base = format!("https://localhost:{}", server.port);
        let mut http = client("localhost", &access(None)).unwrap();
        let refused = http.get(&format!("{base}/private"), &base, [""; 0]);
        assert!(format!("{:?}", refused.err().unwrap()).contains("refused access (HTTP 401)"));
        let moved = http.get(&format!("{base}/moved"), &base, [""; 0]);
        assert!(format!("{:?}", moved.err().unwrap()).contains("redirected"));
        assert_eq!(server.requests.lock().unwrap().len(), 2);
        let posted = http
            .post(
                &format!("{base}/private"),
                &base,
                [""; 0],
                PostBodyDataKind::Unbounded,
            )
            .unwrap();
        drop(posted.post_body);
        assert!(read_all(posted.body).is_err());

        let mut untrusted = client(
            "localhost",
            &HttpsAccess {
                roots: Roots::WebPki,
                ..access(None)
            },
        )
        .unwrap();
        assert!(
            untrusted
                .get(&format!("{base}/ok"), &base, [""; 0])
                .is_err()
        );
    }

    #[test]
    fn requests_go_through_the_proxy_unless_no_proxy_names_the_host() {
        let server = server(Arc::new(answer));
        let proxy = proxy();
        let base = format!("https://localhost:{}", server.port);
        let setting = |no_proxy: &str| {
            ProxySetting::from_values(Some(&format!("127.0.0.1:{}", proxy.port)), Some(no_proxy))
                .unwrap()
        };
        let mut proxied = client("localhost", &access(setting("example.com"))).unwrap();
        let got = proxied.get(&format!("{base}/ok"), &base, [""; 0]).unwrap();
        assert_eq!(read_all(got.body).unwrap(), b"hello");
        assert_eq!(
            *proxy.targets.lock().unwrap(),
            [format!("localhost:{}", server.port)]
        );
        let remote = HttpsRemote::parse(&format!("{base}/app.git")).unwrap();
        let mut transport = connect(
            &remote,
            &HttpsAccess {
                token: Some(Token::new("tok".to_owned())),
                ..access(setting("example.com"))
            },
        )
        .unwrap();
        transport.handshake(Service::UploadPack, &[]).unwrap();
        assert!(proxy.headers.lock().unwrap().iter().all(|header| {
            !header.to_ascii_lowercase().starts_with("authorization") && !header.contains("dG9r")
        }));
        let tunnelled = server.requests.lock().unwrap().last().cloned().unwrap();
        assert_eq!(
            tunnelled.header("authorization"),
            Some("Basic eC1hY2Nlc3MtdG9rZW46dG9r")
        );
        let mut direct = client("localhost", &access(setting("localhost"))).unwrap();
        let got = direct.get(&format!("{base}/ok"), &base, [""; 0]).unwrap();
        assert_eq!(read_all(got.body).unwrap(), b"hello");
        assert_eq!(proxy.targets.lock().unwrap().len(), 2);
        assert_eq!(server.requests.lock().unwrap().len(), 3);
    }

    #[test]
    fn the_token_is_sent_as_the_urls_user_or_as_stored_and_plain_http_is_refused() {
        let server = server(Arc::new(answer));
        let base = format!("https://localhost:{}", server.port);
        for (url, token, expected) in [
            (
                format!("https://bob@localhost:{}/app.git", server.port),
                "tok",
                "Basic Ym9iOnRvaw==",
            ),
            (
                format!("{base}/app.git"),
                "alice:secret",
                "Basic YWxpY2U6c2VjcmV0",
            ),
        ] {
            let remote = HttpsRemote::parse(&url).unwrap();
            let mut transport = connect(
                &remote,
                &HttpsAccess {
                    token: Some(Token::new(token.to_owned())),
                    ..access(None)
                },
            )
            .unwrap();
            transport.handshake(Service::UploadPack, &[]).unwrap();
            let seen = server.requests.lock().unwrap().last().cloned().unwrap();
            assert_eq!(seen.header("authorization"), Some(expected), "{url}");
        }
        let mut http = client("localhost", &access(None)).unwrap();
        let plain = format!("http://localhost:{}/ok", server.port);
        assert!(http.get(&plain, &plain, [""; 0]).is_err());
        assert_eq!(server.requests.lock().unwrap().len(), 2);
    }
}
