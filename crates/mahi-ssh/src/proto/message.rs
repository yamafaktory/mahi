use super::wire::{
    NameList,
    Reader,
    WireError,
    put_bool,
    put_string,
    put_u8,
    put_u32,
};

pub(crate) const DISCONNECT: u8 = 1;
pub(crate) const IGNORE: u8 = 2;
pub(crate) const UNIMPLEMENTED: u8 = 3;
pub(crate) const DEBUG: u8 = 4;
pub(crate) const SERVICE_REQUEST: u8 = 5;
pub(crate) const SERVICE_ACCEPT: u8 = 6;
pub(crate) const KEXINIT: u8 = 20;
pub(crate) const NEWKEYS: u8 = 21;
pub(crate) const KEX_ECDH_INIT: u8 = 30;
pub(crate) const KEX_ECDH_REPLY: u8 = 31;
pub(crate) const USERAUTH_REQUEST: u8 = 50;
pub(crate) const USERAUTH_FAILURE: u8 = 51;
pub(crate) const USERAUTH_SUCCESS: u8 = 52;
pub(crate) const USERAUTH_BANNER: u8 = 53;
pub(crate) const USERAUTH_PK_OK: u8 = 60;
pub(crate) const GLOBAL_REQUEST: u8 = 80;
pub(crate) const REQUEST_SUCCESS: u8 = 81;
pub(crate) const REQUEST_FAILURE: u8 = 82;
pub(crate) const CHANNEL_OPEN: u8 = 90;
pub(crate) const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub(crate) const CHANNEL_OPEN_FAILURE: u8 = 92;
pub(crate) const CHANNEL_WINDOW_ADJUST: u8 = 93;
pub(crate) const CHANNEL_DATA: u8 = 94;
pub(crate) const CHANNEL_EXTENDED_DATA: u8 = 95;
pub(crate) const CHANNEL_EOF: u8 = 96;
pub(crate) const CHANNEL_CLOSE: u8 = 97;
pub(crate) const CHANNEL_REQUEST: u8 = 98;
pub(crate) const CHANNEL_SUCCESS: u8 = 99;
pub(crate) const CHANNEL_FAILURE: u8 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KexInit<'a> {
    pub(crate) cookie: [u8; 16],
    pub(crate) kex: NameList<'a>,
    pub(crate) host_key: NameList<'a>,
    pub(crate) cipher_c2s: NameList<'a>,
    pub(crate) cipher_s2c: NameList<'a>,
    pub(crate) mac_c2s: NameList<'a>,
    pub(crate) mac_s2c: NameList<'a>,
    pub(crate) compression_c2s: NameList<'a>,
    pub(crate) compression_s2c: NameList<'a>,
    pub(crate) language_c2s: NameList<'a>,
    pub(crate) language_s2c: NameList<'a>,
    pub(crate) first_kex_follows: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthMethod<'a> {
    None,
    PublicKey {
        algorithm: &'a [u8],
        key: &'a [u8],
        signature: Option<&'a [u8]>,
    },
    Other(&'a [u8]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Message<'a> {
    Disconnect {
        reason: u32,
        description: &'a [u8],
    },
    Ignore(&'a [u8]),
    Unimplemented {
        sequence: u32,
    },
    Debug {
        message: &'a [u8],
    },
    ServiceRequest(&'a [u8]),
    ServiceAccept(&'a [u8]),
    KexInit(KexInit<'a>),
    NewKeys,
    KexEcdhInit {
        client_public: &'a [u8],
    },
    KexEcdhReply {
        host_key: &'a [u8],
        server_public: &'a [u8],
        signature: &'a [u8],
    },
    UserauthRequest {
        user: &'a [u8],
        service: &'a [u8],
        method: AuthMethod<'a>,
    },
    UserauthFailure {
        methods: NameList<'a>,
        partial: bool,
    },
    UserauthSuccess,
    UserauthBanner {
        message: &'a [u8],
    },
    UserauthPkOk {
        algorithm: &'a [u8],
        key: &'a [u8],
    },
    GlobalRequest {
        name: &'a [u8],
        want_reply: bool,
        data: &'a [u8],
    },
    RequestSuccess {
        data: &'a [u8],
    },
    RequestFailure,
    ChannelOpen {
        kind: &'a [u8],
        sender: u32,
        window: u32,
        max_packet: u32,
        data: &'a [u8],
    },
    ChannelOpenConfirmation {
        recipient: u32,
        sender: u32,
        window: u32,
        max_packet: u32,
        data: &'a [u8],
    },
    ChannelOpenFailure {
        recipient: u32,
        reason: u32,
        description: &'a [u8],
    },
    ChannelWindowAdjust {
        recipient: u32,
        bytes: u32,
    },
    ChannelData {
        recipient: u32,
        data: &'a [u8],
    },
    ChannelExtendedData {
        recipient: u32,
        code: u32,
        data: &'a [u8],
    },
    ChannelEof {
        recipient: u32,
    },
    ChannelClose {
        recipient: u32,
    },
    ChannelRequest {
        recipient: u32,
        kind: &'a [u8],
        want_reply: bool,
        data: &'a [u8],
    },
    ChannelSuccess {
        recipient: u32,
    },
    ChannelFailure {
        recipient: u32,
    },
    Unknown(u8),
}

impl<'a> Message<'a> {
    pub(crate) fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(payload);
        let number = r.u8().map_err(|_| WireError::Empty)?;
        let message = match number {
            ..USERAUTH_REQUEST => decode_transport(number, &mut r)?,
            USERAUTH_REQUEST..GLOBAL_REQUEST => decode_userauth(number, &mut r)?,
            GLOBAL_REQUEST.. => decode_connection(number, &mut r)?,
        };
        r.finish()?;
        Ok(message)
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        if !(self.encode_transport(out)?
            || self.encode_userauth(out)?
            || self.encode_connection(out)?
            || self.encode_channel(out)?)
        {
            return Err(WireError::Empty);
        }
        Ok(())
    }

    fn encode_transport(&self, out: &mut Vec<u8>) -> Result<bool, WireError> {
        match *self {
            Self::Disconnect {
                reason,
                description,
            } => {
                put_u8(out, DISCONNECT);
                put_u32(out, reason);
                put_string(out, description)?;
                put_string(out, b"")?;
            }
            Self::Ignore(data) => {
                put_u8(out, IGNORE);
                put_string(out, data)?;
            }
            Self::Unimplemented { sequence } => {
                put_u8(out, UNIMPLEMENTED);
                put_u32(out, sequence);
            }
            Self::Debug { message } => {
                put_u8(out, DEBUG);
                put_bool(out, false);
                put_string(out, message)?;
                put_string(out, b"")?;
            }
            Self::ServiceRequest(name) => {
                put_u8(out, SERVICE_REQUEST);
                put_string(out, name)?;
            }
            Self::ServiceAccept(name) => {
                put_u8(out, SERVICE_ACCEPT);
                put_string(out, name)?;
            }
            Self::KexInit(ref init) => encode_kexinit(init, out)?,
            Self::NewKeys => put_u8(out, NEWKEYS),
            Self::KexEcdhInit { client_public } => {
                put_u8(out, KEX_ECDH_INIT);
                put_string(out, client_public)?;
            }
            Self::KexEcdhReply {
                host_key,
                server_public,
                signature,
            } => {
                put_u8(out, KEX_ECDH_REPLY);
                put_string(out, host_key)?;
                put_string(out, server_public)?;
                put_string(out, signature)?;
            }
            Self::Unknown(number) => {
                if !matches!(Message::decode(&[number]), Ok(Message::Unknown(_))) {
                    return Err(WireError::Unencodable);
                }
                put_u8(out, number);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn encode_userauth(&self, out: &mut Vec<u8>) -> Result<bool, WireError> {
        match *self {
            Self::UserauthRequest {
                user,
                service,
                method,
            } => {
                put_u8(out, USERAUTH_REQUEST);
                put_userauth_body(out, user, service, method)?;
            }
            Self::UserauthFailure { methods, partial } => {
                put_u8(out, USERAUTH_FAILURE);
                put_string(out, methods.as_str().as_bytes())?;
                put_bool(out, partial);
            }
            Self::UserauthSuccess => put_u8(out, USERAUTH_SUCCESS),
            Self::UserauthBanner { message } => {
                put_u8(out, USERAUTH_BANNER);
                put_string(out, message)?;
                put_string(out, b"")?;
            }
            Self::UserauthPkOk { algorithm, key } => {
                put_u8(out, USERAUTH_PK_OK);
                put_string(out, algorithm)?;
                put_string(out, key)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn encode_connection(&self, out: &mut Vec<u8>) -> Result<bool, WireError> {
        match *self {
            Self::GlobalRequest {
                name,
                want_reply,
                data,
            } => {
                put_u8(out, GLOBAL_REQUEST);
                put_string(out, name)?;
                put_bool(out, want_reply);
                out.extend_from_slice(data);
            }
            Self::RequestSuccess { data } => {
                put_u8(out, REQUEST_SUCCESS);
                out.extend_from_slice(data);
            }
            Self::RequestFailure => put_u8(out, REQUEST_FAILURE),
            Self::ChannelOpen {
                kind,
                sender,
                window,
                max_packet,
                data,
            } => {
                put_u8(out, CHANNEL_OPEN);
                put_string(out, kind)?;
                put_u32(out, sender);
                put_u32(out, window);
                put_u32(out, max_packet);
                out.extend_from_slice(data);
            }
            Self::ChannelOpenConfirmation {
                recipient,
                sender,
                window,
                max_packet,
                data,
            } => {
                put_u8(out, CHANNEL_OPEN_CONFIRMATION);
                put_u32(out, recipient);
                put_u32(out, sender);
                put_u32(out, window);
                put_u32(out, max_packet);
                out.extend_from_slice(data);
            }
            Self::ChannelOpenFailure {
                recipient,
                reason,
                description,
            } => {
                put_u8(out, CHANNEL_OPEN_FAILURE);
                put_u32(out, recipient);
                put_u32(out, reason);
                put_string(out, description)?;
                put_string(out, b"")?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn encode_channel(&self, out: &mut Vec<u8>) -> Result<bool, WireError> {
        match *self {
            Self::ChannelWindowAdjust { recipient, bytes } => {
                put_u8(out, CHANNEL_WINDOW_ADJUST);
                put_u32(out, recipient);
                put_u32(out, bytes);
            }
            Self::ChannelData { recipient, data } => {
                put_u8(out, CHANNEL_DATA);
                put_u32(out, recipient);
                put_string(out, data)?;
            }
            Self::ChannelExtendedData {
                recipient,
                code,
                data,
            } => {
                put_u8(out, CHANNEL_EXTENDED_DATA);
                put_u32(out, recipient);
                put_u32(out, code);
                put_string(out, data)?;
            }
            Self::ChannelEof { recipient } => {
                put_u8(out, CHANNEL_EOF);
                put_u32(out, recipient);
            }
            Self::ChannelClose { recipient } => {
                put_u8(out, CHANNEL_CLOSE);
                put_u32(out, recipient);
            }
            Self::ChannelRequest {
                recipient,
                kind,
                want_reply,
                data,
            } => {
                put_u8(out, CHANNEL_REQUEST);
                put_u32(out, recipient);
                put_string(out, kind)?;
                put_bool(out, want_reply);
                out.extend_from_slice(data);
            }
            Self::ChannelSuccess { recipient } => {
                put_u8(out, CHANNEL_SUCCESS);
                put_u32(out, recipient);
            }
            Self::ChannelFailure { recipient } => {
                put_u8(out, CHANNEL_FAILURE);
                put_u32(out, recipient);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

fn decode_transport<'a>(number: u8, r: &mut Reader<'a>) -> Result<Message<'a>, WireError> {
    Ok(match number {
        DISCONNECT => {
            let reason = r.u32()?;
            let description = r.string()?;
            r.string()?;
            Message::Disconnect {
                reason,
                description,
            }
        }
        IGNORE => Message::Ignore(r.string()?),
        UNIMPLEMENTED => Message::Unimplemented { sequence: r.u32()? },
        DEBUG => {
            r.bool()?;
            let message = r.string()?;
            r.string()?;
            Message::Debug { message }
        }
        SERVICE_REQUEST => Message::ServiceRequest(r.string()?),
        SERVICE_ACCEPT => Message::ServiceAccept(r.string()?),
        KEXINIT => Message::KexInit(decode_kexinit(r)?),
        NEWKEYS => Message::NewKeys,
        KEX_ECDH_INIT => Message::KexEcdhInit {
            client_public: r.string()?,
        },
        KEX_ECDH_REPLY => Message::KexEcdhReply {
            host_key: r.string()?,
            server_public: r.string()?,
            signature: r.string()?,
        },
        other => {
            r.rest();
            Message::Unknown(other)
        }
    })
}

fn decode_userauth<'a>(number: u8, r: &mut Reader<'a>) -> Result<Message<'a>, WireError> {
    Ok(match number {
        USERAUTH_REQUEST => decode_userauth_request(r)?,
        USERAUTH_FAILURE => Message::UserauthFailure {
            methods: r.name_list()?,
            partial: r.bool()?,
        },
        USERAUTH_SUCCESS => Message::UserauthSuccess,
        USERAUTH_BANNER => {
            let message = r.string()?;
            r.string()?;
            Message::UserauthBanner { message }
        }
        USERAUTH_PK_OK => Message::UserauthPkOk {
            algorithm: r.string()?,
            key: r.string()?,
        },
        other => {
            r.rest();
            Message::Unknown(other)
        }
    })
}

fn decode_connection<'a>(number: u8, r: &mut Reader<'a>) -> Result<Message<'a>, WireError> {
    Ok(match number {
        GLOBAL_REQUEST => Message::GlobalRequest {
            name: r.string()?,
            want_reply: r.bool()?,
            data: r.rest(),
        },
        REQUEST_SUCCESS => Message::RequestSuccess { data: r.rest() },
        REQUEST_FAILURE => Message::RequestFailure,
        CHANNEL_OPEN => Message::ChannelOpen {
            kind: r.string()?,
            sender: r.u32()?,
            window: r.u32()?,
            max_packet: r.u32()?,
            data: r.rest(),
        },
        CHANNEL_OPEN_CONFIRMATION => Message::ChannelOpenConfirmation {
            recipient: r.u32()?,
            sender: r.u32()?,
            window: r.u32()?,
            max_packet: r.u32()?,
            data: r.rest(),
        },
        CHANNEL_OPEN_FAILURE => {
            let recipient = r.u32()?;
            let reason = r.u32()?;
            let description = r.string()?;
            r.string()?;
            Message::ChannelOpenFailure {
                recipient,
                reason,
                description,
            }
        }
        CHANNEL_WINDOW_ADJUST => Message::ChannelWindowAdjust {
            recipient: r.u32()?,
            bytes: r.u32()?,
        },
        CHANNEL_DATA => Message::ChannelData {
            recipient: r.u32()?,
            data: r.string()?,
        },
        CHANNEL_EXTENDED_DATA => Message::ChannelExtendedData {
            recipient: r.u32()?,
            code: r.u32()?,
            data: r.string()?,
        },
        CHANNEL_EOF => Message::ChannelEof {
            recipient: r.u32()?,
        },
        CHANNEL_CLOSE => Message::ChannelClose {
            recipient: r.u32()?,
        },
        CHANNEL_REQUEST => Message::ChannelRequest {
            recipient: r.u32()?,
            kind: r.string()?,
            want_reply: r.bool()?,
            data: r.rest(),
        },
        CHANNEL_SUCCESS => Message::ChannelSuccess {
            recipient: r.u32()?,
        },
        CHANNEL_FAILURE => Message::ChannelFailure {
            recipient: r.u32()?,
        },
        other => {
            r.rest();
            Message::Unknown(other)
        }
    })
}

fn decode_kexinit<'a>(r: &mut Reader<'a>) -> Result<KexInit<'a>, WireError> {
    let init = KexInit {
        cookie: r.array()?,
        kex: r.name_list()?,
        host_key: r.name_list()?,
        cipher_c2s: r.name_list()?,
        cipher_s2c: r.name_list()?,
        mac_c2s: r.name_list()?,
        mac_s2c: r.name_list()?,
        compression_c2s: r.name_list()?,
        compression_s2c: r.name_list()?,
        language_c2s: r.name_list()?,
        language_s2c: r.name_list()?,
        first_kex_follows: r.bool()?,
    };
    r.u32()?;
    Ok(init)
}

fn encode_kexinit(init: &KexInit<'_>, out: &mut Vec<u8>) -> Result<(), WireError> {
    put_u8(out, KEXINIT);
    out.extend_from_slice(&init.cookie);
    for list in [
        init.kex,
        init.host_key,
        init.cipher_c2s,
        init.cipher_s2c,
        init.mac_c2s,
        init.mac_s2c,
        init.compression_c2s,
        init.compression_s2c,
        init.language_c2s,
        init.language_s2c,
    ] {
        put_string(out, list.as_str().as_bytes())?;
    }
    put_bool(out, init.first_kex_follows);
    put_u32(out, 0);
    Ok(())
}

fn decode_userauth_request<'a>(r: &mut Reader<'a>) -> Result<Message<'a>, WireError> {
    let user = r.string()?;
    let service = r.string()?;
    let name = r.string()?;
    let method = match name {
        b"none" => AuthMethod::None,
        b"publickey" => {
            let signed = r.bool()?;
            let algorithm = r.string()?;
            let key = r.string()?;
            let signature = if signed { Some(r.string()?) } else { None };
            AuthMethod::PublicKey {
                algorithm,
                key,
                signature,
            }
        }
        other => {
            r.rest();
            AuthMethod::Other(other)
        }
    };
    Ok(Message::UserauthRequest {
        user,
        service,
        method,
    })
}

pub(crate) fn put_userauth_body(
    out: &mut Vec<u8>,
    user: &[u8],
    service: &[u8],
    method: AuthMethod<'_>,
) -> Result<(), WireError> {
    put_string(out, user)?;
    put_string(out, service)?;
    match method {
        AuthMethod::None => put_string(out, b"none")?,
        AuthMethod::PublicKey {
            algorithm,
            key,
            signature,
        } => {
            put_string(out, b"publickey")?;
            put_bool(out, signature.is_some());
            put_string(out, algorithm)?;
            put_string(out, key)?;
            if let Some(signature) = signature {
                put_string(out, signature)?;
            }
        }
        AuthMethod::Other(b"none" | b"publickey") => return Err(WireError::Unencodable),
        AuthMethod::Other(name) => put_string(out, name)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn bytes() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..48)
    }

    fn names() -> impl Strategy<Value = String> {
        proptest::collection::vec("[!-+--~]{1,12}", 0..4).prop_map(|names| names.join(","))
    }

    #[derive(Debug, Clone)]
    struct Owned {
        number: u8,
        words: [u32; 4],
        flag: bool,
        fields: [Vec<u8>; 3],
        lists: [String; 10],
        cookie: [u8; 16],
    }

    fn owned() -> impl Strategy<Value = Owned> {
        (
            any::<u8>(),
            any::<[u32; 4]>(),
            any::<bool>(),
            [bytes(), bytes(), bytes()],
            [
                names(),
                names(),
                names(),
                names(),
                names(),
                names(),
                names(),
                names(),
                names(),
                names(),
            ],
            any::<[u8; 16]>(),
        )
            .prop_map(|(number, words, flag, fields, lists, cookie)| Owned {
                number,
                words,
                flag,
                fields,
                lists,
                cookie,
            })
    }

    fn list(text: &str) -> NameList<'_> {
        NameList::parse(text.as_bytes()).unwrap()
    }

    fn build(o: &Owned) -> Message<'_> {
        let [first, ..] = o.words;
        let [one, two, three] = &o.fields;
        let (one, two, three) = (&one[..], &two[..], &three[..]);
        match o.number % 31 {
            0 => Message::Disconnect {
                reason: first,
                description: one,
            },
            1 => Message::Ignore(one),
            2 => Message::Unimplemented { sequence: first },
            3 => Message::Debug { message: one },
            4 => Message::ServiceRequest(one),
            5 => Message::ServiceAccept(one),
            6 => Message::KexInit(KexInit {
                cookie: o.cookie,
                kex: list(&o.lists[0]),
                host_key: list(&o.lists[1]),
                cipher_c2s: list(&o.lists[2]),
                cipher_s2c: list(&o.lists[3]),
                mac_c2s: list(&o.lists[4]),
                mac_s2c: list(&o.lists[5]),
                compression_c2s: list(&o.lists[6]),
                compression_s2c: list(&o.lists[7]),
                language_c2s: list(&o.lists[8]),
                language_s2c: list(&o.lists[9]),
                first_kex_follows: o.flag,
            }),
            7 => Message::NewKeys,
            8 => Message::KexEcdhInit { client_public: one },
            9 => Message::KexEcdhReply {
                host_key: one,
                server_public: two,
                signature: three,
            },
            10 => Message::UserauthRequest {
                user: one,
                service: two,
                method: AuthMethod::PublicKey {
                    algorithm: three,
                    key: one,
                    signature: o.flag.then_some(two),
                },
            },
            11 => Message::UserauthRequest {
                user: one,
                service: two,
                method: AuthMethod::None,
            },
            12 => Message::UserauthFailure {
                methods: list(&o.lists[0]),
                partial: o.flag,
            },
            13 => Message::UserauthSuccess,
            14 => Message::UserauthBanner { message: one },
            15 => Message::UserauthPkOk {
                algorithm: one,
                key: two,
            },
            16 => Message::GlobalRequest {
                name: one,
                want_reply: o.flag,
                data: two,
            },
            17 => Message::RequestSuccess { data: one },
            18 => Message::RequestFailure,
            _ => build_connection(o),
        }
    }

    fn build_connection(o: &Owned) -> Message<'_> {
        let [first, second, third, fourth] = o.words;
        let [one, two, _] = &o.fields;
        let (one, two) = (&one[..], &two[..]);
        match o.number % 31 {
            19 => Message::ChannelOpen {
                kind: one,
                sender: first,
                window: second,
                max_packet: third,
                data: two,
            },
            20 => Message::ChannelOpenConfirmation {
                recipient: first,
                sender: second,
                window: third,
                max_packet: fourth,
                data: one,
            },
            21 => Message::ChannelOpenFailure {
                recipient: first,
                reason: second,
                description: one,
            },
            22 => Message::ChannelWindowAdjust {
                recipient: first,
                bytes: second,
            },
            23 => Message::ChannelData {
                recipient: first,
                data: one,
            },
            24 => Message::ChannelExtendedData {
                recipient: first,
                code: second,
                data: one,
            },
            25 => Message::ChannelEof { recipient: first },
            26 => Message::ChannelClose { recipient: first },
            27 => Message::ChannelRequest {
                recipient: first,
                kind: one,
                want_reply: o.flag,
                data: two,
            },
            28 => Message::ChannelSuccess { recipient: first },
            29 => Message::ChannelFailure { recipient: first },
            _ => Message::Unknown(200),
        }
    }

    #[test]
    fn a_kexinit_from_openssh_decodes() {
        let mut payload = vec![KEXINIT];
        payload.extend_from_slice(&[7; 16]);
        for list in [
            "curve25519-sha256,kex-strict-s-v00@openssh.com",
            "ssh-ed25519",
            "chacha20-poly1305@openssh.com",
            "chacha20-poly1305@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "none,zlib@openssh.com",
            "none,zlib@openssh.com",
            "",
            "",
        ] {
            put_string(&mut payload, list.as_bytes()).unwrap();
        }
        payload.extend_from_slice(&[0, 0, 0, 0, 0]);
        let Message::KexInit(init) = Message::decode(&payload).unwrap() else {
            panic!("not a kexinit");
        };
        assert!(init.kex.contains("kex-strict-s-v00@openssh.com"));
        assert!(!init.kex.contains("curve25519"));
        assert_eq!(init.language_c2s.names().count(), 0);
        assert!(!init.first_kex_follows);
        payload.push(0);
        assert_eq!(Message::decode(&payload), Err(WireError::Trailing));
    }

    #[test]
    fn an_empty_payload_is_refused_and_unknown_numbers_are_kept() {
        assert_eq!(Message::decode(&[]), Err(WireError::Empty));
        assert_eq!(Message::decode(&[192, 1, 2]), Ok(Message::Unknown(192)));
    }

    #[test]
    fn language_tags_and_always_display_are_read_and_ignored() {
        let mut debug = vec![DEBUG, 1];
        put_string(&mut debug, b"hello").unwrap();
        put_string(&mut debug, b"en").unwrap();
        assert_eq!(
            Message::decode(&debug),
            Ok(Message::Debug { message: b"hello" })
        );
        let mut disconnect = vec![DISCONNECT, 0, 0, 0, 11];
        put_string(&mut disconnect, b"bye").unwrap();
        put_string(&mut disconnect, b"en-GB").unwrap();
        assert_eq!(
            Message::decode(&disconnect),
            Ok(Message::Disconnect {
                reason: 11,
                description: b"bye"
            })
        );
        let mut banner = vec![USERAUTH_BANNER];
        put_string(&mut banner, b"welcome").unwrap();
        put_string(&mut banner, b"fr").unwrap();
        assert_eq!(
            Message::decode(&banner),
            Ok(Message::UserauthBanner {
                message: b"welcome"
            })
        );
        let mut failure = vec![CHANNEL_OPEN_FAILURE, 0, 0, 0, 7, 0, 0, 0, 2];
        put_string(&mut failure, b"no").unwrap();
        put_string(&mut failure, b"de").unwrap();
        assert_eq!(
            Message::decode(&failure),
            Ok(Message::ChannelOpenFailure {
                recipient: 7,
                reason: 2,
                description: b"no"
            })
        );
    }

    #[test]
    fn other_auth_methods_round_trip_but_never_shadow_known_ones() {
        let message = Message::UserauthRequest {
            user: b"git",
            service: b"ssh-connection",
            method: AuthMethod::Other(b"keyboard-interactive"),
        };
        let mut out = Vec::new();
        message.encode(&mut out).unwrap();
        out.extend_from_slice(b"\0\0\0\0");
        assert_eq!(Message::decode(&out), Ok(message));
        for shadow in [&b"none"[..], b"publickey"] {
            let message = Message::UserauthRequest {
                user: b"git",
                service: b"ssh-connection",
                method: AuthMethod::Other(shadow),
            };
            assert_eq!(message.encode(&mut Vec::new()), Err(WireError::Unencodable));
        }
    }

    #[test]
    fn unknown_never_encodes_a_known_message_number() {
        for number in 0..=u8::MAX {
            let byte = [number];
            let decoded = Message::decode(&byte);
            let encoded = Message::Unknown(number).encode(&mut Vec::new());
            assert_eq!(
                encoded.is_ok(),
                matches!(decoded, Ok(Message::Unknown(_))),
                "{number}"
            );
        }
    }

    #[test]
    fn a_channel_data_length_beyond_the_payload_is_refused() {
        let payload = [CHANNEL_DATA, 0, 0, 0, 1, 0, 0, 1, 0, b'x'];
        assert_eq!(Message::decode(&payload), Err(WireError::Truncated));
    }

    proptest! {
        #[test]
        fn every_message_decodes_to_what_was_encoded(o in owned()) {
            let message = build(&o);
            let mut out = Vec::new();
            message.encode(&mut out).unwrap();
            prop_assert_eq!(Message::decode(&out).unwrap(), message);
        }

        #[test]
        fn decoding_any_bytes_never_panics(payload in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = Message::decode(&payload);
        }

        #[test]
        fn a_cut_message_is_refused_or_decodes_differently(o in owned(), cut in any::<prop::sample::Index>()) {
            let message = build(&o);
            let mut out = Vec::new();
            message.encode(&mut out).unwrap();
            let at = cut.index(out.len());
            if let Ok(decoded) = Message::decode(&out[..at]) {
                prop_assert_ne!(decoded, message);
            }
        }
    }
}
