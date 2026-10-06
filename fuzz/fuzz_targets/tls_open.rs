#![no_main]

use rustls::{
    ContentType,
    ProtocolVersion,
    Side,
    SupportedCipherSuite,
    Tls13CipherSuite,
    crypto::cipher::{
        InboundOpaqueMessage,
        OutboundPlainMessage,
    },
    internal::{
        derive_traffic_iv,
        derive_traffic_key,
    },
    quic::{
        Keys,
        Version,
    },
};

const MAX_RECORD: usize = 1 << 14;

fn records(suite: &'static Tls13CipherSuite, secret: &[u8], seq: u64, body: &[u8]) {
    let typ = match body.first().copied().map(ContentType::from) {
        None | Some(ContentType::Unknown(0)) => ContentType::ApplicationData,
        Some(typ) => typ,
    };
    let expander = suite.hkdf_provider.extract_from_secret(None, secret);
    let key = || derive_traffic_key(&*expander, suite.aead_alg);
    let iv = || derive_traffic_iv(&*expander);
    let mut decrypter = suite.aead_alg.decrypter(key(), iv());

    let mut arbitrary = body.to_vec();
    let opaque = InboundOpaqueMessage::new(
        ContentType::ApplicationData,
        ProtocolVersion::TLSv1_2,
        &mut arbitrary,
    );
    let _ = decrypter.decrypt(opaque, seq);

    let plain = &body[..body.len().min(MAX_RECORD)];
    let mut encrypter = suite.aead_alg.encrypter(key(), iv());
    let message = OutboundPlainMessage {
        typ,
        version: ProtocolVersion::TLSv1_2,
        payload: plain.into(),
    };
    let sealed = encrypter
        .encrypt(message, seq)
        .expect("a record within the size limit seals")
        .encode();
    let mut sealed_body = sealed[5..].to_vec();
    let opaque = InboundOpaqueMessage::new(
        ContentType::ApplicationData,
        ProtocolVersion::TLSv1_2,
        &mut sealed_body,
    );
    let opened = decrypter
        .decrypt(opaque, seq)
        .expect("a sealed record opens");
    assert_eq!(opened.typ, typ);
    assert_eq!(opened.payload, plain);
}

fn packets(suite: &'static Tls13CipherSuite, connection_id: &[u8], number: u64, data: &[u8]) {
    let Some(quic) = suite.quic else {
        return;
    };
    let client = Keys::initial(Version::V1, suite, quic, connection_id, Side::Client);
    let server = Keys::initial(Version::V1, suite, quic, connection_id, Side::Server);
    let header_len = data
        .first()
        .map_or(0, |&first| usize::from(first) % 64)
        .min(data.len());
    let (header, payload) = data.split_at(header_len);

    let mut header_copy = header.to_vec();
    let mut payload_copy = payload.to_vec();
    if let Some((first, packet_number)) = header_copy.split_first_mut() {
        let _ = client
            .remote
            .header
            .decrypt_in_place(payload, first, packet_number);
        let packet_number_len = packet_number.len().min(4);
        let _ = client.remote.header.decrypt_in_place(
            &payload[..payload.len().min(client.remote.header.sample_len())],
            first,
            &mut packet_number[..packet_number_len],
        );
    }
    let _ = client
        .remote
        .packet
        .decrypt_in_place(number, header, &mut payload_copy);
    let mut payload_copy = payload.to_vec();
    let _ = client.remote.packet.decrypt_in_place_for_path(
        (number >> 32) as u32,
        number,
        header,
        &mut payload_copy,
    );

    let mut sealed = payload.to_vec();
    let tag = server
        .local
        .packet
        .encrypt_in_place(number, header, &mut sealed)
        .expect("a packet seals");
    sealed.extend_from_slice(tag.as_ref());
    let opened = client
        .remote
        .packet
        .decrypt_in_place(number, header, &mut sealed)
        .expect("a sealed packet opens");
    assert_eq!(opened, payload);

    let path = (number >> 32) as u32;
    let mut sealed = payload.to_vec();
    let tag = server
        .local
        .packet
        .encrypt_in_place_for_path(path, number, header, &mut sealed)
        .expect("a packet seals for a path");
    sealed.extend_from_slice(tag.as_ref());
    if path != 0 {
        assert!(
            client
                .remote
                .packet
                .decrypt_in_place(number, header, &mut sealed.clone())
                .is_err(),
            "a packet sealed for another path does not open on the first"
        );
    }
    let opened = client
        .remote
        .packet
        .decrypt_in_place_for_path(path, number, header, &mut sealed)
        .expect("a packet sealed for a path opens on it");
    assert_eq!(opened, payload);

    let sample_len = server.local.header.sample_len();
    if let (Some(sample), Some((first, packet_number))) =
        (payload.get(..sample_len), header_copy.split_first_mut())
    {
        let packet_number_len = packet_number.len().min(4);
        let (mut masked_first, mut masked) = (*first, packet_number[..packet_number_len].to_vec());
        server
            .local
            .header
            .encrypt_in_place(sample, &mut masked_first, &mut masked)
            .expect("a header is protected");
        client
            .remote
            .header
            .decrypt_in_place(sample, &mut masked_first, &mut masked)
            .expect("a protected header is opened");
        assert_eq!(masked_first, *first);
        assert_eq!(masked, packet_number[..packet_number_len]);
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&choice, rest)) = data.split_first() else {
        return;
    };
    let provider = mahi_tls::provider();
    let SupportedCipherSuite::Tls13(suite) =
        provider.cipher_suites[usize::from(choice) % provider.cipher_suites.len()]
    else {
        return;
    };
    let (secret, rest) = rest.split_at(rest.len().min(20));
    let (number, rest) = match rest.split_first_chunk::<8>() {
        Some((number, rest)) => (u64::from_be_bytes(*number), rest),
        None => (0, rest),
    };
    match choice / 3 % 3 {
        0 => records(suite, secret, number, rest),
        1 => packets(suite, secret, number, rest),
        _ => {
            let exchange = provider.kx_groups[0]
                .start()
                .expect("a key exchange starts");
            let _ = exchange.complete(rest);
        }
    }
});
