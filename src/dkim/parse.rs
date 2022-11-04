use std::slice::Iter;

use mail_parser::decoders::base64::base64_decode_stream;
use rsa::RsaPublicKey;

use crate::common::parse::{ItemParser, TagParser};

use super::{
    Algorithm, Canonicalization, Error, Flag, HashAlgorithm, PublicKey, Record, Service, Signature,
    Version,
};

enum Key {
    V,
    A,
    B,
    BH,
    C,
    D,
    H,
    I,
    L,
    Q,
    S,
    T,
    X,
    Z,
    Unknown,
}

impl<'x> Signature<'x> {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse(header: &'_ [u8]) -> super::Result<Self> {
        let mut signature = Signature {
            v: 0,
            a: Algorithm::RsaSha256,
            d: (b""[..]).into(),
            s: (b""[..]).into(),
            i: (b""[..]).into(),
            b: Vec::with_capacity(0),
            bh: Vec::with_capacity(0),
            h: Vec::with_capacity(0),
            z: Vec::with_capacity(0),
            l: 0,
            x: 0,
            t: 0,
            ch: Canonicalization::Simple,
            cb: Canonicalization::Simple,
        };
        let header_len = header.len();
        let mut header = header.iter();

        while let Some(key) = Key::parse(&mut header) {
            match key {
                Key::V => {
                    while let Some(&ch) = header.next() {
                        match ch {
                            b'1' if signature.v == 0 => {
                                signature.v = 1;
                            }
                            b';' => {
                                break;
                            }
                            _ => {
                                if !ch.is_ascii_whitespace() {
                                    return Err(Error::UnsupportedVersion);
                                }
                            }
                        }
                    }
                    if signature.v != 1 {
                        return Err(Error::UnsupportedVersion);
                    }
                }
                Key::A => {
                    if let Some(ch) = header.next_skip_whitespaces() {
                        match ch {
                            b'r' | b'R' => {
                                if header.match_bytes(b"sa-sha") {
                                    let mut algo = 0;

                                    while let Some(ch) = header.next() {
                                        match ch {
                                            b'1' if algo == 0 => algo = 1,
                                            b'2' if algo == 0 => algo = 2,
                                            b'5' if algo == 2 => algo = 25,
                                            b'6' if algo == 25 => algo = 256,
                                            b';' => {
                                                break;
                                            }
                                            _ => {
                                                if !ch.is_ascii_whitespace() {
                                                    return Err(Error::UnsupportedAlgorithm);
                                                }
                                            }
                                        }
                                    }

                                    signature.a = match algo {
                                        256 => Algorithm::RsaSha256,
                                        1 => Algorithm::RsaSha1,
                                        _ => return Err(Error::UnsupportedAlgorithm),
                                    };
                                } else {
                                    return Err(Error::UnsupportedAlgorithm);
                                }
                            }
                            b'e' | b'E' => {
                                if header.match_bytes(b"d25519-sha256") && header.skip_whitespaces()
                                {
                                    signature.a = Algorithm::Ed25519Sha256;
                                } else {
                                    return Err(Error::UnsupportedAlgorithm);
                                }
                            }
                            b';' => (),
                            _ => {
                                return Err(Error::UnsupportedAlgorithm);
                            }
                        }
                    }
                }
                Key::B => {
                    signature.b =
                        base64_decode_stream(&mut header, header_len, b';').ok_or(Error::Base64)?
                }
                Key::BH => {
                    signature.bh =
                        base64_decode_stream(&mut header, header_len, b';').ok_or(Error::Base64)?
                }
                Key::C => {
                    let mut has_header = false;
                    let mut c = None;

                    while let Some(ch) = header.next() {
                        match (ch, c) {
                            (b's' | b'S', None) => {
                                if header.match_bytes(b"imple") {
                                    c = Canonicalization::Simple.into();
                                } else {
                                    return Err(Error::UnsupportedAlgorithm);
                                }
                            }
                            (b'r' | b'R', None) => {
                                if header.match_bytes(b"elaxed") {
                                    c = Canonicalization::Relaxed.into();
                                } else {
                                    return Err(Error::UnsupportedAlgorithm);
                                }
                            }
                            (b'/', Some(c_)) => {
                                signature.ch = c_;
                                c = None;
                                has_header = true;
                            }
                            (b';', _) => {
                                break;
                            }
                            (_, _) => {
                                if !ch.is_ascii_whitespace() {
                                    return Err(Error::UnsupportedCanonicalization);
                                }
                            }
                        }
                    }

                    if let Some(c) = c {
                        if has_header {
                            signature.cb = c;
                        } else {
                            signature.ch = c;
                        }
                    }
                }
                Key::D => signature.d = header.get_tag().into(),
                Key::H => signature.h = header.get_items(b':'),
                Key::I => signature.i = header.get_tag_qp().into(),
                Key::L => signature.l = header.get_number(),
                Key::S => signature.s = header.get_tag().into(),
                Key::T => signature.t = header.get_number(),
                Key::X => signature.x = header.get_number(),
                Key::Z => signature.z = header.get_headers_qp(),
                Key::Q | Key::Unknown => header.ignore(),
            }
        }

        if !signature.d.is_empty()
            && !signature.d.is_empty()
            && !signature.b.is_empty()
            && !signature.bh.is_empty()
            && !signature.h.is_empty()
        {
            Ok(signature)
        } else {
            Err(Error::MissingParameters)
        }
    }
}

impl Key {
    #[allow(clippy::while_let_on_iterator)]
    fn parse(header: &mut Iter<'_, u8>) -> Option<Self> {
        let mut key = Key::Unknown;

        while let Some(ch) = header.next() {
            key = match ch {
                b'v' | b'V' => Key::V,
                b'a' | b'A' => Key::A,
                b'b' | b'B' => Key::B,
                b'c' | b'C' => Key::C,
                b'd' | b'D' => Key::D,
                b'h' | b'H' => Key::H,
                b'i' | b'I' => Key::I,
                b'l' | b'L' => Key::L,
                b'q' | b'Q' => Key::Q,
                b's' | b'S' => Key::S,
                b't' | b'T' => Key::T,
                b'x' | b'X' => Key::X,
                b'z' | b'Z' => Key::Z,
                b' ' | b'\t' | b'\r' | b'\n' | b';' => continue,
                _ => Key::Unknown,
            };
            break;
        }

        while let Some(ch) = header.next() {
            match ch {
                b'=' => {
                    return key.into();
                }
                b' ' | b'\t' | b'\r' | b'\n' => (),
                b'h' | b'H' if matches!(key, Key::B) => {
                    key = Key::BH;
                }
                _ => {
                    key = Key::Unknown;
                }
            }
        }

        None
    }
}

enum KeyType {
    Rsa,
    Ed25519,
    None,
}

impl Record {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse(header: &[u8]) -> super::Result<Self> {
        let header_len = header.len();
        let mut header = header.iter();
        let mut key = 0;
        let mut record = Record {
            v: Version::Dkim1,
            h: Vec::new(),
            p: PublicKey::Revoked,
            s: Vec::new(),
            t: Vec::new(),
        };
        let mut k = KeyType::None;
        let mut public_key = Vec::new();

        while let Some(&ch) = header.next() {
            match ch {
                b' ' | b'\t' | b'\r' | b'\n' => (),
                b'=' => {
                    match key {
                        b'v' | b'V' => {
                            if !header.match_bytes(b"DKIM1") || !header.skip_whitespaces() {
                                return Err(Error::UnsupportedRecordVersion);
                            }
                        }
                        b'h' | b'H' => record.h = header.get_items(b':'),
                        b'p' | b'P' => {
                            public_key = base64_decode_stream(&mut header, header_len, b';')
                                .unwrap_or_default()
                        }
                        b's' | b'S' => record.s = header.get_items(b':'),
                        b't' | b'T' => record.t = header.get_items(b':'),
                        b'k' | b'K' => {
                            if let Some(ch) = header.next_skip_whitespaces() {
                                match ch {
                                    b'r' | b'R' => {
                                        if header.match_bytes(b"sa") && header.skip_whitespaces() {
                                            k = KeyType::Rsa;
                                        } else {
                                            return Err(Error::UnsupportedKeyType);
                                        }
                                    }
                                    b'e' | b'E' => {
                                        if header.match_bytes(b"d25519")
                                            && header.skip_whitespaces()
                                        {
                                            k = KeyType::Ed25519;
                                        } else {
                                            return Err(Error::UnsupportedKeyType);
                                        }
                                    }
                                    b';' => (),
                                    _ => {
                                        return Err(Error::UnsupportedKeyType);
                                    }
                                }
                            }
                        }
                        _ => {
                            header.ignore();
                        }
                    }
                    key = 0;
                }
                b';' => {
                    key = 0;
                }
                _ => {
                    if key == 0 {
                        key = ch;
                    } else {
                        key = u8::MAX;
                    }
                }
            }
        }

        if !public_key.is_empty() {
            record.p = match k {
                KeyType::Rsa | KeyType::None => PublicKey::Rsa(
                    <RsaPublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(&public_key)
                        .or_else(|_| rsa::pkcs1::DecodeRsaPublicKey::from_pkcs1_der(&public_key))
                        .map_err(Error::PKCS)?,
                ),
                KeyType::Ed25519 => PublicKey::Ed25519(
                    ed25519_dalek::PublicKey::from_bytes(&public_key)
                        .map_err(Error::Ed25519Signature)?,
                ),
            }
        }

        Ok(record)
    }
}

impl ItemParser for HashAlgorithm {
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.eq_ignore_ascii_case(b"sha256") {
            HashAlgorithm::Sha256.into()
        } else if bytes.eq_ignore_ascii_case(b"sha1") {
            HashAlgorithm::Sha1.into()
        } else {
            None
        }
    }
}

impl ItemParser for Flag {
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.eq_ignore_ascii_case(b"y") {
            Flag::Testing.into()
        } else if bytes.eq_ignore_ascii_case(b"s") {
            Flag::MatchDomain.into()
        } else {
            None
        }
    }
}

impl ItemParser for Service {
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.eq(b"*") {
            Service::All.into()
        } else if bytes.eq_ignore_ascii_case(b"email") {
            Service::Email.into()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use mail_parser::decoders::base64::base64_decode;
    use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};

    use crate::dkim::{
        Algorithm, Canonicalization, Flag, HashAlgorithm, PublicKey, Record, Service, Signature,
        Version,
    };

    #[test]
    fn dkim_signature_parse() {
        for (signature, expected_result) in [
            (
                concat!(
                    "v=1; a=rsa-sha256; s=default; d=stalw.art; c=relaxed/relaxed; ",
                    "bh=QoiUNYyUV+1tZ/xUPRcE+gST2zAStvJx1OK078Ylm5s=; ",
                    "b=Du0rvdzNodI6b5bhlUaZZ+gpXJi0VwjY/3qL7lS0wzKutNVCbvdJuZObGdAcv\n",
                    " eVI/RNQh2gxW4H2ynMS3B+Unse1YLJQwdjuGxsCEKBqReKlsEKT8JlO/7b2AvxR\n",
                    "\t9Q+M2aHD5kn9dbNIKnN/PKouutaXmm18QwL5EPEN9DHXSqQ=;",
                    "h=Subject:To:From; t=311923920",
                ),
                Signature {
                    v: 1,
                    a: Algorithm::RsaSha256,
                    d: (b"stalw.art"[..]).into(),
                    s: (b"default"[..]).into(),
                    i: (b""[..]).into(),
                    bh: base64_decode(b"QoiUNYyUV+1tZ/xUPRcE+gST2zAStvJx1OK078Ylm5s=").unwrap(),
                    b: base64_decode(
                        concat!(
                            "Du0rvdzNodI6b5bhlUaZZ+gpXJi0VwjY/3qL7lS0wzKutNVCbvdJuZObGdAcv",
                            "eVI/RNQh2gxW4H2ynMS3B+Unse1YLJQwdjuGxsCEKBqReKlsEKT8JlO/7b2AvxR",
                            "9Q+M2aHD5kn9dbNIKnN/PKouutaXmm18QwL5EPEN9DHXSqQ="
                        )
                        .as_bytes(),
                    )
                    .unwrap(),
                    h: vec![b"Subject".to_vec(), b"To".to_vec(), b"From".to_vec()],
                    z: vec![],
                    l: 0,
                    x: 0,
                    t: 311923920,
                    ch: Canonicalization::Relaxed,
                    cb: Canonicalization::Relaxed,
                },
            ),
            (
                concat!(
                    "v=1; a=rsa-sha1; d=example.net; s=brisbane;\r\n",
                    " c=simple; q=dns/txt; i=@eng.example.net;\r\n",
                    " t=1117574938; x=1118006938;\r\n",
                    " h=from:to:subject:date;\r\n",
                    " z=From:foo@eng.example.net|To:joe@example.com|\r\n",
                    " Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;\r\n",
                    " bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;\r\n",
                    " b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR",
                ),
                Signature {
                    v: 1,
                    a: Algorithm::RsaSha1,
                    d: (b"example.net"[..]).into(),
                    s: (b"brisbane"[..]).into(),
                    i: (b"@eng.example.net"[..]).into(),
                    bh: base64_decode(b"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=").unwrap(),
                    b: base64_decode(
                        concat!(
                            "dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGe",
                            "eruD00lszZVoG4ZHRNiYzR"
                        )
                        .as_bytes(),
                    )
                    .unwrap(),
                    h: vec![
                        b"from".to_vec(),
                        b"to".to_vec(),
                        b"subject".to_vec(),
                        b"date".to_vec(),
                    ],
                    z: vec![
                        b"From:foo@eng.example.net".to_vec(),
                        b"To:joe@example.com".to_vec(),
                        b"Subject:demo run".to_vec(),
                        b"Date:July 5, 2005 3:44:08 PM -0700".to_vec(),
                    ],
                    l: 0,
                    x: 1118006938,
                    t: 1117574938,
                    ch: Canonicalization::Simple,
                    cb: Canonicalization::Simple,
                },
            ),
            (
                concat!(
                    "v=1; a = rsa - sha256; s = brisbane; d = example.com;  \r\n",
                    "c = simple / relaxed; q=dns/txt; i = \r\n joe=20@\r\n",
                    " football.example.com; \r\n",
                    "h=Received : From : To :\r\n Subject : : Date : Message-ID::;;;; \r\n",
                    "bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; \r\n",
                    "b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB \r\n",
                    "4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut \r\n",
                    "KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV \r\n",
                    "4bmp/YzhwvcubU4=; l = 123",
                ),
                Signature {
                    v: 1,
                    a: Algorithm::RsaSha256,
                    d: (b"example.com"[..]).into(),
                    s: (b"brisbane"[..]).into(),
                    i: (b"joe @football.example.com"[..]).into(),
                    bh: base64_decode(b"2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=").unwrap(),
                    b: base64_decode(
                        concat!(
                            "AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB",
                            "4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut",
                            "KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV",
                            "4bmp/YzhwvcubU4="
                        )
                        .as_bytes(),
                    )
                    .unwrap(),
                    h: vec![
                        b"Received".to_vec(),
                        b"From".to_vec(),
                        b"To".to_vec(),
                        b"Subject".to_vec(),
                        b"Date".to_vec(),
                        b"Message-ID".to_vec(),
                    ],
                    z: vec![],
                    l: 123,
                    x: 0,
                    t: 0,
                    ch: Canonicalization::Simple,
                    cb: Canonicalization::Relaxed,
                },
            ),
        ] {
            let result = Signature::parse(signature.as_bytes()).unwrap();
            assert_eq!(result.v, expected_result.v, "{:?}", signature);
            assert_eq!(result.a, expected_result.a, "{:?}", signature);
            assert_eq!(result.d, expected_result.d, "{:?}", signature);
            assert_eq!(result.s, expected_result.s, "{:?}", signature);
            assert_eq!(result.i, expected_result.i, "{:?}", signature);
            assert_eq!(result.b, expected_result.b, "{:?}", signature);
            assert_eq!(result.bh, expected_result.bh, "{:?}", signature);
            assert_eq!(result.h, expected_result.h, "{:?}", signature);
            assert_eq!(result.z, expected_result.z, "{:?}", signature);
            assert_eq!(result.l, expected_result.l, "{:?}", signature);
            assert_eq!(result.x, expected_result.x, "{:?}", signature);
            assert_eq!(result.t, expected_result.t, "{:?}", signature);
            assert_eq!(result.ch, expected_result.ch, "{:?}", signature);
            assert_eq!(result.cb, expected_result.cb, "{:?}", signature);
        }
    }

    #[test]
    fn dkim_record_parse() {
        for (record, expected_result) in [
            (
                concat!(
                    "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ",
                    "KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt",
                    "IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v",
                    "/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi",
                    "tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB",
                ),
                Record {
                    v: Version::Dkim1,
                    h: Vec::new(),
                    p: PublicKey::Rsa(
                        RsaPublicKey::from_public_key_der(
                            &base64_decode(
                                concat!(
                                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ",
                                    "KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt",
                                    "IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v",
                                    "/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi",
                                    "tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB",
                                )
                                .as_bytes(),
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    ),
                    s: Vec::new(),
                    t: Vec::new(),
                },
            ),
            (
                concat!(
                    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOC",
                    "AQ8AMIIBCgKCAQEAvzwKQIIWzQXv0nihasFTT3+JO23hXCg",
                    "e+ESWNxCJdVLxKL5edxrumEU3DnrPeGD6q6E/vjoXwBabpm",
                    "8F5o96MEPm7v12O5IIK7wx7gIJiQWvexwh+GJvW4aFFa0g1",
                    "3Ai75UdZjGFNKHAEGeLmkQYybK/EHW5ymRlSg3g8zydJGEc",
                    "I/melLCiBoShHjfZFJEThxLmPHNSi+KOUMypxqYHd7hzg6W",
                    "7qnq6t9puZYXMWj6tEaf6ORWgb7DOXZSTJJjAJPBWa2+Urx",
                    "XX6Ro7L7Xy1zzeYFCk8W5vmn0wMgGpjkWw0ljJWNwIpxZAj9",
                    "p5wMedWasaPS74TZ1b7tI39ncp6QIDAQAB ; t= y : s :yy:x;",
                    "s=*:email;; h= sha1:sha 256:other;; n=ignore these notes "
                ),
                Record {
                    v: Version::Dkim1,
                    h: vec![HashAlgorithm::Sha1, HashAlgorithm::Sha256],
                    p: PublicKey::Rsa(
                        RsaPublicKey::from_public_key_der(
                            &base64_decode(
                                concat!(
                                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvz",
                                    "wKQIIWzQXv0nihasFTT3+JO23hXCge+ESWNxCJdVLxKL5e",
                                    "dxrumEU3DnrPeGD6q6E/vjoXwBabpm8F5o96MEPm7v12O5",
                                    "IIK7wx7gIJiQWvexwh+GJvW4aFFa0g13Ai75UdZjGFNKHA",
                                    "EGeLmkQYybK/EHW5ymRlSg3g8zydJGEcI/melLCiBoShHjf",
                                    "ZFJEThxLmPHNSi+KOUMypxqYHd7hzg6W7qnq6t9puZYXMWj",
                                    "6tEaf6ORWgb7DOXZSTJJjAJPBWa2+UrxXX6Ro7L7Xy1zzeY",
                                    "FCk8W5vmn0wMgGpjkWw0ljJWNwIpxZAj9p5wMedWasaPS74",
                                    "TZ1b7tI39ncp6QIDAQAB",
                                )
                                .as_bytes(),
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    ),
                    s: vec![Service::All, Service::Email],
                    t: vec![Flag::Testing, Flag::MatchDomain],
                },
            ),
            (
                concat!(
                    "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYtb/9Sh8nGKV7exhUFS",
                    "+cBNXlHgO1CxD9zIfQd5ztlq1LO7g38dfmFpQafh9lKgqPBTolFhZxhF1yUNT",
                    "hpV673NdAtaCVGNyx/fTYtvyyFe9DH2tmm/ijLlygDRboSkIJ4NHZjK++48hk",
                    "NP8/htqWHS+CvwWT4Qgs0NtB7Re9bQIDAQAB"
                ),
                Record {
                    v: Version::Dkim1,
                    h: vec![],
                    p: PublicKey::Rsa(
                        RsaPublicKey::from_public_key_der(
                            &base64_decode(
                                concat!(
                                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYtb/9Sh8nGKV7exhUFS",
                                    "+cBNXlHgO1CxD9zIfQd5ztlq1LO7g38dfmFpQafh9lKgqPBTolFhZxhF1yUNT",
                                    "hpV673NdAtaCVGNyx/fTYtvyyFe9DH2tmm/ijLlygDRboSkIJ4NHZjK++48hk",
                                    "NP8/htqWHS+CvwWT4Qgs0NtB7Re9bQIDAQAB"
                                )
                                .as_bytes(),
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    ),
                    s: vec![],
                    t: vec![],
                },
            ),
        ] {
            assert_eq!(Record::parse(record.as_bytes()).unwrap(), expected_result);
        }
    }
}