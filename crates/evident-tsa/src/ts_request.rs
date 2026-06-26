//! Manual DER encoder for RFC 3161 TimeStampReq (no ASN.1 crates).

/// SHA-256 AlgorithmIdentifier: SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }
const SHA256_ALGORITHM_IDENTIFIER: [u8; 15] = [
    0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
];

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(tag);
    out.extend(der_length(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    der_tlv(0x30, content)
}

fn der_integer_v1() -> Vec<u8> {
    der_tlv(0x02, &[0x01])
}

fn der_boolean_true() -> Vec<u8> {
    der_tlv(0x01, &[0xff])
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    der_tlv(0x04, data)
}

fn build_message_imprint(hash: &[u8; 32]) -> Vec<u8> {
    let mut content = Vec::with_capacity(SHA256_ALGORITHM_IDENTIFIER.len() + 34);
    content.extend_from_slice(&SHA256_ALGORITHM_IDENTIFIER);
    content.extend(der_octet_string(hash));
    der_sequence(&content)
}

/// Build RFC 3161 TimeStampReq DER bytes.
///
/// Structure:
/// ```text
/// SEQUENCE {
///   version INTEGER 1,
///   messageImprint SEQUENCE { sha256 AlgorithmIdentifier, hashedMessage OCTET STRING },
///   certReq BOOLEAN TRUE
/// }
/// ```
///
/// No nonce or extensions (v0.2 contract).
pub fn build_ts_request(hash: &[u8; 32]) -> Vec<u8> {
    let message_imprint = build_message_imprint(hash);
    let mut content = Vec::with_capacity(3 + message_imprint.len() + 3);
    content.extend(der_integer_v1());
    content.extend(message_imprint);
    content.extend(der_boolean_true());
    der_sequence(&content)
}

#[cfg(test)]
mod tests {
    use super::build_ts_request;

    #[test]
    fn builds_expected_der_for_zero_hash() {
        let hash = [0u8; 32];
        let req = build_ts_request(&hash);

        let expected = concat!(
            "3039",             // SEQUENCE len 57
            "020101",           // INTEGER 1
            "3031",             // messageImprint len 49
            "300d06096086480165030402010500", // sha256 + NULL
            "0420",             // OCTET STRING len 32
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0101ff"            // certReq TRUE
        );

        let expected_bytes: Vec<u8> = (0..expected.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&expected[i..i + 2], 16).unwrap())
            .collect();

        assert_eq!(req, expected_bytes);
        assert_eq!(req.len(), 59);
    }

    #[test]
    fn starts_with_timestamp_req_sequence() {
        let hash = [0xab; 32];
        let req = build_ts_request(&hash);
        assert_eq!(req[0], 0x30);
        assert_eq!(req[1], 0x39);
        assert_eq!(&req[req.len() - 3..], &[0x01, 0x01, 0xff]);
    }
}
