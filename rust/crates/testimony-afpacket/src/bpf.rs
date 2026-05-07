//! Cross-platform BPF support: parser for `tcpdump -ddd` output.
//! Lives in its own module so its unit tests run on any host OS, not just
//! Linux.

use crate::{AfpacketError, SockFilter};

/// Parse the body of `tcpdump -ddd` output. Format:
/// first int N (number of instructions), followed by N rows of 4 ints
/// (code, jt, jf, k). All whitespace-separated; line breaks are not
/// significant.
///
/// Errors describe exactly what went wrong (which token failed to parse,
/// what length we expected vs. saw) so the operator can correlate the
/// daemon log against the literal `tcpdump` output.
pub fn parse_tcpdump_ddd_for(
    iface: &str,
    filter: &str,
    text: &str,
) -> Result<Vec<SockFilter>, AfpacketError> {
    let mut nums: Vec<i64> = Vec::new();
    for tok in text.split_ascii_whitespace() {
        match tok.parse::<i64>() {
            Ok(n) => nums.push(n),
            Err(e) => {
                return Err(AfpacketError::BpfCompile {
                    iface: iface.to_owned(),
                    filter: filter.to_owned(),
                    reason: format!("non-numeric token {tok:?} in tcpdump output: {e}"),
                });
            }
        }
    }
    let Some(&count_signed) = nums.first() else {
        return Err(AfpacketError::BpfCompile {
            iface: iface.to_owned(),
            filter: filter.to_owned(),
            reason: "tcpdump -ddd produced empty output".into(),
        });
    };
    if count_signed < 0 {
        return Err(AfpacketError::BpfCompile {
            iface: iface.to_owned(),
            filter: filter.to_owned(),
            reason: format!("tcpdump -ddd reported negative instruction count {count_signed}"),
        });
    }
    let count = count_signed as usize;
    let Some(expected_len) = count.checked_mul(4).and_then(|x| x.checked_add(1)) else {
        return Err(AfpacketError::BpfCompile {
            iface: iface.to_owned(),
            filter: filter.to_owned(),
            reason: format!("tcpdump -ddd: header count {count} too large to validate"),
        });
    };
    if nums.len() != expected_len {
        return Err(AfpacketError::BpfCompile {
            iface: iface.to_owned(),
            filter: filter.to_owned(),
            reason: format!(
                "tcpdump -ddd: expected {expected_len} ints (header {count} * 4 + 1), got {}",
                nums.len()
            ),
        });
    }
    let mut bpfs: Vec<SockFilter> = Vec::with_capacity(count);
    // `chunks_exact(4)` gives us exactly four ints per BPF instruction.
    // The header check above guarantees the body length is a multiple of 4.
    let body = match nums.get(1..) {
        Some(b) => b,
        None => &[],
    };
    for chunk in body.chunks_exact(4) {
        // Slice patterns make the bounds explicit to the compiler — no
        // implicit indexing-and-panic.
        let &[code, jt, jf, k] = chunk else {
            // chunks_exact guarantees exactly 4. If the destructure ever
            // fails we have a logic bug in std, which would be a real
            // panic-vector. Surface it as a structured error so the
            // daemon doesn't crash.
            return Err(AfpacketError::BpfCompile {
                iface: iface.to_owned(),
                filter: filter.to_owned(),
                reason: "internal: chunks_exact(4) produced wrong-sized chunk".into(),
            });
        };
        bpfs.push(SockFilter {
            code: code as u16,
            jt: jt as u8,
            jf: jf as u8,
            k: k as u32,
        });
    }
    Ok(bpfs)
}

/// Backwards-compatible wrapper for callers that don't have iface/filter
/// context handy (e.g. unit tests). Errors lose some context.
pub fn parse_tcpdump_ddd(text: &str) -> Result<Vec<SockFilter>, AfpacketError> {
    parse_tcpdump_ddd_for("<unknown>", "<unknown>", text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> Vec<SockFilter> {
        match parse_tcpdump_ddd(input) {
            Ok(v) => v,
            Err(e) => panic!("parse failed: {e}"),
        }
    }

    #[test]
    fn parse_empty_filter() {
        let bpfs = ok("0\n");
        assert_eq!(bpfs.len(), 0);
    }

    #[test]
    fn parse_two_instructions() {
        let bpfs = ok("2\n6 0 0 65535\n6 0 0 0\n");
        assert_eq!(bpfs.len(), 2);
        assert_eq!(bpfs[0].code, 6);
        assert_eq!(bpfs[0].jt, 0);
        assert_eq!(bpfs[0].jf, 0);
        assert_eq!(bpfs[0].k, 65535);
        assert_eq!(bpfs[1].k, 0);
    }

    /// Simulates a real `tcpdump -ddd "host 169.254.1.1 and host 169.254.1.2"`
    /// transcript shape — many lines of 4 ints each.
    #[test]
    fn parse_realistic_filter() {
        let input = "\
            12\n\
            40 0 0 12\n\
            21 0 8 2048\n\
            32 0 0 26\n\
            21 0 2 -1442840319\n\
            32 0 0 30\n\
            21 6 7 -1442840318\n\
            32 0 0 26\n\
            21 0 5 -1442840318\n\
            32 0 0 30\n\
            21 2 3 -1442840319\n\
            6 0 0 65535\n\
            6 0 0 0\n";
        let bpfs = ok(input);
        assert_eq!(bpfs.len(), 12);
        assert_eq!(bpfs[11].code, 6);
        assert_eq!(bpfs[11].k, 0);
        // -1442840319 as i32 → as u32 = 0xA9FE0101 (169.254.1.1).
        assert_eq!(bpfs[3].k, (-1442840319i64) as u32);
    }

    #[test]
    fn parse_empty_input_errors() {
        assert!(parse_tcpdump_ddd("").is_err());
        assert!(parse_tcpdump_ddd("   ").is_err());
    }

    #[test]
    fn parse_negative_count_errors() {
        assert!(parse_tcpdump_ddd("-1\n").is_err());
    }

    #[test]
    fn parse_wrong_length_errors() {
        assert!(parse_tcpdump_ddd("1\n6 0 0").is_err());
        assert!(parse_tcpdump_ddd("1\n6 0 0 0 0").is_err());
    }

    #[test]
    fn parse_non_numeric_errors() {
        let err = parse_tcpdump_ddd("not_a_number")
            .expect_err("non-numeric must error")
            .to_string();
        assert!(err.contains("non-numeric"), "expected 'non-numeric' in {err}");
    }

    /// Error messages should mention the iface and filter so operators
    /// can correlate logs to config.
    #[test]
    fn parse_error_carries_iface_and_filter() {
        let err = parse_tcpdump_ddd_for("eth0", "tcp port 80", "")
            .expect_err("empty must error");
        let msg = err.to_string();
        assert!(msg.contains("eth0"), "expected iface in {msg}");
        assert!(msg.contains("tcp port 80"), "expected filter in {msg}");
    }

    /// Newlines and tabs are valid whitespace separators (mirrors Go's
    /// `bufio.ScanWords`).
    #[test]
    fn parse_handles_mixed_whitespace() {
        let bpfs = ok("2\t6\t0\t0\t65535\n6\t0  0\t0");
        assert_eq!(bpfs.len(), 2);
    }

    /// Header value larger than fits multiplied by 4 + 1 in usize → error.
    /// On 64-bit usize this is unreachable in practice; we just exercise
    /// the safety guard.
    #[test]
    fn parse_oversized_header_count_errors() {
        // Choose a number large enough that count*4+1 still fits in i64 but
        // we still want to validate length math. With usize being at least
        // 32 bits, count = 1<<31 wouldn't fit count*4+1 in u32 — but this
        // is i64 internally so we'd just hit the "expected_len" mismatch.
        let huge = format!("{}\n", i64::MAX);
        assert!(parse_tcpdump_ddd(&huge).is_err());
    }

    /// Body len not divisible by 4 → caught by header validation.
    #[test]
    fn parse_unaligned_body_errors() {
        // header says 1 instruction, body has 5 ints — mismatch.
        let err = parse_tcpdump_ddd("1\n6 0 0 0 0").expect_err("len mismatch");
        let msg = err.to_string();
        assert!(msg.contains("expected"), "expected explanation in {msg}");
    }

    /// Negative ints in body are valid (tcpdump emits them for sign-extended
    /// constants). They should round-trip through i64→u32 cast intact —
    /// matches what the C/Go ports do for `bpfs[3].k` in
    /// `parse_realistic_filter`.
    #[test]
    fn parse_negative_constants_in_body() {
        let bpfs = ok("1\n21 0 2 -1442840319");
        assert_eq!(bpfs.len(), 1);
        // (-1442840319) as i64 as u32 wraps to 2852126977.
        assert_eq!(bpfs[0].k, (-1442840319i64) as u32);
    }

    /// A real `tcpdump -ddd "host 169.254.1.1"` would produce a non-zero
    /// instruction count whose final BPF op is the accept (k=65535) or
    /// reject (k=0) return. Confirm our parser preserves the program
    /// faithfully — the kernel cares about every byte.
    #[test]
    fn parse_preserves_program_bytes_exactly() {
        let input = "3\n40 0 0 12\n21 0 1 2048\n6 0 0 65535";
        let bpfs = ok(input);
        assert_eq!(bpfs.len(), 3);
        assert_eq!(bpfs[0].code, 40);
        assert_eq!(bpfs[0].k, 12);
        assert_eq!(bpfs[1].code, 21);
        assert_eq!(bpfs[1].jt, 0);
        assert_eq!(bpfs[1].jf, 1);
        assert_eq!(bpfs[1].k, 2048);
        assert_eq!(bpfs[2].code, 6);
        assert_eq!(bpfs[2].k, 65535);
    }
}
