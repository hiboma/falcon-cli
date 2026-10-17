/// Render untrusted text without emitting terminal or log control characters.
///
/// Printable characters are preserved. Control characters are represented as
/// visible Rust-style escapes so each logical value stays on one output line.
pub(crate) fn escape_control_chars(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for ch in value.chars() {
        match ch {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{{{:x}}}", c as u32);
            }
            c => escaped.push(c),
        }
    }

    escaped
}

/// Truncate a string by Unicode scalar values, never through a UTF-8 sequence.
pub(crate) fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_terminal_and_line_control_characters() {
        assert_eq!(
            escape_control_chars("ok\n\r\t\u{1b}]52;c;payload\u{7}"),
            "ok\\n\\r\\t\\u{1b}]52;c;payload\\u{7}"
        );
    }

    #[test]
    fn preserves_printable_unicode() {
        assert_eq!(escape_control_chars("Falcon 日本語"), "Falcon 日本語");
    }

    #[test]
    fn truncates_on_utf8_boundaries() {
        assert_eq!(truncate_chars(&"あ".repeat(100), 50), "あ".repeat(50));
    }
}
