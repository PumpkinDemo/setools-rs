//! Small dependency-free JSON encoding helpers for structured CLI output.

/// Appends one valid JSON string value.
pub(crate) fn push_string(output: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{001f}' => {
                let value = character as usize;
                output.push_str("\\u00");
                output.push(HEX[value >> 4] as char);
                output.push(HEX[value & 0x0f] as char);
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::push_string;

    #[test]
    fn escapes_json_strings_without_changing_unicode() {
        let mut output = String::new();
        push_string(
            &mut output,
            "quote=\" slash=\\\u{0008}\u{000c}\n\r\t\u{001f} 中文",
        );
        assert_eq!(
            output,
            "\"quote=\\\" slash=\\\\\\b\\f\\n\\r\\t\\u001f 中文\""
        );
    }
}
