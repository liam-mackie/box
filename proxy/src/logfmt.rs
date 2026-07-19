use std::time::{SystemTime, UNIX_EPOCH};

pub const NO_FLAGS: &str = "-";
pub const NO_SNI: &str = "-";

pub fn epoch_secs_millis(time: SystemTime) -> (u64, u32) {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs(), d.subsec_millis()),
        Err(_) => (0, 0),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn access_line(
    time: SystemTime,
    client_ip: &str,
    flags: &str,
    status: u16,
    bytes: u64,
    method: &str,
    url: &str,
    sni: &str,
) -> String {
    let (secs, millis) = epoch_secs_millis(time);
    format!(
        "{}.{:03} {} {}/{} {} {} {} {}",
        secs, millis, client_ip, flags, status, bytes, method, url, sni
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64, millis: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(secs * 1000 + millis)
    }

    #[test]
    fn has_seven_whitespace_fields() {
        let line = access_line(at(1_592_000_000, 123), "10.0.0.5", NO_FLAGS, 200, 42, "GET", "https://pypi.org/simple/", NO_SNI);
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields.len(), 7, "line was: {line}");
    }

    #[test]
    fn field_positions_match_box_parser() {
        let line = access_line(at(1_592_000_000, 5), "10.0.0.5", NO_FLAGS, 403, 0, "CONNECT", "evil.test:443", NO_SNI);
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(f[0], "1592000000.005");
        assert_eq!(f[1], "10.0.0.5");
        assert_eq!(f[2], "-/403");
        assert_eq!(f[3], "0");
        assert_eq!(f[4], "CONNECT");
        assert_eq!(f[5], "evil.test:443");
        assert_eq!(f[6], "-");
    }

    #[test]
    fn code_status_token_is_findable_after_client() {
        let line = access_line(at(1_600_000_000, 0), "192.168.64.7", NO_FLAGS, 200, 1024, "POST", "https://api.example.com/v1", NO_SNI);
        let f: Vec<&str> = line.split(' ').collect();
        let cs_index = f.iter().skip(1).position(|t| is_code_status(t)).map(|p| p + 1);
        assert_eq!(cs_index, Some(2));
        assert_eq!(f[cs_index.unwrap() - 1], "192.168.64.7");
    }

    #[test]
    fn millis_are_zero_padded() {
        let line = access_line(at(1_592_000_000, 7), "1.2.3.4", NO_FLAGS, 200, 0, "GET", "http://x/", NO_SNI);
        assert!(line.starts_with("1592000000.007 "), "line was: {line}");
    }

    fn is_code_status(field: &str) -> bool {
        let Some((code, status)) = field.split_once('/') else {
            return false;
        };
        if code.is_empty() || status.is_empty() || status.parse::<u32>().is_err() {
            return false;
        }
        code.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_' || c == ',' || c == '-')
    }
}
