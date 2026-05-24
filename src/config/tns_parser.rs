//! TNS descriptor parser
//!
//! Parses Oracle TNS connect descriptors:
//! `(DESCRIPTION=(ADDRESS=(PROTOCOL=tcp)(HOST=host)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=svc)))`
//!
//! Uses character-level recursive descent to parse the S-expression-like format.

use crate::config::ServiceMethod;

/// A parsed TNS address entry
#[derive(Debug, Clone, PartialEq)]
pub struct TnsAddress {
    pub protocol: String,
    pub host: String,
    pub port: u16,
}

/// A parsed TNS connect descriptor
#[derive(Debug, Clone)]
pub struct TnsDescriptor {
    pub addresses: Vec<TnsAddress>,
    pub connect_data: TnsConnectData,
    pub failover: bool,
    pub load_balance: bool,
}

/// Parsed CONNECT_DATA section
#[derive(Debug, Clone)]
pub struct TnsConnectData {
    pub service: ServiceMethod,
    #[allow(dead_code)]
    pub instance_name: Option<String>,
    #[allow(dead_code)]
    pub server: Option<String>,
}

/// Parse a TNS descriptor string. Returns `None` if the input doesn't look like
/// a TNS descriptor (doesn't start with '(').
pub fn parse_descriptor(input: &str) -> Option<TnsDescriptor> {
    let input = input.trim();
    if !input.starts_with('(') {
        return None;
    }

    let chars: Vec<char> = input.chars().collect();
    let mut pos = 0;
    let sections = parse_section(&chars, &mut pos)?;
    build_descriptor(&sections)
}

/// A key-value pair or named sub-section from the descriptor
#[derive(Debug)]
enum Section {
    KeyValue(String, String),
    Named(String, Vec<Section>),
}

/// Parse one S-expression section: `(KEY1=val1)(KEY2=val2)...` or
/// `(NAME=(key1=val1)(key2=val2))`.
///
/// Returns all key-value pairs and named sub-sections until the matching `)`.
fn parse_section(chars: &[char], pos: &mut usize) -> Option<Vec<Section>> {
    // Expect opening '('
    skip_ws(chars, pos);
    if *pos >= chars.len() || chars[*pos] != '(' {
        return None;
    }
    *pos += 1;

    let mut sections = Vec::new();

    loop {
        skip_ws(chars, pos);
        if *pos >= chars.len() {
            break;
        }
        if chars[*pos] == ')' {
            *pos += 1;
            break;
        }
        if chars[*pos] == '(' {
            // Nested section
            if let Some(nested) = parse_section(chars, pos) {
                sections.extend(nested);
            }
            continue;
        }
        // Read a key or name
        let name = read_identifier(chars, pos);
        if name.is_empty() {
            break;
        }

        skip_ws(chars, pos);
        if *pos < chars.len() && chars[*pos] == '=' {
            *pos += 1; // skip '='
            skip_ws(chars, pos);

            if *pos < chars.len() && chars[*pos] == '(' {
                // Named sub-section: NAME=(...)
                // Collect all child sections until the matching ')'
                let mut child_sections = Vec::new();
                while *pos < chars.len() && chars[*pos] == '(' {
                    if let Some(nested) = parse_section(chars, pos) {
                        child_sections.extend(nested);
                    }
                }
                // Consume the closing ')' if present
                skip_ws(chars, pos);
                if *pos < chars.len() && chars[*pos] == ')' {
                    *pos += 1;
                }
                sections.push(Section::Named(name.to_uppercase(), child_sections));
            } else {
                // Simple key=value
                let value = read_value(chars, pos);
                sections.push(Section::KeyValue(name.to_uppercase(), value));
            }
        } else {
            // Standalone name (no '=') followed by '(' — treat as named section
            skip_ws(chars, pos);
            if *pos < chars.len() && chars[*pos] == '(' {
                let mut child_sections = Vec::new();
                while *pos < chars.len() && chars[*pos] == '(' {
                    if let Some(nested) = parse_section(chars, pos) {
                        child_sections.extend(nested);
                    }
                }
                skip_ws(chars, pos);
                if *pos < chars.len() && chars[*pos] == ')' {
                    *pos += 1;
                }
                sections.push(Section::Named(name.to_uppercase(), child_sections));
            }
            // If not followed by '(', it's just a standalone value — skip
        }
    }

    Some(sections)
}

fn build_descriptor(sections: &[Section]) -> Option<TnsDescriptor> {
    let mut addresses = Vec::new();
    let mut connect_data_entries: Option<&[Section]> = None;
    let mut failover = false;
    let mut load_balance = false;

    for section in sections {
        match section {
            Section::KeyValue(key, val) => match key.as_str() {
                "FAILOVER" => {
                    failover = val.eq_ignore_ascii_case("on")
                        || val.eq_ignore_ascii_case("yes")
                        || val == "true";
                }
                "LOAD_BALANCE" => {
                    load_balance = val.eq_ignore_ascii_case("on")
                        || val.eq_ignore_ascii_case("yes")
                        || val == "true";
                }
                _ => {}
            },
            Section::Named(name, nested) => {
                match name.as_str() {
                    "DESCRIPTION" => {
                        // Recurse into DESCRIPTION
                        if let Some(desc) = build_descriptor(nested) {
                            addresses.extend(desc.addresses);
                            failover = desc.failover || failover;
                            load_balance = desc.load_balance || load_balance;
                            if connect_data_entries.is_none() {
                                return Some(TnsDescriptor {
                                    addresses,
                                    connect_data: desc.connect_data,
                                    failover,
                                    load_balance,
                                });
                            }
                        }
                    }
                    "ADDRESS" => {
                        if let Some(addr) = parse_address(nested) {
                            addresses.push(addr);
                        }
                    }
                    "ADDRESS_LIST" => {
                        for entry in nested {
                            match entry {
                                Section::Named(addr_name, addr_nested)
                                    if addr_name == "ADDRESS" =>
                                {
                                    if let Some(addr) = parse_address(addr_nested) {
                                        addresses.push(addr);
                                    }
                                }
                                Section::KeyValue(key, val) => match key.as_str() {
                                    "FAILOVER" => {
                                        failover = val.eq_ignore_ascii_case("on")
                                            || val.eq_ignore_ascii_case("yes")
                                            || val == "true";
                                    }
                                    "LOAD_BALANCE" => {
                                        load_balance = val.eq_ignore_ascii_case("on")
                                            || val.eq_ignore_ascii_case("yes")
                                            || val == "true";
                                    }
                                    _ => {}
                                },
                                _ => {}
                            }
                        }
                    }
                    "CONNECT_DATA" => {
                        connect_data_entries = Some(nested);
                    }
                    _ => {}
                }
            }
        }
    }

    let connect_data = parse_connect_data(connect_data_entries.unwrap_or(&[]));

    Some(TnsDescriptor {
        addresses,
        connect_data,
        failover,
        load_balance,
    })
}

fn parse_address(sections: &[Section]) -> Option<TnsAddress> {
    let mut protocol = String::from("tcp");
    let mut host = String::new();
    let mut port: u16 = 1521;

    for section in sections {
        match section {
            Section::KeyValue(key, val) => match key.as_str() {
                "PROTOCOL" => protocol = val.to_lowercase(),
                "HOST" => host = val.clone(),
                "PORT" => {
                    if let Ok(p) = val.parse() {
                        port = p;
                    }
                }
                _ => {}
            },
            Section::Named(name, nested) if name == "ADDRESS" => {
                if let Some(addr) = parse_address(nested) {
                    return Some(addr);
                }
            }
            _ => {}
        }
    }

    if host.is_empty() {
        None
    } else {
        Some(TnsAddress {
            protocol,
            host,
            port,
        })
    }
}

fn parse_connect_data(sections: &[Section]) -> TnsConnectData {
    let mut service = ServiceMethod::ServiceName(String::new());
    let mut instance_name = None;
    let mut server = None;

    for section in sections {
        if let Section::KeyValue(key, val) = section {
            match key.as_str() {
                "SERVICE_NAME" => service = ServiceMethod::ServiceName(val.clone()),
                "SID" => service = ServiceMethod::Sid(val.clone()),
                "INSTANCE_NAME" => instance_name = Some(val.clone()),
                "SERVER" => server = Some(val.clone()),
                _ => {}
            }
        }
    }

    TnsConnectData {
        service,
        instance_name,
        server,
    }
}

fn skip_ws(chars: &[char], pos: &mut usize) {
    while *pos < chars.len() && chars[*pos].is_whitespace() {
        *pos += 1;
    }
}

fn read_identifier(chars: &[char], pos: &mut usize) -> String {
    let mut s = String::new();
    while *pos < chars.len()
        && (chars[*pos].is_alphanumeric()
            || chars[*pos] == '_'
            || chars[*pos] == '.'
            || chars[*pos] == '-'
            || chars[*pos] == '#')
    {
        s.push(chars[*pos]);
        *pos += 1;
    }
    s
}

fn read_value(chars: &[char], pos: &mut usize) -> String {
    skip_ws(chars, pos);
    if *pos < chars.len() && (chars[*pos] == '"' || chars[*pos] == '\'') {
        let quote = chars[*pos];
        *pos += 1;
        let mut s = String::new();
        while *pos < chars.len() && chars[*pos] != quote {
            if chars[*pos] == '\\' && *pos + 1 < chars.len() {
                *pos += 1;
            }
            s.push(chars[*pos]);
            *pos += 1;
        }
        if *pos < chars.len() {
            *pos += 1; // skip closing quote
        }
        s
    } else {
        let mut s = String::new();
        while *pos < chars.len()
            && !chars[*pos].is_whitespace()
            && chars[*pos] != ')'
            && chars[*pos] != '('
        {
            s.push(chars[*pos]);
            *pos += 1;
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_descriptor() {
        let input = "(DESCRIPTION=(ADDRESS=(PROTOCOL=tcp)(HOST=myhost)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=orcl)))";
        let desc = parse_descriptor(input).unwrap();
        assert_eq!(desc.addresses.len(), 1);
        assert_eq!(desc.addresses[0].host, "myhost");
        assert_eq!(desc.addresses[0].port, 1521);
        assert_eq!(desc.addresses[0].protocol, "tcp");
        match &desc.connect_data.service {
            ServiceMethod::ServiceName(s) => assert_eq!(s, "orcl"),
            _ => panic!("expected ServiceName"),
        }
    }

    #[test]
    fn test_parse_with_sid() {
        let input = "(DESCRIPTION=(ADDRESS=(PROTOCOL=tcp)(HOST=dbhost)(PORT=1525))(CONNECT_DATA=(SID=mydb)))";
        let desc = parse_descriptor(input).unwrap();
        assert_eq!(desc.addresses[0].host, "dbhost");
        assert_eq!(desc.addresses[0].port, 1525);
        match &desc.connect_data.service {
            ServiceMethod::Sid(s) => assert_eq!(s, "mydb"),
            _ => panic!("expected SID"),
        }
    }

    #[test]
    fn test_parse_address_list() {
        let input = "(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=tcp)(HOST=host1)(PORT=1521))(ADDRESS=(PROTOCOL=tcp)(HOST=host2)(PORT=1522)))(CONNECT_DATA=(SERVICE_NAME=orcl)))";
        let desc = parse_descriptor(input).unwrap();
        assert_eq!(desc.addresses.len(), 2);
        assert_eq!(desc.addresses[0].host, "host1");
        assert_eq!(desc.addresses[1].host, "host2");
    }

    #[test]
    fn test_parse_failover() {
        let input = "(DESCRIPTION=(FAILOVER=on)(ADDRESS=(PROTOCOL=tcp)(HOST=host1)(PORT=1521))(ADDRESS=(PROTOCOL=tcp)(HOST=host2)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=orcl)))";
        let desc = parse_descriptor(input).unwrap();
        assert!(desc.failover);
    }

    #[test]
    fn test_parse_with_instance_name() {
        let input = "(DESCRIPTION=(ADDRESS=(PROTOCOL=tcp)(HOST=host)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=orcl)(INSTANCE_NAME=orcl1)(SERVER=DEDICATED)))";
        let desc = parse_descriptor(input).unwrap();
        assert_eq!(desc.connect_data.instance_name.as_deref(), Some("orcl1"));
        assert_eq!(desc.connect_data.server.as_deref(), Some("DEDICATED"));
    }

    #[test]
    fn test_not_a_descriptor() {
        assert!(parse_descriptor("host:1521/service").is_none());
        assert!(parse_descriptor("not a descriptor").is_none());
    }
}
