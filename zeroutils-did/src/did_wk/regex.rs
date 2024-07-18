use lazy_static::lazy_static;
use regex::{Regex, RegexBuilder};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

lazy_static! {
    /// A pattern that matches `did:wk:` prefix of a [DID Web Key (`did:wk`)][ref] identifier.
    ///
    /// [ref]: https://github.com/zerocore-ai/did-wk
    pub static ref RE_METHOD: Regex = Regex::new(r"^did:wk:$").unwrap();

    /// A pattern that matches the key part of a [DID Web Key (`did:wk`)][ref] identifier.
    ///
    /// [ref]: https://github.com/zerocore-ai/did-wk
    pub static ref RE_KEY: Regex = Regex::new(r"^[^@]+$").unwrap();

    /// A pattern that matches the locator part of a [DID Web Key (`did:wk`)][ref] identifier.
    ///
    /// [ref]: https://github.com/zerocore-ai/did-wk
    pub static ref RE_LOCATOR: Regex = RegexBuilder::new(&format!(r"^{LOCATOR}$", LOCATOR = *LOCATOR))
        .ignore_whitespace(true)
        .build()
        .unwrap();

    /// A pattern that matches the [host part][ref] of a locator component.
    ///
    /// [ref]: https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
    pub static ref RE_HOST: Regex = RegexBuilder::new(&format!(r"^{HOST}$", HOST = *HOST))
        .ignore_whitespace(true)
        .build()
        .unwrap();

    /// A pattern that matches the [port part][ref] of a locator component.
    ///
    /// [ref]: https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
    pub static ref RE_PORT: Regex = Regex::new(&format!(r"^{PORT}$", PORT = *PORT)).unwrap();

    /// A pattern that matches the [path part][ref] of a locator component.
    ///
    /// [ref]: https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
    pub static ref RE_PATH_ABEMPTY: Regex =
        RegexBuilder::new(&format!(r"^{PATH}$", PATH = *PATH_ABEMPTY))
            .ignore_whitespace(true)
            .build()
            .unwrap();
}

lazy_static! {
    pub(crate) static ref RE_REGNAME: Regex =
        Regex::new(&format!(r"^{REGNAME}$", REGNAME = *REGNAME)).unwrap();
    pub(crate) static ref RE_IPV4ADDR: Regex =
        RegexBuilder::new(&format!(r"^{IPV4ADDR}$", IPV4ADDR = *IPV4ADDR))
            .ignore_whitespace(true)
            .build()
            .unwrap();
    pub(crate) static ref RE_IPLITERAL: Regex =
        RegexBuilder::new(&format!(r"^{IPLITERAL}$", IPLITERAL = *IPLITERAL))
            .ignore_whitespace(true)
            .build()
            .unwrap();
}

lazy_static! {
    static ref LOCATOR: String = format!(
        r"({HOST}(:{PORT})?{PATH_ABEMPTY}?)",
        HOST = *HOST,
        PORT = *PORT,
        PATH_ABEMPTY = *PATH_ABEMPTY
    );
    static ref HOST: String = format!(
        r"({IPLITERAL}|{IPV4ADDR}|{REGNAME})",
        IPLITERAL = *IPLITERAL,
        IPV4ADDR = *IPV4ADDR,
        REGNAME = *REGNAME
    );
    static ref PORT: String = format!(r"[0-9]+");
    static ref PATH_ABEMPTY: String = format!(r"(\/{SEGMENT})*", SEGMENT = *SEGMENT);
    static ref REGNAME: String = format!(
        r"({UNRESERVED}|{PCTENCODED}|{SUB_DELIMS})*",
        UNRESERVED = *UNRESERVED,
        PCTENCODED = *PCT_ENCODED,
        SUB_DELIMS = *SUB_DELIMS
    );
    static ref IPLITERAL: String = format!(
        r"(\[({IPV6ADDR}|{IPVFUTURE})\])",
        IPV6ADDR = *IPV6ADDR,
        IPVFUTURE = *IPVFUTURE
    );
    static ref IPVFUTURE: String = format!(
        r"(v[0-9a-fA-F]+\.({UNRESERVED}|{SUB_DELIMS}|:)+)",
        UNRESERVED = *UNRESERVED,
        SUB_DELIMS = *SUB_DELIMS,
    );
    static ref IPV6ADDR: String = format!(
        r#"(
        ({H16}:){{6}}{LS32}
        | ::({H16}:){{5}}{LS32}
        | ({H16})?::({H16}:){{4}}{LS32}
        | (({H16}:){{0, 1}}{H16})?::({H16}:){{3}}{LS32}
        | (({H16}:){{0, 2}}{H16})?::({H16}:){{2}}{LS32}
        | (({H16}:){{0, 3}}{H16})?::{H16}:{LS32}
        | (({H16}:){{0, 4}}{H16})?::{LS32}
        | (({H16}:){{0, 5}}{H16})?::{H16}
        | (({H16}:){{0, 6}}{H16})?::
        )"#,
        H16 = *H16,
        LS32 = *LS32
    );
    static ref LS32: String = format!(
        r"(({H16}:{H16})|{IPV4ADDR})",
        H16 = *H16,
        IPV4ADDR = *IPV4ADDR
    );
    static ref H16: String = format!(r"[0-9a-fA-F]{{1, 4}}");
    static ref IPV4ADDR: String = format!(
        r#"(
        ([0-9]|[1-9][0-9]|1[0-9]{{2}}|2[0-4][0-9]|25[0-5])\.
        ([0-9]|[1-9][0-9]|1[0-9]{{2}}|2[0-4][0-9]|25[0-5])\.
        ([0-9]|[1-9][0-9]|1[0-9]{{2}}|2[0-4][0-9]|25[0-5])\.
        ([0-9]|[1-9][0-9]|1[0-9]{{2}}|2[0-4][0-9]|25[0-5])
        )"#
    );
    static ref SEGMENT: String = format!(r"({PCHAR})*", PCHAR = *PCHAR);
    static ref SEGMENT_NZ: String = format!(r"({PCHAR})+", PCHAR = *PCHAR);
    static ref SEGMENT_NZ_NC: String = format!(
        r"(({UNRESERVED}|{PCT_ENCODED}|{SUB_DELIMS}|@)+)",
        UNRESERVED = *UNRESERVED,
        PCT_ENCODED = *PCT_ENCODED,
        SUB_DELIMS = *SUB_DELIMS
    );
    static ref PCHAR: String = format!(
        r"(({UNRESERVED}|{PCT_ENCODED}|{SUB_DELIMS}|[:@]))",
        UNRESERVED = *UNRESERVED,
        PCT_ENCODED = *PCT_ENCODED,
        SUB_DELIMS = *SUB_DELIMS
    );
    static ref SUB_DELIMS: String = format!(r"[!$&'()*+,;=]");
    static ref PCT_ENCODED: String = format!(r"%[0-9a-fA-F]{{2}}");
    static ref UNRESERVED: String = format!(r"[a-zA-Z0-9\-\._~]");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use anyhow::Ok;
    use regex::RegexBuilder;

    use super::*;

    #[test]
    fn test_unreserved_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *UNRESERVED))?;
        for x in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~".chars() {
            assert!(re.is_match(&x.to_string()));
        }

        Ok(())
    }

    #[test]
    fn test_pct_encoded_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *PCT_ENCODED))?;
        for x in ["%00", "%04", "%0a", "%0F", "%fF", "%FF"].iter() {
            assert!(re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_sub_delims_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *SUB_DELIMS))?;
        for x in "!$&'()*+,;=".chars() {
            assert!(re.is_match(&x.to_string()));
        }

        Ok(())
    }

    #[test]
    fn test_pchar_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *PCHAR))?;
        for x in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:@".chars() {
            assert!(re.is_match(&x.to_string()));
        }

        Ok(())
    }

    #[test]
    fn test_segment_nz_nc_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *SEGMENT_NZ_NC))?;
        for x in [
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
            "-._~@",
            "%00%04%0a%0F%fF%FF",
            "!$&'()*+,;=",
            "a",
        ] {
            assert!(re.is_match(x));
        }

        assert!(!re.is_match(":"));

        Ok(())
    }

    #[test]
    fn test_segment_nz_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *SEGMENT_NZ))?;
        for x in [
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
            "-._~:@",
            "%00%04%0a%0F%fF%FF",
            "!$&'()*+,;=",
            "a",
        ] {
            assert!(re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_segment_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *SEGMENT))?;
        for x in [
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
            "-._~:@",
            "%00%04%0a%0F%fF%FF",
            "!$&'()*+,;=",
            "a",
            "",
        ] {
            assert!(re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_ipv4addr_pattern() -> anyhow::Result<()> {
        let re = RegexBuilder::new(&format!(r"^{}$", *IPV4ADDR))
            .ignore_whitespace(true)
            .build()?;
        for x in [
            "192.168.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.100.1",
            "192.168.1.255",
            "224.0.0.1",
            "8.8.8.8",
            "127.0.0.1",
            "172.31.255.254",
            "255.255.255.0",
            "192.168.254.254",
        ] {
            assert!(re.is_match(x));
        }

        // No leading zeros
        for x in ["192.168.007.007", "010.002.000.002"] {
            assert!(!re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_h16_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *H16))?;
        for x in [
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "A",
            "0a", "2b", "Fe", "1A", "3B", "4C", "5D", "6E", "7F", "8F", "9F", "aF", "bF", "cF",
            "33a", "4b3", "5c4", "6d5", "7e6", "8f7", "9f8", "aF9", "bF0", "cF1", "dF2", "eF3",
            "23A9", "4B3A", "5C4B", "6D5C", "7E6D", "8F7E", "9F8F", "aF9F", "bF0F", "cF1F", "dF2F",
        ] {
            assert!(re.is_match(x));
        }

        // No less than 1, no more than 4 characters, hexadecimal
        for x in ["", "00000", "aF296", "g45"] {
            assert!(!re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_ls32_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *LS32))?;
        for x in [
            "64:64", "0:0", "2f:2f", "ff:ff", "aF:0F", "bF:1F", "cF:2F", "dF:3F", "eF:4F",
        ] {
            assert!(re.is_match(x));
        }

        // No less than 1, single colon, hexadecimal
        for x in ["", "0", "0:0:0", "5:g"] {
            assert!(!re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_ipv6addr_pattern() -> anyhow::Result<()> {
        let re = RegexBuilder::new(&format!(r"^{}$", *IPV6ADDR))
            .ignore_whitespace(true)
            .build()?;

        for x in [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:0db8:85a3:0000:0000:8a2e:184.45.6.255",
            "::2001:db8:85a3:0:8a2e:370:7334",
            "::2001:db8:85a3:0:8a2e:184.45.6.255",
            "2001::85a3:0:0:8a2e:370:7334",
            "2001::85a3:0:0:8a2e:184.45.6.255",
            "::85a3:0:0:8a2e:370:7334",
            "::85a3:0:0:8a2e:184.45.6.255",
            "2001:0db8::0000:0000:8a2e:0370:7334",
            "2001:0db8::0000:0000:8a2e:184.45.6.255",
            "0db8::0000:0000:8a2e:0370:7334",
            "0db8::0000:0000:8a2e:184.45.6.255",
            "::0000:0000:8a2e:0370:7334",
            "::0000:0000:8a2e:184.45.6.255",
            "2001:0db8:0000::0000:8a2e:0370:7334",
            "2001:0db8:0000::0000:8a2e:184.45.6.255",
            "0db8:0000::0000:8a2e:0370:7334",
            "0db8:0000::0000:8a2e:184.45.6.255",
            "0000::0000:8a2e:0370:7334",
            "0000::0000:8a2e:184.45.6.255",
            "::0000:8a2e:0370:7334",
            "::0000:8a2e:184.45.6.255",
            "2001:0db8:0000:0000::8a2e:0370:7334",
            "2001:0db8:0000:0000::8a2e:184.45.6.255",
            "0db8:0000:0000::8a2e:0370:7334",
            "0db8:0000:0000::8a2e:184.45.6.255",
            "0000:0000::8a2e:0370:7334",
            "0000:0000::8a2e:184.45.6.255",
            "0000::8a2e:0370:7334",
            "0000::8a2e:184.45.6.255",
            "::8a2e:0370:7334",
            "::8a2e:184.45.6.255",
            "2001:0db8:0000:0000:8a2e::0370:7334",
            "2001:0db8:0000:0000:8a2e::184.45.6.255",
            "0db8:0000:0000:8a2e::0370:7334",
            "0db8:0000:0000:8a2e::184.45.6.255",
            "0000:0000:8a2e::0370:7334",
            "0000:0000:8a2e::184.45.6.255",
            "0000:8a2e::0370:7334",
            "0000:8a2e::184.45.6.255",
            "8a2e::0370:7334",
            "8a2e::184.45.6.255",
            "::0370:7334",
            "::184.45.6.255",
            "2001:0db8:0000:0000:8a2e:0370::7334",
            "0db8:0000:0000:8a2e:0370::7334",
            "0000:0000:8a2e:0370::7334",
            "0000:8a2e:0370::7334",
            "8a2e:0370::7334",
            "0370::7334",
            "::7334",
            "2001:0db8:0000:0000:8a2e:0370:7334::",
            "0db8:0000:0000:8a2e:0370:7334::",
            "0000:0000:8a2e:0370:7334::",
            "0000:8a2e:0370:7334::",
            "8a2e:0370:7334::",
            "0370:7334::",
            "7334::",
            "::",
        ] {
            assert!(re.is_match(x));
        }

        for x in [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8:85a3::8a2e:370:7334",
            "fe80::1",
            "::1",
            "::ffff:192.168.1.1",
            "::",
            "ff02::1",
            "ff02::1:ff00:0",
            "ff02::2",
            "fd00::8a2e:0370:7334",
            "::1234:5678",
            "2001:db8::8a2e:0:0:1",
            "2001:db8::",
            "2001:db8::192.168.1.1",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(re.is_match(x));
        }

        for x in [
            "2001:db8:85a3:0:8a2e:370:7334",
            "2001:db8:85a3:0:8a2e:184.45.6.255",
            "0db8::2001:db8:85a3:0:8a2e:370:7334",
            "0db8::2001:db8:85a3:0:8a2e:184.45.6.255",
            "2001:0db8:0000:0000:8a2e:0370::0370:184.45.6.255",
        ] {
            assert!(!re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_ipvfuture_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *IPVFUTURE))?;
        for x in ["v0.azAZ09-._~!$&':()*+,", "v1F.azAZ09-._~!$&':()*+,"] {
            assert!(re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_ipliteral_pattern() -> anyhow::Result<()> {
        let re = RegexBuilder::new(&format!(r"^{}$", *IPLITERAL))
            .ignore_whitespace(true)
            .build()?;
        for x in [
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]",
            "[2001:db8:85a3::8a2e:370:7334]",
            "[fe80::1]",
            "[::1]",
            "[::ffff:192.168.1.1]",
            "[::]",
            "[ff02::1]",
            "[ff02::1:ff00:0]",
            "[ff02::2]",
            "[fd00::8a2e:0370:7334]",
            "[::1234:5678]",
            "[2001:db8::8a2e:0:0:1]",
            "[2001:db8::]",
            "[2001:db8::192.168.1.1]",
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]",
            "[v1F.azAZ09-._~!$&':()*+,]",
        ] {
            assert!(re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_regname_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *REGNAME))?;
        for x in [
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
            "-._~",
            "!$&'()*+,;=",
            "a",
            "a0",
            "a0-_~!$&'()*+,;=",
            "a0-_~!$&'()*+,;",
        ] {
            assert!(re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_path_abempty_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *PATH_ABEMPTY))?;
        for x in [
            "",
            "/",
            "//",
            "/a0-_~!$&'()*+,;=",
            "//a0-_~!$&'()*+,;=",
            "/a0-_~!$&'()*+,;/B1-",
            "/a0-_~!$&'()*+,;///B1-",
        ] {
            assert!(re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_port_pattern() -> anyhow::Result<()> {
        let re = Regex::new(&format!(r"^{}$", *PORT))?;
        for x in [
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "100", "1000", "65535",
        ] {
            assert!(re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_host_pattern() -> anyhow::Result<()> {
        let re = RegexBuilder::new(&format!(r"^{}$", *HOST))
            .ignore_whitespace(true)
            .build()?;
        for x in [
            "neomancypher.zerocore.ai",
            "189.45.6.255",
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]",
            "[v1F.azAZ09-._~!$&':()*+,]",
        ] {
            assert!(re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_locator_pattern() -> anyhow::Result<()> {
        let re = RegexBuilder::new(&format!(r"^{}$", *LOCATOR))
            .ignore_whitespace(true)
            .build()?;
        for x in [
            "neomancypher.zerocore.ai:8080/",
            "neomancypher.zerocore.ai:8080/public",
            "neomancypher.zerocore.ai/public/",
            "neomancypher.zerocore.ai/public/ids",
            "184.45.6.255:8000/",
            "184.45.6.255:8000/public",
            "184.45.6.255/public/",
            "184.45.6.255/public/ids",
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080/",
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080/public",
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]/public/",
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]/public/ids",
            "[v1F.azAZ09-._~!$&':()*+,]:8080/",
            "[v1F.azAZ09-._~!$&':()*+,]:8080/public",
            "[v1F.azAZ09-._~!$&':()*+,]/public/",
            "[v1F.azAZ09-._~!$&':()*+,]/public/ids",
        ] {
            assert!(re.is_match(x));
        }

        Ok(())
    }

    #[test]
    fn test_key_regex() -> anyhow::Result<()> {
        for x in [
            "z6Mkn5zafXe3zRNPmL2qFcDeQe1DVjo7Zn9nJaG3cGKXX27M",
            "mgCQCVJj5vFsH1OQSpdykyE1KrS8ry9PlIG7fjbgAqART/Yg",
            "fe70103905946d1cd0bdc53cf173149abbfb2b080a9bdebe01826daa06bbfc337683a66",
        ] {
            assert!(RE_KEY.is_match(x))
        }

        Ok(())
    }
}
