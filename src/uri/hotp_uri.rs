// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use crate::Secret;
use regex::Regex;

/// Represents a HOTP (HMAC-based One-Time Password) generator.
///
/// # Fields
///
/// * `name` - Human-readable account label.
/// * `secret` - The shared secret key (Base32-encoded).
/// * `initial_count` - The starting counter value for HOTP generation.
#[derive(Debug, Clone)]
pub struct HOTPUri {
    pub name: String,
    pub secret: Secret,
    pub initial_count: u64,
}

impl HOTPUri {
    /// Create a new `HOTPUri`.
    ///
    /// Arguments:
    /// - `name`: Account label / identifier to display in authenticators.
    /// - `secret`: Shared secret (wrapped in crate's `Secret` type). This should
    ///   be a Base32-encoded secret string.
    /// - `initial_count`: Starting counter for HOTP generation.
    ///
    /// Returns a constructed `HOTPUri`.
    ///
    /// # Examples
    ///
    /// Basic construction:
    ///
    /// ```rust
    /// use crate::Secret;
    /// use crate::uri::hotp_uri::HOTPUri;
    ///
    /// let secret = Secret::new("JBSWY3DPEHPK3PXP").unwrap();
    /// let uri = HOTPUri::new("alice@example.com", secret.clone(), 0);
    ///
    /// assert_eq!(uri.name, "alice@example.com");
    /// assert_eq!(uri.initial_count, 0);
    /// ```
    ///
    /// Serialize to an `otpauth` URI:
    ///
    /// ```rust
    /// use crate::Secret;
    /// use crate::uri::hotp_uri::HOTPUri;
    ///
    /// let secret = Secret::new("JBSWY3DPEHPK3PXP").unwrap();
    /// let uri = HOTPUri::new("alice@example.com", secret, 5);
    /// let s = uri.uri();
    ///
    /// assert!(s.starts_with("otpauth://hotp/"));
    /// assert!(s.contains("counter=5"));
    /// ```
    pub fn new(name: &str, secret: Secret, initial_count: u64) -> HOTPUri {
        HOTPUri {
            name: name.to_string(),
            secret,
            initial_count,
        }
    }

    /// Serialize the `HOTPUri` into an `otpauth://hotp/...` URI string.
    ///
    /// The `name` and `secret` fields are URL-encoded so the resulting URI is
    /// safe to transport or display. The `secret` is obtained from the
    /// `Secret` wrapper as bytes and converted lossily to UTF-8 for inclusion;
    /// this is acceptable because secrets are expected to be ASCII Base32.
    ///
    /// Example:
    ///
    /// ```rust
    /// use crate::Secret;
    /// use crate::uri::hotp_uri::HOTPUri;
    ///
    /// let secret = Secret::new("JBSWY3DPEHPK3PXP").unwrap();
    /// let uri = HOTPUri::new("alice@example.com", secret, 5);
    /// let s = uri.uri();
    ///
    /// assert!(s.starts_with("otpauth://hotp/"));
    /// assert!(s.contains("counter=5"));
    /// ```
    pub fn uri(&self) -> String {
        format!(
            "otpauth://hotp/{}?secret={}&counter={}",
            urlencoding::encode(&self.name),
            urlencoding::encode(String::from_utf8_lossy(&self.secret.clone().get()).as_ref()),
            self.initial_count
        )
    }

    /// Parse an `otpauth://hotp/...` URI into a `HOTPUri`.
    ///
    /// Accepts URIs where the `secret` and `counter` query parameters may
    /// appear in either order. Returns `Ok(HOTPUri)` on success or `Err(String)`
    /// with a short error message when parsing fails.
    ///
    /// The regular expression captures:
    /// - `name`: the path segment after `hotp/` (URL-encoded label)
    /// - `secret` / `secret2`: the `secret` query parameter value (Base32, URL-encoded)
    /// - `counter` / `counter2`: the `counter` query parameter value (decimal)
    ///
    /// Example:
    ///
    /// ```rust
    /// use crate::uri::hotp_uri::HOTPUri;
    ///
    /// let s = "otpauth://hotp/alice%40example.com?secret=JBSWY3DPEHPK3PXP&counter=5";
    /// let uri = HOTPUri::parse(s).unwrap();
    /// assert_eq!(uri.name, "alice@example.com");
    /// assert_eq!(uri.initial_count, 5);
    /// ```
    pub fn parse(uri: &str) -> Result<HOTPUri, String> {
        let re = Regex::new(
            r"^otpauth://hotp/(?P<name>[^?]+)\?(?:.*?secret=(?P<secret>[^&]+).*?counter=(?P<counter>\d+)|.*?counter=(?P<counter2>\d+).*?secret=(?P<secret2>[^&]+)).*$"
        ).unwrap();

        if let Some(caps) = re.captures(uri) {
            let name = caps.name("name").unwrap().as_str();
            let secret = caps.name("secret").or_else(|| caps.name("secret2")).unwrap().as_str();
            let counter = caps
                .name("counter")
                .or_else(|| caps.name("counter2"))
                .unwrap()
                .as_str()
                .parse::<u64>()
                .unwrap();

            Ok(HOTPUri::new(
                name,
                Secret::new(urlencoding::decode(secret).unwrap().to_string().as_str()).unwrap(),
                counter,
            ))
        } else {
            Err("Unable to parse URI".to_owned())
        }
    }
}
