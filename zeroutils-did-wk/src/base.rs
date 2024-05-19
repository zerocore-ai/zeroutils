use serde::{Deserialize, Serialize};

use super::DidResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Supported base encodings.
///
/// This is a convenience enum that maps to the [`multibase::Base`] enum.
///
// This code is adapted from the `multibase` crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub enum Base {
    /// 8-bit binary (encoder and decoder keeps data unmodified).
    Identity,

    /// Base2 (alphabet: 01).
    Base2,

    /// Base8 (alphabet: 01234567).
    Base8,

    /// Base10 (alphabet: 0123456789).
    Base10,

    /// Base16 lower hexadecimal (alphabet: 0123456789abcdef).
    Base16Lower,

    /// Base16 upper hexadecimal (alphabet: 0123456789ABCDEF).
    Base16Upper,

    /// Base32, rfc4648 no padding (alphabet: abcdefghijklmnopqrstuvwxyz234567).
    Base32Lower,

    /// Base32, rfc4648 no padding (alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567).
    Base32Upper,

    /// Base32, rfc4648 with padding (alphabet: abcdefghijklmnopqrstuvwxyz234567).
    Base32PadLower,

    /// Base32, rfc4648 with padding (alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567).
    Base32PadUpper,

    /// Base32hex, rfc4648 no padding (alphabet: 0123456789abcdefghijklmnopqrstuv).
    Base32HexLower,

    /// Base32hex, rfc4648 no padding (alphabet: 0123456789ABCDEFGHIJKLMNOPQRSTUV).
    Base32HexUpper,

    /// Base32hex, rfc4648 with padding (alphabet: 0123456789abcdefghijklmnopqrstuv).
    Base32HexPadLower,

    /// Base32hex, rfc4648 with padding (alphabet: 0123456789ABCDEFGHIJKLMNOPQRSTUV).
    Base32HexPadUpper,

    /// z-base-32 (used by Tahoe-LAFS) (alphabet: ybndrfg8ejkmcpqxot1uwisza345h769).
    Base32Z,

    /// Base36, [0-9a-z] no padding (alphabet: 0123456789abcdefghijklmnopqrstuvwxyz).
    Base36Lower,

    /// Base36, [0-9A-Z] no padding (alphabet: 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ).
    Base36Upper,

    /// Base58 flicker (alphabet: 123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ).
    Base58Flickr,

    /// Base58 bitcoin (alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz).
    Base58Btc,

    /// Base64, rfc4648 no padding (alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/).
    Base64,

    /// Base64, rfc4648 with padding (alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/).
    Base64Pad,

    /// Base64 url, rfc4648 no padding (alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_).
    Base64Url,

    /// Base64 url, rfc4648 with padding (alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_).
    Base64UrlPad,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Base {
    /// Encodes the given data using the specified base encoding.
    ///
    /// This method encodes the provided input data into a string representation according to the
    /// [Multibase][multibase] standard.
    ///
    /// [multibase]: https://github.com/multiformats/multibase
    pub fn encode(&self, input: &[u8]) -> String {
        multibase::encode((*self).into(), input)
    }

    /// Decodes a given encoded string back to the original data and its base format.
    ///
    /// This function takes an encoded string, determines the base encoding used, and decodes it back
    /// to the original byte array. It also returns the `Base` variant that was used for encoding.
    ///
    /// This follows the [Multibase][multibase] standard.
    ///
    /// [multibase]: https://github.com/multiformats/multibase
    pub fn decode(encoded: impl AsRef<str>) -> DidResult<(Base, Vec<u8>)> {
        let (base, data) = multibase::decode(encoded)?;
        Ok((base.into(), data))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<multibase::Base> for Base {
    fn from(value: multibase::Base) -> Self {
        match value {
            multibase::Base::Identity => Self::Identity,
            multibase::Base::Base2 => Self::Base2,
            multibase::Base::Base8 => Self::Base8,
            multibase::Base::Base10 => Self::Base10,
            multibase::Base::Base16Lower => Self::Base16Lower,
            multibase::Base::Base16Upper => Self::Base16Upper,
            multibase::Base::Base32Lower => Self::Base32Lower,
            multibase::Base::Base32Upper => Self::Base32Upper,
            multibase::Base::Base32PadLower => Self::Base32PadLower,
            multibase::Base::Base32PadUpper => Self::Base32PadUpper,
            multibase::Base::Base32HexLower => Self::Base32HexLower,
            multibase::Base::Base32HexUpper => Self::Base32HexUpper,
            multibase::Base::Base32HexPadLower => Self::Base32HexPadLower,
            multibase::Base::Base32HexPadUpper => Self::Base32HexPadUpper,
            multibase::Base::Base32Z => Self::Base32Z,
            multibase::Base::Base36Lower => Self::Base36Lower,
            multibase::Base::Base36Upper => Self::Base36Upper,
            multibase::Base::Base58Flickr => Self::Base58Flickr,
            multibase::Base::Base58Btc => Self::Base58Btc,
            multibase::Base::Base64 => Self::Base64,
            multibase::Base::Base64Pad => Self::Base64Pad,
            multibase::Base::Base64Url => Self::Base64Url,
            multibase::Base::Base64UrlPad => Self::Base64UrlPad,
        }
    }
}

impl From<Base> for multibase::Base {
    fn from(value: Base) -> Self {
        match value {
            Base::Identity => multibase::Base::Identity,
            Base::Base2 => multibase::Base::Base2,
            Base::Base8 => multibase::Base::Base8,
            Base::Base10 => multibase::Base::Base10,
            Base::Base16Lower => multibase::Base::Base16Lower,
            Base::Base16Upper => multibase::Base::Base16Upper,
            Base::Base32Lower => multibase::Base::Base32Lower,
            Base::Base32Upper => multibase::Base::Base32Upper,
            Base::Base32PadLower => multibase::Base::Base32PadLower,
            Base::Base32PadUpper => multibase::Base::Base32PadUpper,
            Base::Base32HexLower => multibase::Base::Base32HexLower,
            Base::Base32HexUpper => multibase::Base::Base32HexUpper,
            Base::Base32HexPadLower => multibase::Base::Base32HexPadLower,
            Base::Base32HexPadUpper => multibase::Base::Base32HexPadUpper,
            Base::Base32Z => multibase::Base::Base32Z,
            Base::Base36Lower => multibase::Base::Base36Lower,
            Base::Base36Upper => multibase::Base::Base36Upper,
            Base::Base58Flickr => multibase::Base::Base58Flickr,
            Base::Base58Btc => multibase::Base::Base58Btc,
            Base::Base64 => multibase::Base::Base64,
            Base::Base64Pad => multibase::Base::Base64Pad,
            Base::Base64Url => multibase::Base::Base64Url,
            Base::Base64UrlPad => multibase::Base::Base64UrlPad,
        }
    }
}
