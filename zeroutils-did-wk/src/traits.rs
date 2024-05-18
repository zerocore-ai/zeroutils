use std::{fmt::Display, str::FromStr};

use anyhow::Result;

use zeroutils_key::{
    Ed25519PubKey, P256PubKey, PublicKeyBytes, PublicKeyGenerate, Secp256k1PubKey,
};

use super::{Base, DidError};

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// A trait for working with decentralized identifier (DID) types.
pub trait Did: Display + FromStr {
    // fn verification_method(&self) -> String;
    // fn fetch_did_document(&self) -> impl Future<Output = DidDocument>;
}

/// A trait for encoding public keys into a DID Web Key format.
pub trait KeyEncode {
    /// Encodes the public key by first encoding it with [Multicodec][multicodec] and then encoding it
    /// with [Multibase][multibase].
    ///
    /// `base` lets you choose the base encoding format. [`Base`] enum provides the supported encodings.
    ///
    /// [multicodec]: https://github.com/multiformats/multicodec
    /// [multibase]: https://github.com/multiformats/multibase
    fn encode(&self, base: Base) -> String;
}

/// A trait for decoding public keys from a DID Web Key format.
pub trait KeyDecode {
    /// The error type of the decoding operation.
    type Error;

    /// Decodes the public key by first decoding it from a [Multibase][multibase] form and then decoding it
    /// from a [Multicodec][multicodec].
    ///
    /// [multicodec]: https://github.com/multiformats/multicodec
    /// [multibase]: https://github.com/multiformats/multibase
    fn decode(encoded: impl AsRef<str>) -> Result<(Self, Base), Self::Error>
    where
        Self: Sized;
}

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `ed25519-pub` varuint public key code and varuint representation.
const ED25519_PUB_KEY_CODE: (u8, [u8; 2]) = (0xed, [0xED, 0x01]);

/// `p256-pub` varuint public key code and varuint representation.
const P256_PUB_KEY_CODE: (u16, [u8; 2]) = (0x1200, [0x80, 0x1A]);

/// `secp256k1-pub` varuint public key code and varuint representation.
const SECP256K1_PUB_KEY_CODE: (u8, [u8; 2]) = (0xe7, [0xE7, 0x01]);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl KeyEncode for Ed25519PubKey<'_> {
    fn encode(&self, base: Base) -> String {
        let multicodec_enc = {
            let mut tmp = ED25519_PUB_KEY_CODE.1.to_vec();
            tmp.extend(self.public_key_bytes());
            tmp
        };

        base.encode(&multicodec_enc)
    }
}

impl KeyEncode for P256PubKey<'_> {
    fn encode(&self, base: Base) -> String {
        let multicodec_enc = {
            let mut tmp = P256_PUB_KEY_CODE.1.to_vec();
            tmp.extend(self.public_key_bytes());
            tmp
        };

        base.encode(&multicodec_enc)
    }
}

impl KeyEncode for Secp256k1PubKey<'_> {
    fn encode(&self, base: Base) -> String {
        let multicodec_enc = {
            let mut tmp = SECP256K1_PUB_KEY_CODE.1.to_vec();
            tmp.extend(self.public_key_bytes());
            tmp
        };

        base.encode(&multicodec_enc)
    }
}

impl KeyDecode for Ed25519PubKey<'_> {
    type Error = DidError;

    fn decode(encoded: impl AsRef<str>) -> Result<(Self, Base), Self::Error> {
        let (base, multicodec_enc) = Base::decode(encoded)?;

        let pk_bytes = match &multicodec_enc[0..2] {
            [0xED, 0x01] => &multicodec_enc[2..],
            _ => return Err(DidError::ExpectedKeyType("ed25519".to_string())),
        };

        Ok((Ed25519PubKey::from_public_key(pk_bytes)?, base))
    }
}

impl KeyDecode for P256PubKey<'_> {
    type Error = DidError;

    fn decode(encoded: impl AsRef<str>) -> Result<(Self, Base), Self::Error> {
        let (base, multicodec_enc) = Base::decode(encoded)?;

        let pk_bytes = match &multicodec_enc[0..2] {
            [0x80, 0x1A] => &multicodec_enc[2..],
            _ => return Err(DidError::ExpectedKeyType("p256".to_string())),
        };

        Ok((P256PubKey::from_public_key(pk_bytes)?, base))
    }
}

impl KeyDecode for Secp256k1PubKey<'_> {
    type Error = DidError;

    fn decode(encoded: impl AsRef<str>) -> Result<(Self, Base), Self::Error> {
        let (base, multicodec_enc) = Base::decode(encoded)?;

        let pk_bytes = match &multicodec_enc[0..2] {
            [0xE7, 0x01] => &multicodec_enc[2..],
            _ => return Err(DidError::ExpectedKeyType("secp256k1".to_string())),
        };

        Ok((Secp256k1PubKey::from_public_key(pk_bytes)?, base))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use anyhow::Ok;

    use zeroutils_key::{Ed25519KeyPair, KeyPairGenerate, P256KeyPair, Secp256k1KeyPair};

    use super::*;

    #[test]
    fn test_ed25519_encode_and_decode() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let pub_key = Ed25519PubKey::from(Ed25519KeyPair::generate(&mut rng)?);

        let encoded = pub_key.encode(Base::Base58Btc);
        let (decoded, base) = Ed25519PubKey::decode(encoded)?;

        assert_eq!(pub_key, decoded);
        assert_eq!(base, Base::Base58Btc);

        Ok(())
    }

    #[test]
    fn test_p256_encode_and_decode() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let pub_key = P256PubKey::from(P256KeyPair::generate(&mut rng)?);

        let encoded = pub_key.encode(Base::Base64);
        let (decoded, base) = P256PubKey::decode(encoded)?;

        assert_eq!(pub_key, decoded);
        assert_eq!(base, Base::Base64);

        Ok(())
    }

    #[test]
    fn test_secp256k1_encode_and_decode() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let pub_key = Secp256k1PubKey::from(Secp256k1KeyPair::generate(&mut rng)?);

        let encoded = pub_key.encode(Base::Base32Z);
        let (decoded, base) = Secp256k1PubKey::decode(encoded)?;

        assert_eq!(pub_key, decoded);
        assert_eq!(base, Base::Base32Z);

        Ok(())
    }
}
