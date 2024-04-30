//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub enum KeyPairType {
    Ed25519,
    P256,
    Secp256k1,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum JwsAlgName {
    #[serde(rename = "EdDSA")]
    EdDSA,

    #[serde(rename = "ES256")]
    ES256,

    #[serde(rename = "ES256K")]
    ES256K,
}
