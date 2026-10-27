//! serde helpers: fixed-size byte arrays and `Fr` as hex strings.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
    hex::encode(v).serialize(s)
}

pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
    let s = String::deserialize(d)?;
    let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
    v.try_into()
        .map_err(|_| serde::de::Error::custom(format!("expected {N} bytes")))
}

pub mod fr {
    use super::*;
    use sb_primitives::Fr;
    use sb_primitives::encoding::{fr_from_bytes, fr_to_bytes};

    pub fn serialize<S: Serializer>(v: &Fr, s: S) -> Result<S::Ok, S::Error> {
        hex::encode(fr_to_bytes(v)).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Fr, D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        fr_from_bytes(&v).map_err(serde::de::Error::custom)
    }
}

pub mod fr_vec {
    use super::*;
    use sb_primitives::Fr;
    use sb_primitives::encoding::{fr_from_bytes, fr_to_bytes};

    pub fn serialize<S: Serializer>(v: &[Fr], s: S) -> Result<S::Ok, S::Error> {
        let strings: Vec<String> = v.iter().map(|f| hex::encode(fr_to_bytes(f))).collect();
        strings.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Fr>, D::Error> {
        let strings: Vec<String> = Vec::deserialize(d)?;
        strings
            .iter()
            .map(|s| {
                let v = hex::decode(s).map_err(serde::de::Error::custom)?;
                fr_from_bytes(&v).map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

pub mod bytes {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        hex::encode(v).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
