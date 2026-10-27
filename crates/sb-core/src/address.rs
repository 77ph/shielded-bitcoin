//! Payment addresses `(d, pk_d)` and their bech32m text form (profile §3).

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};

use sb_primitives::JubjubAffine;
use sb_primitives::diversify::{DIVERSIFIER_LEN, diversify_hash};
use sb_primitives::encoding::{DecodeError, point_from_bytes, point_to_bytes};

/// Bitcoin network a deployment lives on; selects the address HRP.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl Network {
    pub fn hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "sb",
            Network::Testnet | Network::Signet => "tsb",
            Network::Regtest => "rsb",
        }
    }

    fn from_hrp(hrp: &str) -> Option<Self> {
        match hrp {
            "sb" => Some(Network::Mainnet),
            "tsb" => Some(Network::Signet),
            "rsb" => Some(Network::Regtest),
            _ => None,
        }
    }
}

/// `addr_d = (d, pk_d)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PaymentAddress {
    pub d: [u8; DIVERSIFIER_LEN],
    pub pk_d: JubjubAffine,
}

/// Length of the raw address payload.
pub const ADDRESS_LEN: usize = DIVERSIFIER_LEN + 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("bech32m: {0}")]
    Bech32(String),
    #[error("unknown human-readable part {0:?}")]
    UnknownHrp(String),
    #[error("wrong payload length {0}")]
    Length(usize),
    #[error("invalid diversifier (no curve point)")]
    InvalidDiversifier,
    #[error("invalid pk_d: {0}")]
    Point(#[from] DecodeError),
}

impl PaymentAddress {
    pub fn to_bytes(&self) -> [u8; ADDRESS_LEN] {
        let mut out = [0u8; ADDRESS_LEN];
        out[..DIVERSIFIER_LEN].copy_from_slice(&self.d);
        out[DIVERSIFIER_LEN..].copy_from_slice(&point_to_bytes(&self.pk_d));
        out
    }

    /// Parse and validate: `pk_d` canonical and in the subgroup, `d` valid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AddressError> {
        if bytes.len() != ADDRESS_LEN {
            return Err(AddressError::Length(bytes.len()));
        }
        let mut d = [0u8; DIVERSIFIER_LEN];
        d.copy_from_slice(&bytes[..DIVERSIFIER_LEN]);
        if diversify_hash(&d).is_none() {
            return Err(AddressError::InvalidDiversifier);
        }
        let pk_d = point_from_bytes(&bytes[DIVERSIFIER_LEN..])?;
        Ok(PaymentAddress { d, pk_d })
    }

    pub fn encode(&self, network: Network) -> String {
        let hrp = Hrp::parse(network.hrp()).expect("static hrp");
        bech32::encode::<Bech32m>(hrp, &self.to_bytes()).expect("short payload")
    }

    pub fn decode(s: &str) -> Result<(Network, Self), AddressError> {
        let checked =
            CheckedHrpstring::new::<Bech32m>(s).map_err(|e| AddressError::Bech32(e.to_string()))?;
        let hrp = checked.hrp();
        let network = Network::from_hrp(hrp.as_str())
            .ok_or_else(|| AddressError::UnknownHrp(hrp.to_string()))?;
        let payload: Vec<u8> = checked.byte_iter().collect();
        Ok((network, Self::from_bytes(&payload)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Seed, WalletKeys};

    #[test]
    fn text_round_trip_and_rejections() {
        let k = WalletKeys::from_seed(&Seed([3u8; 32]));
        let (_, a) = k.ivk.find_address(0);
        let s = a.encode(Network::Signet);
        assert!(s.starts_with("tsb1"));
        let (net, back) = PaymentAddress::decode(&s).unwrap();
        assert_eq!(net, Network::Signet);
        assert_eq!(back, a);
        // flip a character: checksum failure
        let mut bad = s.clone().into_bytes();
        let i = bad.len() - 3;
        bad[i] = if bad[i] == b'q' { b'p' } else { b'q' };
        assert!(matches!(
            PaymentAddress::decode(std::str::from_utf8(&bad).unwrap()),
            Err(AddressError::Bech32(_))
        ));
        // mainnet hrp with the same payload decodes as mainnet
        let m = a.encode(Network::Mainnet);
        assert_eq!(PaymentAddress::decode(&m).unwrap().0, Network::Mainnet);
    }

    #[test]
    fn invalid_diversifier_is_rejected() {
        let k = WalletKeys::from_seed(&Seed([4u8; 32]));
        let (i, a) = k.ivk.find_address(0);
        // find an invalid diversifier
        let mut j = i + 1;
        let bad_d = loop {
            let d = k.ivk.diversifier(j);
            if diversify_hash(&d).is_none() {
                break d;
            }
            j += 1;
        };
        let mut bytes = a.to_bytes();
        bytes[..DIVERSIFIER_LEN].copy_from_slice(&bad_d);
        assert_eq!(
            PaymentAddress::from_bytes(&bytes),
            Err(AddressError::InvalidDiversifier)
        );
    }
}
