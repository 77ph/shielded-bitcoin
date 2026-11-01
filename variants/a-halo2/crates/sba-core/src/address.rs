//! Payment addresses `(d, pk_d)` and their bech32m text form (PROFILE-A.md §3).

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};

use sba_primitives::Affine;
use sba_primitives::diversify::{DIVERSIFIER_LEN, diversify_hash};
use sba_primitives::encoding::{DecodeError, point_from_bytes, point_to_bytes};

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
            Network::Mainnet => "sba",
            Network::Testnet | Network::Signet => "tsba",
            Network::Regtest => "rsba",
        }
    }

    fn from_hrp(hrp: &str) -> Option<Self> {
        match hrp {
            "sba" => Some(Network::Mainnet),
            "tsba" => Some(Network::Signet),
            "rsba" => Some(Network::Regtest),
            _ => None,
        }
    }

    pub fn to_bitcoin(self) -> bitcoin_network::Network {
        match self {
            Network::Mainnet => bitcoin_network::Network::Bitcoin,
            Network::Testnet => bitcoin_network::Network::Testnet,
            Network::Signet => bitcoin_network::Network::Signet,
            Network::Regtest => bitcoin_network::Network::Regtest,
        }
    }
}

/// The subset of `bitcoin::Network` this crate names, without depending on
/// the `bitcoin` crate here.
pub mod bitcoin_network {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Network {
        Bitcoin,
        Testnet,
        Signet,
        Regtest,
    }
}

/// `addr_d = (d, pk_d)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PaymentAddress {
    pub d: [u8; DIVERSIFIER_LEN],
    pub pk_d: Affine,
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

    /// Parse and validate: `pk_d` a canonical non-identity point, `d` valid.
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
        assert!(s.starts_with("tsba1"));
        let (net, back) = PaymentAddress::decode(&s).unwrap();
        assert_eq!(net, Network::Signet);
        assert_eq!(back, a);
        let mut bad = s.clone().into_bytes();
        let i = bad.len() - 3;
        bad[i] = if bad[i] == b'q' { b'p' } else { b'q' };
        assert!(matches!(
            PaymentAddress::decode(std::str::from_utf8(&bad).unwrap()),
            Err(AddressError::Bech32(_))
        ));
        // the paper profile's HRP is not ours
        assert!(PaymentAddress::decode(&a.encode(Network::Signet).replacen("tsba1", "tsb1", 1)).is_err());
        assert_eq!(
            PaymentAddress::from_bytes(&[0u8; 10]),
            Err(AddressError::Length(10))
        );
        let mut raw = a.to_bytes();
        raw[DIVERSIFIER_LEN..].copy_from_slice(&[0u8; 32]);
        assert!(matches!(
            PaymentAddress::from_bytes(&raw),
            Err(AddressError::Point(_))
        ));
    }
}
