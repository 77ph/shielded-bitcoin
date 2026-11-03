//! Variant A behind the `sb` binary (`docs/VARIANT-A.md` §6.5): `sb`
//! dispatches here when the deployment profile (or `profile-new --family`)
//! names family `a-halo2`. The commands mirror the paper CLI's for the
//! transfer layer: profile, wallets, addresses, sync, scan, mint, send,
//! transparent fee funding; publication through the fee coins of the
//! wallet (witness carrier or OP_RETURN) or to the outbox.

use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand, ValueEnum};
use ff::Field;
use serde::{Deserialize, Serialize};

use sb_common::carrier::{CarrierMode, carrier_output, memo_output};
use sb_common::chain::ChainSource;
use sb_common::chain::esplora::Esplora;
use sb_common::chain::light::LightSource;
use sb_common::chain::rpc::BitcoinCoreRpc;
use sb_common::funding::{self, FundingState, FundingWallet};
use sb_common::witness;
use sba_core::address::{Network as SbNetwork, PaymentAddress};
use sba_core::envelope::MintEnvelope;
use sba_core::note::NotePlaintext;
use sba_indexer::{Deployment, DevBoundary, Indexer, JsonStore, StateStore};
use sba_primitives::Fp;
use sba_primitives::encoding::fp_to_bytes;
use sba_wallet::{Wallet, anchor_for};

mod relay;
mod serve;

/// The family this crate implements, as a deployment profile names it.
pub const FAMILY: &str = sba_core::FAMILY;

/// Does this invocation belong to family A? `profile-new --family a-halo2`,
/// or a `--profile` whose JSON carries `"family": "a-halo2"`.
pub fn is_family_a(args: &[String]) -> bool {
    if args.iter().any(|a| a == "profile-new") {
        if let Some(i) = args.iter().position(|a| a == "--family") {
            return args.get(i + 1).map(|f| f == FAMILY).unwrap_or(false);
        }
        return args.iter().any(|a| a == &format!("--family={FAMILY}"));
    }
    let mut profile = PathBuf::from("deployments/signet-dev.json");
    for (i, a) in args.iter().enumerate() {
        if a == "--profile" {
            if let Some(p) = args.get(i + 1) {
                profile = PathBuf::from(p);
            }
        } else if let Some(p) = a.strip_prefix("--profile=") {
            profile = PathBuf::from(p);
        }
    }
    let Ok(text) = std::fs::read_to_string(&profile) else {
        return false;
    };
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| {
            v.get("family")
                .and_then(|f| f.as_str())
                .map(|f| f == FAMILY)
        })
        .unwrap_or(false)
}

#[derive(Parser)]
#[command(
    name = "sb",
    about = "Shielded Bitcoin, variant A (Halo 2 over Pasta, no trusted setup)"
)]
struct Cli {
    #[arg(long, global = true, default_value = "deployments/signet-dev.json")]
    profile: PathBuf,
    #[arg(long, global = true, default_value = "sb-data")]
    data_dir: PathBuf,
    #[arg(long, global = true)]
    passphrase_file: Option<PathBuf>,
    /// Block source: `esplora:<url>`, `electrum:…`, `rpc:<url>:<user>:<pass>`, `rpc-cookie:<url>:<cookie-path>`, or verified sync from an `sb serve` indexer of this family: `light:<url>` (`light:<url>|<full source>` also checks block hashes there).
    #[arg(
        long,
        global = true,
        default_value = "esplora:https://mempool.space/signet/api"
    )]
    chain: String,
    #[arg(long, global = true, env = "SB_PROXY")]
    proxy: Option<String>,
    #[arg(long, global = true)]
    publish_via: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum CarrierArg {
    OpReturn,
    Witness,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write a new family-A deployment profile (derives the verifying key to pin its identifier).
    ProfileNew {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "signet")]
        network: String,
        #[arg(long)]
        activation: u32,
        /// Must be `a-halo2` (what routes `sb` here).
        #[arg(long)]
        family: String,
        #[arg(long)]
        vault_script: Option<String>,
        #[arg(long)]
        operator_address: Option<String>,
        #[arg(long, value_enum, default_value = "witness")]
        carrier: CarrierArg,
        #[arg(long, default_value = "100")]
        window: u32,
        #[arg(long, default_value = "3")]
        anchor_depth: u32,
    },
    /// Create a wallet (encrypted unless --no-encrypt).
    WalletNew {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        no_encrypt: bool,
    },
    /// Encrypt a plaintext wallet file.
    WalletEncrypt {
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Show the wallet's shielded and funding addresses.
    Address {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        new: bool,
    },
    /// Replay the chain into the local state.
    Sync,
    /// Show the replayed state.
    Status,
    /// Scan the replayed history for the wallet's notes.
    Scan {
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Release input locks left by unpublished transfers.
    Unlock {
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Development mint: pay the vault and publish the note (docs/BOUNDARY.md).
    Mint {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "1")]
        fee_rate: u64,
        #[arg(long)]
        no_broadcast: bool,
    },
    /// Private payment to a shielded address.
    Send {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "1")]
        fee_rate: u64,
        #[arg(long)]
        no_broadcast: bool,
        /// Hand the envelope to a sponsored relayer (`http://host:port`) instead of paying the carrier.
        #[arg(long, conflicts_with = "no_broadcast")]
        relay: Option<String>,
    },
    /// Withdraw `amount` sat to a Bitcoin address through the dev operator
    /// (`docs/BOUNDARY.md`): a transfer to the operator's shielded address
    /// with a payout memo next to the envelope.
    Withdraw {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        amount: u64,
        /// Destination Bitcoin address on the deployment's network.
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "1")]
        fee_rate: u64,
        #[arg(long)]
        no_broadcast: bool,
        /// Hand the envelope to a sponsored relayer (`http://host:port`) instead of paying the carrier.
        #[arg(long, conflicts_with = "no_broadcast")]
        relay: Option<String>,
    },
    /// Operator: pay pending withdraw requests from the vault wallet's coins.
    Payouts {
        #[arg(long, default_value = "operator")]
        name: String,
        #[arg(long, default_value = "1")]
        fee_rate: u64,
        /// List the pending requests without paying them.
        #[arg(long)]
        no_broadcast: bool,
    },
    /// Publish a carrier from the outbox, paid from a wallet's fee coins
    /// (any wallet, not only the sender's: third-party funding).
    Publish {
        /// Outbox label (`transfer-…`, `mint-…`, `withdraw-…`) or a path to its `.json`.
        label: String,
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long, default_value = "1")]
        fee_rate: u64,
        /// Hand the envelope to a sponsored relayer (`http://host:port`) instead of paying the carrier.
        #[arg(long)]
        relay: Option<String>,
    },
    /// Serve the indexer API for verified-sync clients (`--chain light:<url>`).
    Serve {
        #[arg(long, default_value = "127.0.0.1:8788")]
        listen: String,
        /// Exit after this many requests (tests).
        #[arg(long)]
        max_requests: Option<u32>,
    },
    /// Run a sponsored relayer: publish other people's transfers from this wallet's fee coins.
    RelayServe {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        #[arg(long, default_value = "1")]
        fee_rate: u64,
        /// Carriers paid per hour at most.
        #[arg(long, default_value = "20")]
        max_per_hour: u32,
        /// Submissions checked per client address per minute at most.
        #[arg(long, default_value = "6")]
        max_checks_per_minute: u32,
        /// Seconds between replays to the chain tip.
        #[arg(long, default_value = "5")]
        sync_interval: u64,
        /// Exit after this many requests (tests).
        #[arg(long)]
        max_requests: Option<u32>,
    },
    /// Pay transparent coins from the wallet's funding address.
    FundSend {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "1")]
        fee_rate: u64,
    },
}

/// A carrier waiting in the outbox.
#[derive(Debug, Serialize, Deserialize)]
struct OutboxEntry {
    envelope: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extra: Vec<ExtraOutput>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExtraOutput {
    value: u64,
    script_hex: String,
}

impl OutboxEntry {
    fn new(envelope: &[u8], extra: Vec<bitcoin::TxOut>) -> Self {
        OutboxEntry {
            envelope: hex::encode(envelope),
            extra: extra
                .into_iter()
                .map(|o| ExtraOutput {
                    value: o.value.to_sat(),
                    script_hex: hex::encode(o.script_pubkey.as_bytes()),
                })
                .collect(),
        }
    }

    /// What a relayer may be handed: no extra output (a transfer) or one
    /// payout memo (a withdraw); a mint's vault output is refused here.
    fn relay_memo(&self) -> Result<Option<Vec<u8>>> {
        use bitcoin::script::Instruction;
        let extras = self.extra_outputs()?;
        match extras.as_slice() {
            [] => Ok(None),
            [out] if out.value.to_sat() == 0 => {
                let mut it = out.script_pubkey.instructions();
                let memo = match (it.next(), it.next(), it.next()) {
                    (
                        Some(Ok(Instruction::Op(bitcoin::opcodes::all::OP_RETURN))),
                        Some(Ok(Instruction::PushBytes(b))),
                        None,
                    ) if b.as_bytes().starts_with(&sb_common::carrier::MEMO_MAGIC) => {
                        b.as_bytes().to_vec()
                    }
                    _ => bail!("a relayer only publishes transfers and payout memos"),
                };
                Ok(Some(memo))
            }
            _ => bail!("a mint pays the vault; a relayer only publishes transfers"),
        }
    }

    fn extra_outputs(&self) -> Result<Vec<bitcoin::TxOut>> {
        self.extra
            .iter()
            .map(|e| {
                Ok(bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(e.value),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(hex::decode(&e.script_hex)?),
                })
            })
            .collect()
    }

    /// Carrier outputs for the OP_RETURN mode: the extra ones, then the envelope.
    fn outputs(&self) -> Result<Vec<bitcoin::TxOut>> {
        let mut out = self.extra_outputs()?;
        out.push(carrier_output(&hex::decode(&self.envelope)?));
        Ok(out)
    }
}

struct Ctx {
    passphrase_file: Option<PathBuf>,
    deployment: Deployment,
    data_dir: PathBuf,
    chain: String,
    publish_via: Option<String>,
}

impl Ctx {
    fn state_path(&self) -> PathBuf {
        self.data_dir
            .join(format!("state-{}.json", self.deployment.name))
    }

    fn wallet_path(&self, name: &str) -> PathBuf {
        self.data_dir.join("wallets").join(format!("{name}.json"))
    }

    fn full_source(spec: &str) -> Result<Box<dyn ChainSource>> {
        if let Some(url) = spec.strip_prefix("esplora:") {
            return Ok(Box::new(Esplora::new(url)));
        }
        if let Some(url) = spec.strip_prefix("electrum:") {
            return Ok(Box::new(sb_common::chain::electrum::Electrum::new(url)?));
        }
        if let Some(rest) = spec.strip_prefix("rpc-cookie:") {
            let (url, cookie) = rest
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("rpc-cookie:<url>:<cookie-path>"))?;
            return Ok(Box::new(BitcoinCoreRpc::with_cookie(
                url,
                Path::new(cookie),
            )?));
        }
        if let Some(rest) = spec.strip_prefix("rpc:") {
            let parts: Vec<&str> = rest.rsplitn(3, ':').collect();
            if parts.len() != 3 {
                bail!("rpc:<url>:<user>:<pass>");
            }
            return Ok(Box::new(BitcoinCoreRpc::new(parts[2], parts[1], parts[0])));
        }
        bail!("unknown chain spec {spec:?}")
    }

    fn chain_source(&self) -> Result<Box<dyn ChainSource>> {
        match self.light_source()? {
            Some(l) => Ok(Box::new(l)),
            None => Self::full_source(&self.chain),
        }
    }

    /// `light:<url>[|<full source>]`: verified sync from an `sb serve`
    /// indexer of this family, with block hashes cross-checked against the
    /// full source when one is given.
    fn light_source(&self) -> Result<Option<Rc<LightSource>>> {
        let Some(rest) = self.chain.strip_prefix("light:") else {
            return Ok(None);
        };
        let (url, headers) = match rest.split_once('|') {
            Some((u, h)) => (u, Some(Self::full_source(h)?)),
            None => (rest, None),
        };
        Ok(Some(Rc::new(LightSource::new(url, headers))))
    }

    /// UTXO lookup and broadcast through `--publish-via` or `--chain` (for
    /// `light:`, through its full source; a relayer needs none).
    fn publisher(&self) -> Result<Box<dyn funding::Publisher>> {
        let spec = match self.publish_via.as_deref() {
            Some(s) => s,
            None => match self.chain.strip_prefix("light:") {
                Some(rest) => match rest.split_once('|') {
                    Some((_, full)) => full,
                    None => bail!(
                        "light:<url> has no publisher: add |<full source>, --publish-via, or publish through --relay"
                    ),
                },
                None => self.chain.as_str(),
            },
        };
        if let Some(url) = spec.strip_prefix("esplora:") {
            return Ok(Box::new(funding::EsploraPublisher::new(url)));
        }
        if let Some(url) = spec.strip_prefix("electrum:") {
            let electrum = sb_common::chain::electrum::Electrum::new(url)?;
            return Ok(Box::new(funding::ElectrumPublisher { electrum }));
        }
        if let Some(rest) = spec.strip_prefix("rpc-cookie:") {
            let (url, cookie) = rest
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("rpc-cookie:<url>:<cookie-path>"))?;
            let rpc = BitcoinCoreRpc::with_cookie(url, Path::new(cookie))?;
            return Ok(Box::new(funding::RpcPublisher { rpc }));
        }
        if let Some(rest) = spec.strip_prefix("rpc:") {
            let parts: Vec<&str> = rest.rsplitn(3, ':').collect();
            if parts.len() != 3 {
                bail!("rpc:<url>:<user>:<pass>");
            }
            let rpc = BitcoinCoreRpc::new(parts[2], parts[1], parts[0]);
            return Ok(Box::new(funding::RpcPublisher { rpc }));
        }
        bail!("no publisher for chain spec {spec:?}")
    }

    fn indexer(&self) -> Result<(Indexer, Box<dyn StateStore>)> {
        let verifier = self.deployment.verifier()?;
        let mut store: Box<dyn StateStore> = Box::new(JsonStore::new(self.state_path()));
        let state = store.load()?;
        Ok((
            Indexer::new(self.deployment.clone(), verifier, state),
            store,
        ))
    }

    /// Passphrase from --passphrase-file, then SB_WALLET_PASSPHRASE, then a prompt.
    fn passphrase(&self, prompt: &str, confirm: bool) -> Result<String> {
        if let Some(p) = &self.passphrase_file {
            return Ok(std::fs::read_to_string(p)?
                .trim_end_matches(['\n', '\r'])
                .to_string());
        }
        if let Ok(p) = std::env::var("SB_WALLET_PASSPHRASE") {
            return Ok(p);
        }
        let p = rpassword::prompt_password(prompt)?;
        if confirm && rpassword::prompt_password("Repeat passphrase: ")? != p {
            bail!("passphrases differ");
        }
        Ok(p)
    }

    fn wallet(&self, name: &str) -> Result<Wallet> {
        let path = self.wallet_path(name);
        match Wallet::load(&path, None) {
            Ok(w) => {
                eprintln!(
                    "warning: wallet {name} is stored in plaintext; run `sb wallet-encrypt --name {name}`"
                );
                Ok(w)
            }
            Err(sba_wallet::WalletError::PassphraseRequired) => {
                let pass = self.passphrase(&format!("Passphrase for wallet {name}: "), false)?;
                Wallet::load(&path, Some(&pass)).with_context(|| format!("wallet {name}"))
            }
            Err(e) => Err(e).with_context(|| format!("wallet {name} (run `sb wallet-new`)")),
        }
    }

    fn btc_network(&self) -> bitcoin::Network {
        match self.deployment.network {
            SbNetwork::Mainnet => bitcoin::Network::Bitcoin,
            SbNetwork::Testnet => bitcoin::Network::Testnet,
            SbNetwork::Signet => bitcoin::Network::Signet,
            SbNetwork::Regtest => bitcoin::Network::Regtest,
        }
    }

    fn funding(&self, wallet: &Wallet) -> Result<FundingWallet> {
        let seed = hex::decode(wallet.seed_hex())?;
        Ok(FundingWallet::new(
            seed.try_into().unwrap(),
            self.btc_network(),
        ))
    }

    fn funding_state(wallet: &Wallet) -> FundingState {
        FundingState {
            receive: wallet.funding_receive,
            change: wallet.funding_change,
        }
    }

    fn funding_address(&self, wallet: &Wallet) -> Result<bitcoin::Address> {
        self.funding(wallet)?
            .receive_address(Self::funding_state(wallet))
    }

    /// Pay `outputs` from the wallet's fee coins, broadcast, and persist the
    /// address counters the payment advanced.
    fn pay(
        &self,
        wallet: &mut Wallet,
        name: &str,
        outputs: Vec<bitcoin::TxOut>,
        fee_rate: u64,
    ) -> Result<bitcoin::Transaction> {
        let publisher = self.publisher()?;
        let (tx, next) = self.funding(wallet)?.pay(
            publisher.as_ref(),
            Self::funding_state(wallet),
            outputs,
            fee_rate,
        )?;
        wallet.funding_receive = next.receive;
        wallet.funding_change = next.change;
        wallet.save(&self.wallet_path(name))?;
        publisher.broadcast(&tx)?;
        Ok(tx)
    }

    /// Commit and reveal from the wallet's fee coins (`docs/WITNESS-CARRIER.md` §3).
    fn publish_witness(
        &self,
        wallet: &mut Wallet,
        name: &str,
        envelope: &[u8],
        extra: Vec<bitcoin::TxOut>,
        fee_rate: u64,
    ) -> Result<bitcoin::Txid> {
        let publisher = self.publisher()?;
        let fw = self.funding(wallet)?;
        let key = fw.key(funding::Chain::Receive, 0)?;
        let (coins, st) = fw.coins(publisher.as_ref(), Self::funding_state(wallet))?;
        let p = witness::build_pair(
            &fw,
            &key,
            &coins,
            st,
            envelope,
            extra,
            None,
            fee_rate,
            self.btc_network(),
        )?;
        wallet.funding_receive = p.next.receive;
        wallet.funding_change = p.next.change;
        wallet.save(&self.wallet_path(name))?;
        let (c, r) = witness::broadcast(publisher.as_ref(), &p)?;
        println!(
            "commit {c} ({} vB), reveal {r} ({} vB): {} vB for the pair",
            p.commit.vsize(),
            p.reveal.vsize(),
            p.commit.vsize() + p.reveal.vsize()
        );
        Ok(r)
    }

    /// Write a carrier to the outbox and, unless `outbox_only`, publish it
    /// from the wallet's fee coins as the deployment's carrier says.
    #[allow(clippy::too_many_arguments)]
    fn publish(
        &self,
        wallet: &mut Wallet,
        name: &str,
        label: &str,
        entry: &OutboxEntry,
        fee_rate: u64,
        outbox_only: bool,
        relay: Option<&str>,
    ) -> Result<()> {
        let outbox = self.data_dir.join("outbox");
        std::fs::create_dir_all(&outbox)?;
        let envelope = hex::decode(&entry.envelope)?;
        let json_path = outbox.join(format!("{label}.json"));
        std::fs::write(&json_path, serde_json::to_string_pretty(entry)?)?;
        std::fs::write(outbox.join(format!("{label}.hex")), hex::encode(&envelope))?;
        println!(
            "envelope ({} bytes) written to {}",
            envelope.len(),
            json_path.display()
        );
        if outbox_only {
            println!("not broadcast (--no-broadcast)");
            return Ok(());
        }
        if let Some(url) = relay {
            let memo = entry.relay_memo()?;
            let txid = relay::submit(url, &envelope, memo.as_deref())?;
            println!("relayed by {url}: {txid}");
            return Ok(());
        }
        match self.deployment.carrier {
            CarrierMode::Witness => {
                self.publish_witness(wallet, name, &envelope, entry.extra_outputs()?, fee_rate)?;
            }
            CarrierMode::OpReturn => {
                let tx = self.pay(wallet, name, entry.outputs()?, fee_rate)?;
                println!("broadcast {} ({} vB)", tx.compute_txid(), tx.vsize());
            }
        }
        Ok(())
    }
}

fn print_status(idx: &Indexer) {
    let s = &idx.state;
    println!(
        "deployment {} ({:?}, family {}), activation {}",
        idx.deployment.name,
        idx.deployment.network,
        idx.deployment.family,
        idx.deployment.activation_height
    );
    println!(
        "replayed to {:?}, note tree size {}, nullifiers {}, accepted {}, rejected {}",
        s.last_height(),
        s.tree.size(),
        s.nullifiers.len(),
        s.events.len(),
        s.rejections.len()
    );
    for e in s.events.iter().rev().take(10) {
        println!(
            "  {:?} at {} tx {} leaves {}..{}",
            e.kind,
            e.height,
            e.tx_index,
            e.first_position,
            e.first_position + e.leaves.len() as u64
        );
    }
    for r in s.rejections.iter().rev().take(5) {
        println!("  rejected at {} tx {}: {}", r.height, r.tx_index, r.reason);
    }
}

fn print_wallet(w: &Wallet) {
    println!(
        "balance {} sat ({} notes, {} spent, {} locked)",
        w.balance(),
        w.notes.len(),
        w.notes.iter().filter(|n| n.spent_at.is_some()).count(),
        w.notes.iter().filter(|n| n.locked_by.is_some()).count()
    );
    for n in &w.notes {
        println!(
            "  pos {} value {} height {} {}{}",
            n.pos,
            n.value,
            n.height,
            if n.spent_at.is_some() {
                "spent"
            } else {
                "unspent"
            },
            if n.locked_by.is_some() {
                " (locked)"
            } else {
                ""
            }
        );
    }
    for s in &w.sent {
        println!(
            "  sent {} at {} {}",
            s.value,
            s.height,
            if s.is_change { "(change)" } else { "" }
        );
    }
}

/// The entry point `sb` delegates to for family A.
pub fn run(args: Vec<String>) -> Result<()> {
    let cli = Cli::parse_from(args);
    sb_common::net::set_proxy(cli.proxy.as_deref())?;

    if let Cmd::ProfileNew {
        name,
        network,
        activation,
        family,
        vault_script,
        operator_address,
        carrier,
        window,
        anchor_depth,
    } = &cli.cmd
    {
        if family != FAMILY {
            bail!("this build implements family {FAMILY}, not {family}");
        }
        let network = match network.as_str() {
            "signet" => SbNetwork::Signet,
            "testnet" => SbNetwork::Testnet,
            "regtest" => SbNetwork::Regtest,
            "mainnet" => bail!("mainnet is refused: this is development software"),
            other => bail!("unknown network {other}"),
        };
        if let Some(a) = operator_address {
            let (net, _) = PaymentAddress::decode(a).context("operator address")?;
            if net != network {
                bail!("operator address is for {net:?}, profile is {network:?}");
            }
        }
        eprintln!(
            "deriving the verifying key (k = {}) to pin its identifier…",
            sba_circuit::K
        );
        let verifier = sba_circuit::TransferVerifier::build()?;
        let d = Deployment {
            profile: sba_core::PROFILE_VERSION.into(),
            family: FAMILY.into(),
            name: name.clone(),
            network,
            activation_height: *activation,
            const_salt: Deployment::derive_const_salt(name),
            transfer_k: sba_circuit::K,
            transfer_vk_id: verifier.vk_id(),
            window_w: *window,
            k_min: 1,
            anchor_depth: *anchor_depth,
            boundary: vault_script.as_ref().map(|v| DevBoundary {
                vault_script_hex: v.clone(),
                operator_address: operator_address.clone(),
            }),
            carrier: match carrier {
                CarrierArg::OpReturn => CarrierMode::OpReturn,
                CarrierArg::Witness => CarrierMode::Witness,
            },
        };
        if let Some(p) = cli.profile.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(&cli.profile, d.to_json())?;
        println!("wrote {}", cli.profile.display());
        println!("{}", d.to_json());
        return Ok(());
    }

    let deployment = Deployment::load(&cli.profile)
        .with_context(|| format!("profile {}", cli.profile.display()))?;
    std::fs::create_dir_all(cli.data_dir.join("wallets"))?;
    let ctx = Ctx {
        passphrase_file: cli.passphrase_file.clone(),
        deployment,
        data_dir: cli.data_dir.clone(),
        chain: cli.chain.clone(),
        publish_via: cli.publish_via.clone(),
    };

    match cli.cmd {
        Cmd::ProfileNew { .. } => unreachable!(),
        Cmd::WalletNew { name, no_encrypt } => {
            let path = ctx.wallet_path(&name);
            if path.exists() {
                bail!("{} exists", path.display());
            }
            let mut w = Wallet::create(
                &mut rand::thread_rng(),
                ctx.deployment.network,
                &ctx.deployment.name,
            );
            if !no_encrypt {
                let pass = ctx.passphrase("Passphrase for the new wallet: ", true)?;
                w.set_passphrase(&pass, &mut rand::thread_rng())?;
            }
            w.save(&path)?;
            println!(
                "wallet {} written ({})",
                path.display(),
                if w.is_encrypted() {
                    "encrypted"
                } else {
                    "seed stored in plaintext"
                }
            );
            println!(
                "shielded address: {}",
                w.default_address().encode(ctx.deployment.network)
            );
            println!("funding address:  {}", ctx.funding_address(&w)?);
        }
        Cmd::WalletEncrypt { name } => {
            let mut w = ctx.wallet(&name)?;
            let pass = ctx.passphrase("New passphrase: ", true)?;
            w.set_passphrase(&pass, &mut rand::thread_rng())?;
            w.save(&ctx.wallet_path(&name))?;
            println!("wallet {name} encrypted (Argon2id + ChaCha20-Poly1305)");
        }
        Cmd::Address { name, new } => {
            let mut w = ctx.wallet(&name)?;
            let addr = if new {
                let (i, a) = w.new_address();
                w.funding_receive += 1;
                w.save(&ctx.wallet_path(&name))?;
                println!("receive path {i}, funding index {}", w.funding_receive);
                a
            } else {
                w.default_address()
            };
            println!("shielded address: {}", addr.encode(ctx.deployment.network));
            println!("funding address:  {}", ctx.funding_address(&w)?);
        }
        Cmd::Sync => {
            let (mut idx, mut store) = ctx.indexer()?;
            let light = ctx.light_source()?;
            let chain: Box<dyn ChainSource> = match &light {
                Some(l) => Box::new(l.clone()),
                None => ctx.chain_source()?,
            };
            if let Some(rest) = ctx.chain.strip_prefix("light:") {
                match rest.split_once('|') {
                    Some((url, full)) => {
                        println!("light sync from {url}: block hashes cross-checked against {full}")
                    }
                    None => println!(
                        "bare light sync from {rest}: the chain itself (tip and headers) is trusted from that indexer, proof of work is not validated; add |<full source> to cross-check block hashes"
                    ),
                }
            }
            let r = idx.sync_with(chain.as_ref(), Some(store.as_mut()))?;
            println!("{r:?}");
            if let Some(l) = light {
                let n =
                    l.verify_claims(|h| idx.root_at(h).map(|r| hex::encode(fp_to_bytes(&r))))?;
                println!("the indexer's claimed roots agree with local replay for {n} block(s)");
            }
            print_status(&idx);
        }
        Cmd::Serve {
            listen,
            max_requests,
        } => {
            let (indexer, store) = ctx.indexer()?;
            let chain = ctx.chain_source()?;
            let listener = std::net::TcpListener::bind(&listen)
                .with_context(|| format!("listen on {listen}"))?;
            println!(
                "indexer API on http://{} (deployment {}, family {}): GET /tip, /block/<height|hash>",
                listener.local_addr()?,
                ctx.deployment.name,
                FAMILY
            );
            std::io::Write::flush(&mut std::io::stdout())?;
            serve::Server {
                indexer,
                store,
                chain,
            }
            .serve(listener, max_requests)?;
        }
        Cmd::Status => print_status(&ctx.indexer()?.0),
        Cmd::Scan { name } => {
            let (idx, _store) = ctx.indexer()?;
            let mut w = ctx.wallet(&name)?;
            let n = w.scan(
                &ctx.deployment.const_salt_fp(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            w.save(&ctx.wallet_path(&name))?;
            println!("new notes: {n}");
            print_wallet(&w);
        }
        Cmd::Unlock { name } => {
            let mut w = ctx.wallet(&name)?;
            w.unlock_all();
            w.save(&ctx.wallet_path(&name))?;
            print_wallet(&w);
        }
        Cmd::Mint {
            name,
            amount,
            fee_rate,
            no_broadcast,
        } => {
            let boundary = ctx
                .deployment
                .boundary
                .clone()
                .ok_or_else(|| anyhow!("profile has no dev boundary"))?;
            let mut w = ctx.wallet(&name)?;
            let addr = w.default_address();
            let env = MintEnvelope {
                note: NotePlaintext {
                    value: amount,
                    d: addr.d,
                    rseed: Fp::random(&mut rand::thread_rng()),
                },
                pk_d: addr.pk_d,
            };
            let vault = bitcoin::ScriptBuf::from_bytes(hex::decode(&boundary.vault_script_hex)?);
            let extra = vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(amount),
                script_pubkey: vault,
            }];
            let label = format!(
                "mint-{}",
                hex::encode(&fp_to_bytes(&env.h_body(&ctx.deployment.const_salt))[..8])
            );
            let entry = OutboxEntry::new(&env.to_bytes(), extra);
            ctx.publish(&mut w, &name, &label, &entry, fee_rate, no_broadcast, None)?;
        }
        Cmd::Send {
            name,
            to,
            amount,
            fee_rate,
            no_broadcast,
            relay,
        } => {
            let (net, to_addr) = PaymentAddress::decode(&to)?;
            if net != ctx.deployment.network {
                bail!(
                    "address is for {:?}, profile is {:?}",
                    net,
                    ctx.deployment.network
                );
            }
            let (idx, _store) = ctx.indexer()?;
            let tip = idx
                .state
                .last_height()
                .ok_or_else(|| anyhow!("run `sb sync` first"))?;
            let h_anchor = anchor_for(tip, ctx.deployment.anchor_depth);
            let size = idx
                .state
                .size_at(h_anchor)
                .ok_or_else(|| anyhow!("anchor {h_anchor} not replayed"))?;
            let mut w = ctx.wallet(&name)?;
            w.scan(
                &ctx.deployment.const_salt_fp(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            eprintln!("deriving the proving key (k = {})…", sba_circuit::K);
            let params = ctx.deployment.params()?;
            eprintln!("proving (anchor {h_anchor}, tree size {size})…");
            let built = w.build_send(
                &params,
                &ctx.deployment.const_salt,
                &idx.state.tree,
                h_anchor,
                size,
                to_addr,
                amount,
                &mut rand::thread_rng(),
            )?;
            w.save(&ctx.wallet_path(&name))?;
            let label = format!(
                "transfer-{}",
                hex::encode(&fp_to_bytes(&built.statement.h_body)[..8])
            );
            let entry = OutboxEntry::new(&built.envelope.to_bytes(), vec![]);
            ctx.publish(
                &mut w,
                &name,
                &label,
                &entry,
                fee_rate,
                no_broadcast,
                relay.as_deref(),
            )?;
            println!("inputs locked until the transfer is accepted (`sb unlock` to release)");
        }
        Cmd::Withdraw {
            name,
            amount,
            to,
            fee_rate,
            no_broadcast,
            relay,
        } => {
            let boundary = ctx
                .deployment
                .boundary
                .clone()
                .ok_or_else(|| anyhow!("profile has no dev boundary"))?;
            let op = boundary
                .operator_address
                .ok_or_else(|| anyhow!("profile has no operator address"))?;
            let (net, op_addr) = PaymentAddress::decode(&op)?;
            if net != ctx.deployment.network {
                bail!("operator address network mismatch");
            }
            if amount < funding::DUST_LIMIT {
                bail!(
                    "withdraw amount {amount} is below the dust limit ({} sat); the operator could not pay it",
                    funding::DUST_LIMIT
                );
            }
            let dest: bitcoin::Address = to
                .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()?
                .require_network(ctx.btc_network())?;
            let memo = sba_wallet::build_payout_memo(amount, dest.script_pubkey().as_bytes());
            let (idx, _store) = ctx.indexer()?;
            let tip = idx
                .state
                .last_height()
                .ok_or_else(|| anyhow!("run `sb sync` first"))?;
            let h_anchor = anchor_for(tip, ctx.deployment.anchor_depth);
            let size = idx
                .state
                .size_at(h_anchor)
                .ok_or_else(|| anyhow!("anchor {h_anchor} not replayed"))?;
            let mut w = ctx.wallet(&name)?;
            w.scan(
                &ctx.deployment.const_salt_fp(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            eprintln!("deriving the proving key (k = {})…", sba_circuit::K);
            let params = ctx.deployment.params()?;
            eprintln!("proving withdraw of {amount} sat to {dest} (anchor {h_anchor})…");
            let built = w.build_send(
                &params,
                &ctx.deployment.const_salt,
                &idx.state.tree,
                h_anchor,
                size,
                op_addr,
                amount,
                &mut rand::thread_rng(),
            )?;
            w.save(&ctx.wallet_path(&name))?;
            let label = format!(
                "withdraw-{}",
                hex::encode(&fp_to_bytes(&built.statement.h_body)[..8])
            );
            let entry = OutboxEntry::new(&built.envelope.to_bytes(), vec![memo_output(&memo)]);
            ctx.publish(
                &mut w,
                &name,
                &label,
                &entry,
                fee_rate,
                no_broadcast,
                relay.as_deref(),
            )?;
            println!("the operator pays {dest} after the transfer is accepted");
        }
        Cmd::Payouts {
            name,
            fee_rate,
            no_broadcast,
        } => {
            let (idx, _store) = ctx.indexer()?;
            let mut w = ctx.wallet(&name)?;
            w.scan(
                &ctx.deployment.const_salt_fp(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            let pending = w.pending_payouts(&idx.state.events);
            println!("{} pending payout(s)", pending.len());
            for p in pending {
                let spk = bitcoin::ScriptBuf::from_bytes(p.request.script_pubkey.clone());
                let dest = bitcoin::Address::from_script(&spk, ctx.btc_network())
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| hex::encode(spk.as_bytes()));
                println!(
                    "  {} sat to {} (request in {})",
                    p.request.amount, dest, p.note.txid
                );
                if p.request.amount < funding::DUST_LIMIT {
                    println!(
                        "  refused: below the dust limit ({} sat); recorded as unpaid",
                        funding::DUST_LIMIT
                    );
                    w.record_payout(&p.note.txid, &p.request, None);
                    w.save(&ctx.wallet_path(&name))?;
                    continue;
                }
                if no_broadcast {
                    continue;
                }
                let out = bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(p.request.amount),
                    script_pubkey: spk,
                };
                let txid = ctx.pay(&mut w, &name, vec![out], fee_rate)?.compute_txid();
                println!("  paid in {txid}");
                w.record_payout(&p.note.txid, &p.request, Some(txid.to_string()));
                w.save(&ctx.wallet_path(&name))?;
            }
        }
        Cmd::Publish {
            label,
            name,
            fee_rate,
            relay,
        } => {
            let path = if label.contains('/') || label.ends_with(".json") {
                PathBuf::from(&label)
            } else {
                ctx.data_dir.join("outbox").join(format!("{label}.json"))
            };
            let text = std::fs::read_to_string(&path).with_context(|| {
                format!(
                    "{} (`sb <mint|send|withdraw> --no-broadcast` writes it)",
                    path.display()
                )
            })?;
            let entry: OutboxEntry = serde_json::from_str(&text)?;
            let label = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("carrier")
                .to_string();
            if let Some(url) = relay.as_deref() {
                // a relayer pays: no wallet of ours is involved
                let envelope = hex::decode(&entry.envelope)?;
                let memo = entry.relay_memo()?;
                let txid = relay::submit(url, &envelope, memo.as_deref())?;
                println!("relayed by {url}: {txid}");
            } else {
                let mut w = ctx.wallet(&name)?;
                ctx.publish(&mut w, &name, &label, &entry, fee_rate, false, None)?;
            }
        }
        Cmd::RelayServe {
            name,
            listen,
            fee_rate,
            max_per_hour,
            max_checks_per_minute,
            sync_interval,
            max_requests,
        } => {
            let (idx, store) = ctx.indexer()?;
            let chain = ctx.chain_source()?;
            let publisher = ctx.publisher()?;
            let w = ctx.wallet(&name)?;
            let fw = ctx.funding(&w)?;
            let listener = std::net::TcpListener::bind(&listen)
                .with_context(|| format!("listen on {listen}"))?;
            println!(
                "relayer listening on http://{} (deployment {}, family {}, wallet {name}, {fee_rate} sat/vB, {max_per_hour} carriers/hour, {max_checks_per_minute} checks/minute/address)",
                listener.local_addr()?,
                ctx.deployment.name,
                FAMILY
            );
            std::io::Write::flush(&mut std::io::stdout())?;
            let mut r = relay::Relayer::new(
                idx,
                store,
                chain,
                publisher,
                fw,
                w,
                ctx.wallet_path(&name),
                ctx.btc_network(),
                fee_rate,
                max_per_hour,
            );
            r.max_checks_per_minute = max_checks_per_minute;
            r.sync_interval = std::time::Duration::from_secs(sync_interval);
            r.serve(listener, max_requests)?;
        }
        Cmd::FundSend {
            name,
            to,
            amount,
            fee_rate,
        } => {
            let mut w = ctx.wallet(&name)?;
            let dest: bitcoin::Address = to
                .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()?
                .require_network(ctx.btc_network())?;
            let out = bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(amount),
                script_pubkey: dest.script_pubkey(),
            };
            let tx = ctx.pay(&mut w, &name, vec![out], fee_rate)?;
            println!(
                "paid {amount} sat to {dest} in {} ({} vB)",
                tx.compute_txid(),
                tx.vsize()
            );
        }
    }
    let _ = memo_output;
    Ok(())
}
