//! `sb`: Shielded Bitcoin wallet and indexer.
//!
//! ```text
//! sb --profile deployments/signet-dev.json --data-dir ./sb-data --chain esplora:https://mempool.space/signet/api <command>
//! ```

mod funding;
mod http;
mod relay;
mod serve;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use funding::FundingState;

use sb_circuit::vk_sha256;
use sb_core::address::{Network as SbNetwork, PaymentAddress};
use sb_core::envelope::MintEnvelope;
use sb_core::note::NotePlaintext;
use sb_indexer::chain::esplora::Esplora;
use sb_indexer::chain::light::LightSource;
use sb_indexer::chain::rpc::BitcoinCoreRpc;
use sb_indexer::deployment::DevBoundary;
use sb_indexer::{ChainSource, Deployment, Indexer, Setup};
use sb_wallet::{K_WALLET, Wallet, anchor_for};

#[derive(Parser)]
#[command(
    name = "sb",
    version,
    about = "Shielded Bitcoin wallet and indexer (pre-alpha, insecure setup)"
)]
struct Cli {
    /// Deployment profile JSON.
    #[arg(long, global = true, default_value = "deployments/signet-dev.json")]
    profile: PathBuf,
    /// Directory for indexer state and wallets.
    #[arg(long, global = true, default_value = "sb-data")]
    data_dir: PathBuf,
    /// PostgreSQL connection string for the indexer state (default: a JSON file in the data dir),
    /// e.g. `host=/var/run/postgresql dbname=shielded_bitcoin` or `postgresql://user:pass@host/db`.
    #[arg(long, global = true)]
    db: Option<String>,
    /// File holding the wallet passphrase (else `SB_WALLET_PASSPHRASE`, else a prompt).
    #[arg(long, global = true)]
    passphrase_file: Option<PathBuf>,
    /// Block source: `esplora:<url>`, `electrum:ssl://host:port` (or `ssl-pin://host:port/<sha256>`, `tcp://`),
    /// `rpc:<url>:<user>:<pass>`, `rpc-cookie:<url>:<cookie-path>`, or verified sync from an
    /// `sb serve` indexer: `light:<url>` (`light:<url>|<full source>` also checks block hashes there).
    #[arg(
        long,
        global = true,
        default_value = "esplora:https://mempool.space/signet/api"
    )]
    chain: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write a new deployment profile (runs the insecure setup to pin the vk hash).
    ProfileNew {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "signet")]
        network: String,
        #[arg(long)]
        activation: u32,
        /// Hex scriptPubKey of the dev vault; enables mints.
        #[arg(long)]
        vault_script: Option<String>,
        /// Operator's shielded address; enables withdrawals.
        #[arg(long)]
        operator_address: Option<String>,
        /// Setup seed (hex, 32 bytes); defaults to all zeros.
        #[arg(long)]
        setup_seed: Option<String>,
        #[arg(long, default_value = "100")]
        window: u32,
    },
    /// Create a wallet (encrypted unless --no-encrypt).
    WalletNew {
        #[arg(long, default_value = "default")]
        name: String,
        /// Store the seed in plaintext (development only).
        #[arg(long)]
        no_encrypt: bool,
    },
    /// Encrypt an existing plaintext wallet file (or change the passphrase).
    WalletEncrypt {
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Show the wallet's shielded address and the transparent funding address to pay fees from.
    Address {
        #[arg(long, default_value = "default")]
        name: String,
        /// Derive a fresh shielded receive path and a fresh funding address.
        #[arg(long)]
        new: bool,
    },
    /// Replay the chain into the local state.
    Sync,
    /// Indexer status.
    Status,
    /// Scan accepted history for the wallet's notes and print the balance.
    Scan {
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Mint `amount` sat into the wallet (dev boundary; pays the vault).
    Mint {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "2")]
        fee_rate: u64,
        /// Only write the carrier to the outbox (fund it elsewhere, or `sb publish` it later).
        #[arg(long)]
        no_broadcast: bool,
    },
    /// Build and publish a private payment.
    Send {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "2")]
        fee_rate: u64,
        /// Only write the carrier to the outbox (fund it elsewhere, or `sb publish` it later).
        #[arg(long)]
        no_broadcast: bool,
        /// Hand the envelope to a sponsored relayer (`http://host:port`) instead of paying the carrier.
        #[arg(long, conflicts_with = "no_broadcast")]
        relay: Option<String>,
    },
    /// Withdraw `amount` sat to a Bitcoin address through the dev operator.
    Withdraw {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        amount: u64,
        /// Destination Bitcoin address on the deployment's network.
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "2")]
        fee_rate: u64,
        /// Only write the carrier to the outbox (fund it elsewhere, or `sb publish` it later).
        #[arg(long)]
        no_broadcast: bool,
        /// Hand the envelope to a sponsored relayer (`http://host:port`) instead of paying the carrier.
        #[arg(long, conflicts_with = "no_broadcast")]
        relay: Option<String>,
    },
    /// Publish a carrier from the outbox: pay it from a wallet's fee coins, or hand it to a relayer.
    Publish {
        /// Outbox label (`transfer-…`, `mint-…`, `withdraw-…`) or a path to its `.json`.
        label: String,
        /// Wallet whose fee coins pay the carrier (any wallet, not only the sender's).
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long, default_value = "2")]
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
        #[arg(long, default_value = "2")]
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
    /// Operator: pay pending withdraw requests from the vault.
    Payouts {
        #[arg(long, default_value = "operator")]
        name: String,
        #[arg(long, default_value = "2")]
        fee_rate: u64,
        #[arg(long)]
        no_broadcast: bool,
    },
    /// Pay transparent coins from the wallet's funding address (e.g. to fund another wallet's fees).
    FundSend {
        #[arg(long, default_value = "default")]
        name: String,
        /// Destination Bitcoin address on the deployment's network.
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "1")]
        fee_rate: u64,
    },
    /// Show the TLS certificate fingerprint of an Electrum server for `ssl-pin://` (trust on first use).
    ElectrumFingerprint {
        /// `host:port`
        server: String,
    },
    /// Release input locks left by unpublished transfers.
    Unlock {
        #[arg(long, default_value = "default")]
        name: String,
    },
}

struct Ctx {
    db: Option<String>,
    passphrase_file: Option<PathBuf>,
    profile_path: PathBuf,
    deployment: Deployment,
    data_dir: PathBuf,
    chain: String,
}

impl Ctx {
    fn state_path(&self) -> PathBuf {
        self.data_dir
            .join(format!("state-{}.json", self.deployment.name))
    }

    fn wallet_path(&self, name: &str) -> PathBuf {
        self.data_dir.join("wallets").join(format!("{name}.json"))
    }

    fn base_dir(&self) -> PathBuf {
        self.profile_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }

    fn chain_source(&self) -> Result<Box<dyn ChainSource>> {
        match self.light_source()? {
            Some(l) => Ok(Box::new(l)),
            None => Self::full_source(&self.chain),
        }
    }

    /// `light:<url>[|<full source>]`: verified sync from an `sb serve`
    /// indexer, with block hashes cross-checked against the full source.
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

    fn full_source(spec: &str) -> Result<Box<dyn ChainSource>> {
        if let Some(url) = spec.strip_prefix("esplora:") {
            return Ok(Box::new(Esplora::new(url)));
        }
        if let Some(url) = spec.strip_prefix("electrum:") {
            return Ok(Box::new(sb_indexer::chain::electrum::Electrum::new(url)?));
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

    /// UTXO lookup and broadcast through the same backend as `--chain` (for
    /// `light:`, through its full source; a relayer needs none).
    fn publisher(&self) -> Result<Box<dyn funding::Publisher>> {
        let spec = match self.chain.strip_prefix("light:") {
            Some(rest) => match rest.split_once('|') {
                Some((_, full)) => full,
                None => bail!(
                    "light:<url> has no publisher: add |<full source> or publish through --relay"
                ),
            },
            None => self.chain.as_str(),
        };
        if let Some(url) = spec.strip_prefix("esplora:") {
            return Ok(Box::new(funding::EsploraPublisher::new(url)));
        }
        if let Some(url) = spec.strip_prefix("electrum:") {
            let electrum = sb_indexer::chain::electrum::Electrum::new(url)?;
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
        bail!("unknown chain spec {spec:?}")
    }

    fn store(&self) -> Result<Box<dyn sb_indexer::StateStore>> {
        Ok(match &self.db {
            Some(conn) => Box::new(sb_indexer::PgStore::connect(conn, &self.deployment.name)?),
            None => Box::new(sb_indexer::JsonStore::new(self.state_path())),
        })
    }

    fn indexer(&self) -> Result<(Indexer, Box<dyn sb_indexer::StateStore>)> {
        let verifier = self.deployment.verifier(&self.base_dir())?;
        let mut store = self.store()?;
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
            Err(sb_wallet::WalletError::PassphraseRequired) => {
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

    fn funding(&self, wallet: &Wallet) -> Result<funding::FundingWallet> {
        let seed = hex::decode(wallet.seed_hex())?;
        Ok(funding::FundingWallet::new(
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

    /// The funding address to show: the first receive index not used yet.
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
        // counters first: a crash after the broadcast must not reuse the
        // change address (an unused index is the harmless outcome)
        wallet.funding_receive = next.receive;
        wallet.funding_change = next.change;
        wallet.save(&self.wallet_path(name))?;
        publisher.broadcast(&tx)?;
        Ok(tx)
    }

    /// Write a carrier to the outbox and publish it as `mode` says; `payer`
    /// is the wallet (and its name) whose fee coins pay when self-funding.
    fn publish(
        &self,
        payer: Option<(&mut Wallet, &str)>,
        label: &str,
        entry: &OutboxEntry,
        fee_rate: u64,
        mode: PublishMode,
    ) -> Result<()> {
        let outbox = self.data_dir.join("outbox");
        std::fs::create_dir_all(&outbox)?;
        let envelope = hex::decode(&entry.envelope)?;
        let outputs = entry.outputs()?;
        let json_path = outbox.join(format!("{label}.json"));
        std::fs::write(&json_path, serde_json::to_string_pretty(entry)?)?;
        std::fs::write(outbox.join(format!("{label}.hex")), hex::encode(&envelope))?;
        let tx_path = outbox.join(format!("{label}.tx"));
        std::fs::write(&tx_path, unfunded_hex(&outputs))?;
        println!(
            "envelope ({} bytes) written to {}",
            envelope.len(),
            json_path.display()
        );
        match mode {
            PublishMode::Outbox => {
                println!("unfunded carrier (no inputs) in {}", tx_path.display());
                println!("publish it from any wallet, e.g. Bitcoin Core:");
                println!(
                    "  bitcoin-cli fundrawtransaction $(cat {0}) | jq -r .hex | xargs bitcoin-cli signrawtransactionwithwallet | jq -r .hex | xargs bitcoin-cli sendrawtransaction",
                    tx_path.display()
                );
                println!(
                    "or from an sb wallet holding fee coins:  sb publish {label} --name <wallet>"
                );
                if entry.extra.is_empty() {
                    println!(
                        "or through a sponsored relayer:         sb publish {label} --relay http://host:port"
                    );
                }
            }
            PublishMode::Relay(url) => {
                if !entry.extra.is_empty() {
                    bail!("a mint pays the vault; a relayer only publishes transfers");
                }
                let memo = entry.memo.as_deref().map(hex::decode).transpose()?;
                let txid = relay::submit(&url, &envelope, memo.as_deref())?;
                println!("relayed by {url}: {txid}");
            }
            PublishMode::SelfFund => {
                let (wallet, name) = payer.ok_or_else(|| anyhow!("no wallet to pay from"))?;
                let tx = self.pay(wallet, name, outputs, fee_rate)?;
                println!("broadcast {} ({} vB)", tx.compute_txid(), tx.vsize());
            }
        }
        Ok(())
    }
}

/// A transaction with these outputs and no inputs, framed the way Bitcoin
/// Core's `createrawtransaction` writes it (legacy framing: version, empty
/// input list, outputs, lock time). The segwit framing would put a marker
/// and flag where Core expects the input count, and Core rejects it.
fn unfunded_hex(outputs: &[bitcoin::TxOut]) -> String {
    use bitcoin::consensus::Encodable;
    let mut v = Vec::new();
    v.extend_from_slice(&2i32.to_le_bytes());
    v.push(0);
    bitcoin::VarInt(outputs.len() as u64)
        .consensus_encode(&mut v)
        .expect("vec");
    for o in outputs {
        o.consensus_encode(&mut v).expect("vec");
    }
    v.extend_from_slice(&0u32.to_le_bytes());
    hex::encode(v)
}

/// How a built carrier leaves the wallet.
enum PublishMode {
    /// Only the outbox: fund it elsewhere or `sb publish` it later.
    Outbox,
    /// Pay from this wallet's fee coins.
    SelfFund,
    /// Hand the envelope to a sponsored relayer at this URL.
    Relay(String),
}

impl PublishMode {
    #[cfg(test)]
    fn name(&self) -> &'static str {
        match self {
            PublishMode::Outbox => "outbox",
            PublishMode::SelfFund => "self-fund",
            PublishMode::Relay(_) => "relay",
        }
    }

    fn pick(no_broadcast: bool, relay: Option<String>) -> Self {
        match (no_broadcast, relay) {
            (true, _) => PublishMode::Outbox,
            (false, Some(url)) => PublishMode::Relay(url),
            (false, None) => PublishMode::SelfFund,
        }
    }
}

/// A carrier waiting in the outbox: the envelope, the optional payout memo
/// and the extra outputs the carrier must have (a mint's vault payment).
#[derive(Debug, Serialize, Deserialize)]
struct OutboxEntry {
    envelope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    memo: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extra: Vec<ExtraOutput>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExtraOutput {
    value: u64,
    script_hex: String,
}

impl OutboxEntry {
    fn new(envelope: &[u8], memo: Option<Vec<u8>>, extra: Vec<bitcoin::TxOut>) -> Self {
        OutboxEntry {
            envelope: hex::encode(envelope),
            memo: memo.map(hex::encode),
            extra: extra
                .into_iter()
                .map(|o| ExtraOutput {
                    value: o.value.to_sat(),
                    script_hex: hex::encode(o.script_pubkey.as_bytes()),
                })
                .collect(),
        }
    }

    /// Carrier outputs: the extra ones, the envelope, then the memo.
    fn outputs(&self) -> Result<Vec<bitcoin::TxOut>> {
        let mut out = Vec::new();
        for e in &self.extra {
            out.push(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(e.value),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(hex::decode(&e.script_hex)?),
            });
        }
        out.push(sb_indexer::carrier::carrier_output(&hex::decode(
            &self.envelope,
        )?));
        if let Some(m) = &self.memo {
            out.push(sb_indexer::carrier::memo_output(&hex::decode(m)?));
        }
        Ok(out)
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    if let Cmd::ProfileNew {
        name,
        network,
        activation,
        vault_script,
        operator_address,
        setup_seed,
        window,
    } = &cli.cmd
    {
        let seed: [u8; 32] = match setup_seed {
            Some(h) => hex::decode(h)?
                .try_into()
                .map_err(|_| anyhow!("seed must be 32 bytes"))?,
            None => [0u8; 32],
        };
        let network = match network.as_str() {
            "mainnet" => bail!("refusing to create a mainnet profile with an insecure setup"),
            "signet" => SbNetwork::Signet,
            "testnet" => SbNetwork::Testnet,
            "regtest" => SbNetwork::Regtest,
            other => bail!("unknown network {other}"),
        };
        eprintln!("running the insecure setup to pin the verifying key…");
        let params = sb_circuit::TransferParams::insecure_setup(&seed)?;
        let d = Deployment {
            profile: sb_core::PROFILE_VERSION.into(),
            name: name.clone(),
            network,
            activation_height: *activation,
            const_salt: Deployment::derive_const_salt(name),
            transfer_vk_sha256: vk_sha256(params.vk()),
            setup: Setup::InsecureSeed { seed },
            window_w: *window,
            k_min: 1,
            boundary: vault_script.as_ref().map(|v| DevBoundary {
                vault_script_hex: v.clone(),
                operator_address: operator_address.clone(),
            }),
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
        db: cli.db.clone(),
        passphrase_file: cli.passphrase_file.clone(),
        profile_path: cli.profile.clone(),
        deployment,
        data_dir: cli.data_dir.clone(),
        chain: cli.chain.clone(),
    };

    match cli.cmd {
        Cmd::ProfileNew { .. } => unreachable!(),
        Cmd::WalletEncrypt { name } => {
            let mut w = ctx.wallet(&name)?;
            let pass = ctx.passphrase("New passphrase: ", true)?;
            w.set_passphrase(&pass, &mut rand::thread_rng())?;
            w.save(&ctx.wallet_path(&name))?;
            println!("wallet {name} encrypted (Argon2id + ChaCha20-Poly1305)");
        }
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
            let r = idx.sync_with(chain.as_ref(), Some(store.as_mut()))?;
            println!("{r:?}");
            if let Some(l) = light {
                let n = l.verify_claims(&idx)?;
                println!("the indexer's claimed roots agree with local replay for {n} block(s)");
            }
            print_status(&idx);
        }
        Cmd::Status => print_status(&ctx.indexer()?.0),
        Cmd::Scan { name } => {
            let (idx, _store) = ctx.indexer()?;
            let mut w = ctx.wallet(&name)?;
            let n = w.scan(
                &ctx.deployment.const_salt_fr(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            w.save(&ctx.wallet_path(&name))?;
            println!("new notes: {n}");
            print_wallet(&w);
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
        Cmd::ElectrumFingerprint { server } => {
            let (host, port) = server
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("expected host:port"))?;
            let fp = sb_indexer::chain::electrum::Electrum::fingerprint(host, port.parse()?)?;
            println!("{}", hex::encode(fp));
            println!(
                "use: --chain electrum:ssl-pin://{host}:{port}/{}",
                hex::encode(fp)
            );
            println!("verify this fingerprint out of band before trusting it");
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
            let note = NotePlaintext {
                value: amount,
                d: addr.d,
                rseed: <sb_primitives::Fr as ark_ff::UniformRand>::rand(&mut rand::thread_rng()),
            };
            let env = MintEnvelope {
                note,
                pk_d: addr.pk_d,
            };
            let vault = bitcoin::ScriptBuf::from_bytes(hex::decode(&boundary.vault_script_hex)?);
            let extra = vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(amount),
                script_pubkey: vault,
            }];
            let label = format!(
                "mint-{}",
                hex::encode(
                    &sb_primitives::encoding::fr_to_bytes(&env.h_body(&ctx.deployment.const_salt))
                        [..8]
                )
            );
            let entry = OutboxEntry::new(&env.to_bytes(), None, extra);
            let mode = if no_broadcast {
                PublishMode::Outbox
            } else {
                PublishMode::SelfFund
            };
            ctx.publish(Some((&mut w, &name)), &label, &entry, fee_rate, mode)?;
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
            let h_anchor = anchor_for(tip, K_WALLET);
            let size = idx
                .state
                .size_at(h_anchor)
                .ok_or_else(|| anyhow!("anchor {h_anchor} not replayed"))?;
            let mut w = ctx.wallet(&name)?;
            w.scan(
                &ctx.deployment.const_salt_fr(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            eprintln!("loading proving parameters…");
            let params = ctx.deployment.params(&ctx.base_dir())?;
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
                hex::encode(&sb_primitives::encoding::fr_to_bytes(&built.statement.h_body)[..8])
            );
            let entry = OutboxEntry::new(&built.envelope.to_bytes(), None, vec![]);
            ctx.publish(
                Some((&mut w, &name)),
                &label,
                &entry,
                fee_rate,
                PublishMode::pick(no_broadcast, relay),
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
            let memo = sb_wallet::build_payout_memo(amount, dest.script_pubkey().as_bytes());
            let (idx, _store) = ctx.indexer()?;
            let tip = idx
                .state
                .last_height()
                .ok_or_else(|| anyhow!("run `sb sync` first"))?;
            let h_anchor = anchor_for(tip, K_WALLET);
            let size = idx
                .state
                .size_at(h_anchor)
                .ok_or_else(|| anyhow!("anchor {h_anchor} not replayed"))?;
            let mut w = ctx.wallet(&name)?;
            w.scan(
                &ctx.deployment.const_salt_fr(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            eprintln!("loading proving parameters…");
            let params = ctx.deployment.params(&ctx.base_dir())?;
            eprintln!("proving withdraw of {amount} sat to {dest}…");
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
                hex::encode(&sb_primitives::encoding::fr_to_bytes(&built.statement.h_body)[..8])
            );
            let entry = OutboxEntry::new(&built.envelope.to_bytes(), Some(memo), vec![]);
            ctx.publish(
                Some((&mut w, &name)),
                &label,
                &entry,
                fee_rate,
                PublishMode::pick(no_broadcast, relay),
            )?;
            println!("the operator pays {dest} after the transfer is accepted");
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
            // a relayer pays: no wallet of ours is involved
            let mut payer = match relay {
                Some(_) => None,
                None => Some(ctx.wallet(&name)?),
            };
            ctx.publish(
                payer.as_mut().map(|w| (w, name.as_str())),
                &label,
                &entry,
                fee_rate,
                PublishMode::pick(false, relay),
            )?;
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
                "indexer API on http://{} (deployment {}): GET /tip, /block/<height|hash>",
                listener.local_addr()?,
                ctx.deployment.name
            );
            std::io::stdout().flush()?;
            serve::Server {
                indexer,
                store,
                chain,
            }
            .serve(listener, max_requests)?;
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
                "relayer listening on http://{} (deployment {}, wallet {name}, {fee_rate} sat/vB, {max_per_hour} carriers/hour, {max_checks_per_minute} checks/minute/address)",
                listener.local_addr()?,
                ctx.deployment.name
            );
            std::io::stdout().flush()?;
            let mut r = relay::Relayer::new(
                idx,
                store,
                chain,
                publisher,
                fw,
                w,
                ctx.wallet_path(&name),
                fee_rate,
                max_per_hour,
            );
            r.max_checks_per_minute = max_checks_per_minute;
            r.sync_interval = std::time::Duration::from_secs(sync_interval);
            r.serve(listener, max_requests)?;
        }
        Cmd::Payouts {
            name,
            fee_rate,
            no_broadcast,
        } => {
            let (idx, _store) = ctx.indexer()?;
            let mut w = ctx.wallet(&name)?;
            w.scan(
                &ctx.deployment.const_salt_fr(),
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
    }
    Ok(())
}

fn print_status(idx: &Indexer) {
    let s = &idx.state;
    println!(
        "deployment {} ({:?}), activation {}",
        idx.deployment.name, idx.deployment.network, idx.deployment.activation_height
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The unfunded template decodes as Bitcoin Core's own framing: a
    /// 2-byte prefix of version + empty inputs, then the outputs, then the
    /// lock time, with no segwit marker.
    #[test]
    fn unfunded_template_uses_legacy_framing() {
        let out = sb_indexer::carrier::carrier_output(&[0xab; 10]);
        let hex = unfunded_hex(std::slice::from_ref(&out));
        let mut expect = String::from("02000000") + "00" + "01";
        expect += &hex::encode(bitcoin::consensus::encode::serialize(&out));
        expect += "00000000";
        assert_eq!(hex, expect);
        let entry = OutboxEntry::new(&[0xab; 10], Some(b"sbx\x01".to_vec()), vec![out]);
        assert_eq!(entry.outputs().unwrap().len(), 3);
        assert_eq!(PublishMode::pick(true, Some("x".into())).name(), "outbox");
        assert_eq!(PublishMode::pick(false, Some("x".into())).name(), "relay");
        assert_eq!(PublishMode::pick(false, None).name(), "self-fund");
    }
}
