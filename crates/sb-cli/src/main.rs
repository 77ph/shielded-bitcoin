//! `sb`: Shielded Bitcoin wallet and indexer.
//!
//! ```text
//! sb --profile deployments/signet-dev.json --data-dir ./sb-data --chain esplora:https://mempool.space/signet/api <command>
//! ```

mod funding;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};

use sb_circuit::vk_sha256;
use sb_core::address::{Network as SbNetwork, PaymentAddress};
use sb_core::envelope::MintEnvelope;
use sb_core::note::NotePlaintext;
use sb_indexer::chain::esplora::Esplora;
use sb_indexer::chain::rpc::BitcoinCoreRpc;
use sb_indexer::deployment::DevBoundary;
use sb_indexer::{ChainSource, Deployment, Indexer, ReplayState, Setup};
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
    /// Block source: `esplora:<url>` or `rpc:<url>:<user>:<pass>` or `rpc-cookie:<url>:<cookie-path>`.
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
    /// Create a wallet.
    WalletNew {
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Show the wallet's shielded address (and the transparent funding address).
    Address {
        #[arg(long, default_value = "default")]
        name: String,
        /// Derive a fresh receive path.
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
        /// Publish through Esplora (default) or only write the envelope to the outbox.
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
        #[arg(long)]
        no_broadcast: bool,
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
        #[arg(long)]
        no_broadcast: bool,
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
    /// Release input locks left by unpublished transfers.
    Unlock {
        #[arg(long, default_value = "default")]
        name: String,
    },
}

struct Ctx {
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
        if let Some(url) = self.chain.strip_prefix("esplora:") {
            return Ok(Box::new(Esplora::new(url)));
        }
        if let Some(rest) = self.chain.strip_prefix("rpc-cookie:") {
            let (url, cookie) = rest
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("rpc-cookie:<url>:<cookie-path>"))?;
            return Ok(Box::new(BitcoinCoreRpc::with_cookie(
                url,
                Path::new(cookie),
            )?));
        }
        if let Some(rest) = self.chain.strip_prefix("rpc:") {
            let parts: Vec<&str> = rest.rsplitn(3, ':').collect();
            if parts.len() != 3 {
                bail!("rpc:<url>:<user>:<pass>");
            }
            return Ok(Box::new(BitcoinCoreRpc::new(parts[2], parts[1], parts[0])));
        }
        bail!("unknown chain spec {:?}", self.chain)
    }

    /// UTXO lookup and broadcast through the same backend as `--chain`.
    fn publisher(&self) -> Result<Box<dyn funding::Publisher>> {
        if let Some(url) = self.chain.strip_prefix("esplora:") {
            return Ok(Box::new(funding::EsploraPublisher::new(url)));
        }
        if let Some(rest) = self.chain.strip_prefix("rpc-cookie:") {
            let (url, cookie) = rest
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("rpc-cookie:<url>:<cookie-path>"))?;
            let rpc = BitcoinCoreRpc::with_cookie(url, Path::new(cookie))?;
            return Ok(Box::new(funding::RpcPublisher { rpc }));
        }
        if let Some(rest) = self.chain.strip_prefix("rpc:") {
            let parts: Vec<&str> = rest.rsplitn(3, ':').collect();
            if parts.len() != 3 {
                bail!("rpc:<url>:<user>:<pass>");
            }
            let rpc = BitcoinCoreRpc::new(parts[2], parts[1], parts[0]);
            return Ok(Box::new(funding::RpcPublisher { rpc }));
        }
        bail!("unknown chain spec {:?}", self.chain)
    }

    fn indexer(&self) -> Result<Indexer> {
        let verifier = self.deployment.verifier(&self.base_dir())?;
        let state = if self.state_path().exists() {
            ReplayState::load(&self.state_path())?
        } else {
            ReplayState::new()
        };
        Ok(Indexer::new(self.deployment.clone(), verifier, state))
    }

    fn wallet(&self, name: &str) -> Result<Wallet> {
        Wallet::load(&self.wallet_path(name))
            .with_context(|| format!("wallet {name} (run `sb wallet-new`)"))
    }

    fn btc_network(&self) -> bitcoin::Network {
        match self.deployment.network {
            SbNetwork::Mainnet => bitcoin::Network::Bitcoin,
            SbNetwork::Testnet => bitcoin::Network::Testnet,
            SbNetwork::Signet => bitcoin::Network::Signet,
            SbNetwork::Regtest => bitcoin::Network::Regtest,
        }
    }

    fn funding(&self, wallet: &Wallet) -> Result<funding::FundingKey> {
        let seed = hex::decode(wallet.seed_hex())?;
        funding::FundingKey::from_seed(&seed.try_into().unwrap(), self.btc_network())
    }

    /// Fund, sign and broadcast a carrier (or just write it to the outbox).
    fn publish(
        &self,
        wallet: &Wallet,
        label: &str,
        envelope: &[u8],
        extra: Vec<bitcoin::TxOut>,
        memo: Option<Vec<u8>>,
        fee_rate: u64,
        broadcast: bool,
    ) -> Result<()> {
        let outbox = self.data_dir.join("outbox");
        std::fs::create_dir_all(&outbox)?;
        let path = outbox.join(format!("{label}.hex"));
        std::fs::write(&path, hex::encode(envelope))?;
        println!(
            "envelope ({} bytes) written to {}",
            envelope.len(),
            path.display()
        );
        if !broadcast {
            return Ok(());
        }
        let publisher = self.publisher()?;
        let fk = self.funding(wallet)?;
        let utxos = publisher.utxos(&fk.address)?;
        let mut outputs = extra;
        outputs.push(sb_indexer::carrier::carrier_output(envelope));
        if let Some(m) = memo {
            outputs.push(sb_indexer::carrier::memo_output(&m));
        }
        let tx = fk.build_tx(&utxos, outputs, fee_rate)?;
        let txid = publisher.broadcast(&tx)?;
        println!("broadcast {} ({} vB)", txid, tx.vsize());
        Ok(())
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
        profile_path: cli.profile.clone(),
        deployment,
        data_dir: cli.data_dir.clone(),
        chain: cli.chain.clone(),
    };

    match cli.cmd {
        Cmd::ProfileNew { .. } => unreachable!(),
        Cmd::WalletNew { name } => {
            let path = ctx.wallet_path(&name);
            if path.exists() {
                bail!("{} exists", path.display());
            }
            let w = Wallet::create(
                &mut rand::thread_rng(),
                ctx.deployment.network,
                &ctx.deployment.name,
            );
            w.save(&path)?;
            println!(
                "wallet {} written (seed stored in plaintext)",
                path.display()
            );
            println!(
                "shielded address: {}",
                w.default_address().encode(ctx.deployment.network)
            );
            println!("funding address:  {}", ctx.funding(&w)?.address);
        }
        Cmd::Address { name, new } => {
            let mut w = ctx.wallet(&name)?;
            let addr = if new {
                let (i, a) = w.new_address();
                w.save(&ctx.wallet_path(&name))?;
                println!("receive path {i}");
                a
            } else {
                w.default_address()
            };
            println!("shielded address: {}", addr.encode(ctx.deployment.network));
            println!("funding address:  {}", ctx.funding(&w)?.address);
        }
        Cmd::Sync => {
            let mut idx = ctx.indexer()?;
            let chain = ctx.chain_source()?;
            let r = idx.sync(chain.as_ref())?;
            idx.state.save(&ctx.state_path())?;
            println!("{r:?}");
            print_status(&idx);
        }
        Cmd::Status => print_status(&ctx.indexer()?),
        Cmd::Scan { name } => {
            let idx = ctx.indexer()?;
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
            let w = ctx.wallet(&name)?;
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
            ctx.publish(
                &w,
                &label,
                &env.to_bytes(),
                extra,
                None,
                fee_rate,
                !no_broadcast,
            )?;
        }
        Cmd::Send {
            name,
            to,
            amount,
            fee_rate,
            no_broadcast,
        } => {
            let (net, to_addr) = PaymentAddress::decode(&to)?;
            if net != ctx.deployment.network {
                bail!(
                    "address is for {:?}, profile is {:?}",
                    net,
                    ctx.deployment.network
                );
            }
            let idx = ctx.indexer()?;
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
            ctx.publish(
                &w,
                &label,
                &built.envelope.to_bytes(),
                vec![],
                None,
                fee_rate,
                !no_broadcast,
            )?;
            println!("inputs locked until the transfer is accepted (`sb unlock` to release)");
        }
        Cmd::Withdraw {
            name,
            amount,
            to,
            fee_rate,
            no_broadcast,
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
            let dest: bitcoin::Address = to
                .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()?
                .require_network(ctx.btc_network())?;
            let memo = sb_wallet::build_payout_memo(amount, dest.script_pubkey().as_bytes());
            let idx = ctx.indexer()?;
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
            ctx.publish(
                &w,
                &label,
                &built.envelope.to_bytes(),
                vec![],
                Some(memo),
                fee_rate,
                !no_broadcast,
            )?;
            println!("the operator pays {dest} after the transfer is accepted");
        }
        Cmd::Payouts {
            name,
            fee_rate,
            no_broadcast,
        } => {
            let idx = ctx.indexer()?;
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
                if no_broadcast {
                    continue;
                }
                let publisher = ctx.publisher()?;
                let fk = ctx.funding(&w)?;
                let utxos = publisher.utxos(&fk.address)?;
                let out = bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(p.request.amount),
                    script_pubkey: spk,
                };
                let tx = fk.build_tx(&utxos, vec![out], fee_rate)?;
                let txid = publisher.broadcast(&tx)?;
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
