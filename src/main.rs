extern crate bitcoin;
extern crate rand;
extern crate serde;
extern crate serde_json;
extern crate hex;
extern crate bloom;
extern crate chrono;

use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::key::PrivateKey;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use std::env;
use bloom::{BloomFilter, ASMS};
use chrono::Duration;
use tokio::task;
use num_bigint::{BigUint, RandBigInt};
use num_traits::Num;

const REPORT_INTERVAL: usize = 100_000;
const MAX_INSERTIONS_BEFORE_RESET: usize = 100_000_000;
const BLOOM_FILTER_SIZE: usize = 958_505_839;
const BLOOM_FILTER_HASHES: u32 = 7;

#[derive(Serialize, Deserialize, Clone)]
struct Wallet {
    numero: u32,
    lowerbound: String,
    upperbound: String,
    address: String,
}

#[derive(Serialize, Deserialize)]
struct Wallets {
    wallets: Vec<Wallet>,
}

fn load_wallets() -> Wallets {
    let path = env::var("WALLETS_PATH").unwrap_or("./src/wallets.json".to_string());
    let mut file = File::open(&path).expect("File not found");
    let mut data = String::new();
    file.read_to_string(&mut data).expect("Unable to read string");
    serde_json::from_str(&data).expect("JSON was not well-formatted")
}

fn append_to_file(wallet_number: u32, address: &str, private_key: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("found_keys.txt")?;
    writeln!(file, "Carteira número: {}, Endereço: {}, Chave privada: {}", wallet_number, address, private_key)?;
    Ok(())
}

fn hex_to_bytes(hex: &str) -> [u8; 32] {
    let hex = if hex.len() % 2 != 0 {
        format!("0{}", hex)
    } else {
        hex.to_string()
    };
    
    let mut bytes = [0u8; 32];
    let hex_bytes = hex::decode(&hex).expect("Invalid hex string");
    for (i, byte) in hex_bytes.iter().enumerate() {
        bytes[32 - hex_bytes.len() + i] = *byte;
    }
    bytes
}

fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn format_duration(duration: Duration) -> String {
    let days = duration.num_days();
    let hours = duration.num_hours() % 24;
    let minutes = duration.num_minutes() % 60;
    let seconds = duration.num_seconds() % 60;

    format!(
        "{} days, {} hours, {} minutes, {} seconds",
        days, hours, minutes, seconds
    )
}

fn generate_random_biguint_in_range(rng: &mut impl Rng, lower_bound: &BigUint, upper_bound: &BigUint) -> BigUint {
    let range = upper_bound - lower_bound;
    rng.gen_biguint_below(&range) + lower_bound
}

fn precompute_public_key(private_key: &SecretKey, secp: &Secp256k1<bitcoin::secp256k1::All>) -> Address {
    let public_key = bitcoin::util::key::PublicKey {
        compressed: true,
        key: bitcoin::secp256k1::PublicKey::from_secret_key(secp, private_key),
    };
    Address::p2pkh(&public_key, Network::Bitcoin)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} --carteira=<number>", args[0]);
        return;
    }

    let wallet_number: u32 = args[1].split('=').nth(1).expect("Invalid argument format").parse().expect("Invalid wallet number");

    let wallets = load_wallets();
    let wallet = wallets.wallets.into_iter().find(|w| w.numero == wallet_number).expect("Wallet not found");

    let lower_bound = BigUint::from_str_radix(&wallet.lowerbound, 16).unwrap();
    let upper_bound = BigUint::from_str_radix(&wallet.upperbound, 16).unwrap();

    let target_address = Address::from_str(&wallet.address).unwrap();
    let secp = Secp256k1::new();

    let total_checked = Arc::new(AtomicUsize::new(0));
    let found = Arc::new(AtomicBool::new(false));
    let start_time = Instant::now();
    let print_once = Arc::new(AtomicBool::new(false));
    
    let file_mutex = Arc::new(Mutex::new(()));
    let bloom_filter = Arc::new(Mutex::new(BloomFilter::with_size(BLOOM_FILTER_SIZE, BLOOM_FILTER_HASHES)));
    let insertions = Arc::new(AtomicUsize::new(0));

    let num_cpus = num_cpus::get();
    let num_threads = (num_cpus as f64 * 0.9).ceil() as usize;

    println!("CPUs Detectadas: {}", num_cpus);
    println!("Usando {} threads (90%)", num_threads);

    let range_per_thread = (upper_bound.clone() - lower_bound.clone()) / num_threads;

    let mut tasks = vec![];

    for i in 0..num_threads {
        let total_checked = Arc::clone(&total_checked);
        let found = Arc::clone(&found);
        let print_once = Arc::clone(&print_once);
        let file_mutex = Arc::clone(&file_mutex);
        let bloom_filter = Arc::clone(&bloom_filter);
        let insertions = Arc::clone(&insertions);
        let lower_bound = lower_bound.clone() + (i * &range_per_thread);
        let upper_bound = if i == num_threads - 1 {
            upper_bound.clone()
        } else {
            lower_bound.clone() + &range_per_thread
        };

        println!("Thread {}: lower_bound = {}, upper_bound = {}", i, lower_bound, upper_bound);

        let target_address = target_address.clone();
        let secp = secp.clone();
        let wallet = wallet.clone();

        let task = task::spawn(async move {
            let mut rng = rand::thread_rng();

            while !found.load(Ordering::Relaxed) {
                let random_key = generate_random_biguint_in_range(&mut rng, &lower_bound, &upper_bound);

                let mut private_key_hex = format!("{:x}", random_key);

                if private_key_hex.len() % 2 != 0 {
                    private_key_hex = format!("0{}", private_key_hex);
                }

                let private_key_bytes = hex::decode(&private_key_hex).expect("Invalid hex string");

                let mut padded_private_key_bytes = [0u8; 32];
                let start_index = 32 - private_key_bytes.len();
                padded_private_key_bytes[start_index..].copy_from_slice(&private_key_bytes);

                let private_key = SecretKey::from_slice(&padded_private_key_bytes).unwrap();
                let generated_address = precompute_public_key(&private_key, &secp);

                let mut new_key = false;
                {
                    let mut filter = bloom_filter.lock().unwrap();
                    if !filter.contains(&private_key_hex) {
                        filter.insert(&private_key_hex);
                        new_key = true;
                    }
                }

                if new_key {
                    if generated_address == target_address {
                        found.store(true, Ordering::SeqCst);
                        if !print_once.swap(true, Ordering::SeqCst) {
                            let elapsed = start_time.elapsed();
                            let elapsed_duration = Duration::from_std(elapsed).unwrap();
                            let formatted_time = format_duration(elapsed_duration);
                            println!("Found matching private key: {}\nTime to find the key: {}", private_key_hex, formatted_time);
                        }
                        let _file_lock = file_mutex.lock().unwrap();
                        append_to_file(wallet_number, &wallet.address, &private_key_hex).expect("Unable to write to file");
                    }

                    let total = total_checked.fetch_add(1, Ordering::Relaxed) + 1;
                    if total % REPORT_INTERVAL == 0 {
                        let elapsed_time = start_time.elapsed().as_secs_f64();
                        let keys_per_second = total as f64 / elapsed_time;
                        println!("Keys checked: {}, Keys per second: {:.0}, Last key checked: {}, Last generated address: {}, Target Address: {}", total, keys_per_second, private_key_hex, generated_address, target_address);
                    }
                }

                let insertion_count = insertions.fetch_add(1, Ordering::Relaxed) + 1;
                if insertion_count >= MAX_INSERTIONS_BEFORE_RESET {
                    let mut filter = bloom_filter.lock().unwrap();
                    *filter = BloomFilter::with_size(BLOOM_FILTER_SIZE, BLOOM_FILTER_HASHES);
                    insertions.store(0, Ordering::Relaxed);
                }
            }
        });

        tasks.push(task);
    }

    for task in tasks {
        task.await.unwrap();
    }
}
