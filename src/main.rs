extern crate bitcoin;
extern crate rand;
extern crate serde;
extern crate serde_json;
extern crate hex;
extern crate bloom;
extern crate chrono;

use bitcoin::util::address::Address;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::hashes::{sha256, ripemd160, Hash}; // Importando o trait Hash
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use std::env;
use bloom::{BloomFilter, ASMS};  // Importando o ASMS para acessar contains e insert

use chrono::Duration;
use tokio::task;
use num_bigint::{BigUint, RandBigInt};
use num_traits::Num;

const REPORT_INTERVAL: usize = 100_000;
const MAX_INSERTIONS_BEFORE_RESET: usize = 100_000_000;
const BLOOM_FILTER_SIZE: usize = 1_438_935_000;  // Aproximadamente 172 MB
const BLOOM_FILTER_HASHES: u32 = 10;             // 10 funções de hash

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

// Função para calcular o RIPEMD-160 a partir de uma chave privada
fn compute_ripemd160_from_private_key(private_key: &SecretKey, secp: &Secp256k1<bitcoin::secp256k1::All>) -> ripemd160::Hash {
    // Gerar chave pública a partir da chave privada
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(secp, private_key);
    
    // Fazer o hash SHA-256 da chave pública
    let sha256_hash = sha256::Hash::hash(&public_key.serialize()); // Usando serialize() no lugar de to_bytes()
    
    // Fazer o hash RIPEMD-160 do resultado do SHA-256
    ripemd160::Hash::hash(&sha256_hash)
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

    // Definir o tamanho padrão do range
   

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
    let num_threads = if num_cpus > 1 { num_cpus - 1 } else { 1 };

    let range_size: BigUint = BigUint::from_str_radix("500000", 16).unwrap();
    let total_range = &upper_bound - &lower_bound;

    println!("CPUs Detectadas: {}", num_cpus);
    println!("Usando {} threads (90%)", num_threads);

    let target_ripemd160 = match target_address.payload {
        bitcoin::util::address::Payload::PubkeyHash(ref hash) => *hash,
        _ => panic!("Endereço alvo inválido."),
    };

    // Substituir `ThreadRng` por `StdRng` que é `Send`
    let rng_mutex = Arc::new(Mutex::new(StdRng::from_entropy()));

    let mut tasks = vec![];

    for i in 0..num_threads {
        let total_checked = Arc::clone(&total_checked);
        let found = Arc::clone(&found);
        let print_once = Arc::clone(&print_once);
        let file_mutex = Arc::clone(&file_mutex);
        let bloom_filter = Arc::clone(&bloom_filter);
        let insertions = Arc::clone(&insertions);
        let rng_mutex = Arc::clone(&rng_mutex);
        let secp = secp.clone();
        let wallet = wallet.clone();
        let target_ripemd160 = target_ripemd160.clone();
        let lower_bound = lower_bound.clone();
        let upper_bound = upper_bound.clone();
        let range_size = range_size.clone();

        let task = task::spawn(async move {
            while !found.load(Ordering::Relaxed) {
                let thread_lower_bound: BigUint;
                let thread_upper_bound: BigUint;

                {
                    // Gerar o próximo range de forma aleatória e verificar se já está em uso
                    let mut rng = rng_mutex.lock().unwrap();
                    loop {
                        let range_start = rng.gen_biguint_range(&lower_bound, &upper_bound);
                        let range_end = std::cmp::min(range_start.clone() + range_size.clone(), upper_bound.clone());

                        let mut bloom = bloom_filter.lock().unwrap();

                        // Verifica se o range já foi testado com o Bloom Filter
                        if !bloom.contains(&range_start.to_bytes_be()) {
                            // Se não foi testado, adicionar ao Bloom Filter
                            bloom.insert(&range_start.to_bytes_be());

                            thread_lower_bound = range_start;
                            thread_upper_bound = range_end;
                            break;
                        }
                    }
                }

                println!("Thread {}: lower_bound = {}, upper_bound = {}", i, thread_lower_bound, thread_upper_bound);

                let mut current_key = thread_lower_bound.clone();

                while current_key <= thread_upper_bound && !found.load(Ordering::Relaxed) {
                    let private_key_hex = format!("{:x}", current_key);
                    let private_key_hex = if private_key_hex.len() % 2 != 0 {
                        format!("0{}", private_key_hex)
                    } else {
                        private_key_hex
                    };
                    let private_key_bytes = hex::decode(&private_key_hex).expect("Invalid hex string");

                    let mut padded_private_key_bytes = [0u8; 32];
                    let start_index = 32 - private_key_bytes.len();
                    padded_private_key_bytes[start_index..].copy_from_slice(&private_key_bytes);

                    let private_key = SecretKey::from_slice(&padded_private_key_bytes).unwrap();

                    // Gerar o RIPEMD-160 diretamente da chave privada
                    let ripemd160_hash = compute_ripemd160_from_private_key(&private_key, &secp);

                    // Verificar se o hash RIPEMD-160 gerado corresponde ao alvo
                    if ripemd160_hash == ripemd160::Hash::from_inner(target_ripemd160.into_inner()) {
                        found.store(true, Ordering::SeqCst);
                        if !print_once.swap(true, Ordering::SeqCst) {
                            let elapsed = start_time.elapsed();
                            let elapsed_duration = Duration::from_std(elapsed).unwrap();
                            let formatted_time = format_duration(elapsed_duration);
                            println!("Chave privada correspondente encontrada: {}\nTempo para encontrar a chave: {}", private_key_hex, formatted_time);
                        }
                        let _file_lock = file_mutex.lock().unwrap();
                        append_to_file(wallet_number, &wallet.address, &private_key_hex).expect("Unable to write to file");
                    }

                    let total = total_checked.fetch_add(1, Ordering::Relaxed) + 1;
                    if total % REPORT_INTERVAL == 0 {
                        let elapsed_time = start_time.elapsed().as_secs_f64();
                        let keys_per_second = total as f64 / elapsed_time;
                        println!("Chaves verificadas: {}, Chaves por segundo: {:.0}, Última chave verificada: {}, RIPEMD-160 gerado: {}, RIPEMD-160 alvo: {}", total, keys_per_second, private_key_hex, ripemd160_hash, target_ripemd160);
                    }

                    current_key += 1u8; // Incremento para chave sequencial

                    let insertion_count = insertions.fetch_add(1, Ordering::Relaxed) + 1;
                    if insertion_count >= MAX_INSERTIONS_BEFORE_RESET {
                        let mut filter = bloom_filter.lock().unwrap();
                        *filter = BloomFilter::with_size(BLOOM_FILTER_SIZE, BLOOM_FILTER_HASHES);
                        insertions.store(0, Ordering::Relaxed);
                    }
                }
            }
        });

        tasks.push(task);
    }

    for task in tasks {
        task.await.unwrap();
    }
}
