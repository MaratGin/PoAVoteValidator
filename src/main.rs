mod models;

use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::{env, io};
use std::collections::HashMap;
use std::io::{Read, Write};

use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::{ToRsaPrivateKey, ToRsaPublicKey}};
use rand::rngs::OsRng;
use tokio::sync::Mutex;
use crate::models::{Block, BlockHeader, Transaction};
use std::fs::{File, OpenOptions};
use std::time::{SystemTime, UNIX_EPOCH};
use actix_web::web::Data;


use openssl::rsa::Rsa;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::hash::MessageDigest;
use serde_json::json;
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize)]
pub struct GenesisBlock {
    index: u64,
    hash: String,
    timestamp: u128,
    election_name: String,
    election_description: String,
    users: Vec<String>,
    options: Vec<OptionInfo>,
    validators: Vec<String>,
    is_open: bool,
    is_multi: bool,
}

#[derive(Serialize, Deserialize)]
pub struct OptionInfo {
    pub index: u64,
    pub value: String,
}

struct AppState {
    genesis_block: Mutex<Option<GenesisBlock>>,
    validator_public_key: String,
    validator_private_key: PKey<Private>,
}

fn load_validator_public_key() -> io::Result<String> {
    let mut file = File::open("public_key.pem")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn load_validator_private_key() -> io::Result<PKey<Private>> {
    let mut file = File::open("private_key.pem")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let rsa = Rsa::private_key_from_pem(contents.as_bytes())?;
    Ok(PKey::from_rsa(rsa)?)
}

async fn receive_genesis_block(genesis_block: web::Json<GenesisBlock>) -> impl Responder {
    println!("GENESIS");
    let genesis_block = genesis_block.into_inner();
    let file_path = "genesis.json";
    let file = File::create(file_path);

    match file {
        Ok(mut file) => {
            let genesis_json = serde_json::to_string_pretty(&genesis_block).unwrap();
            if let Err(err) = file.write_all(genesis_json.as_bytes()) {
                return HttpResponse::InternalServerError().body(format!("Failed to write to file: {}", err));
            }
        },
        Err(err) => {
            return HttpResponse::InternalServerError().body(format!("Failed to create file: {}", err));
        }
    }

    HttpResponse::Ok().body("Genesis block received and saved")
}

async fn get_votes_by_user(query: web::Query<HashMap<String, String>>) -> impl Responder {
    // println!("TEST");
    let user_name = match query.get("user_name") {
        Some(name) => name.clone(),
        None => return HttpResponse::BadRequest().body("Missing user_name parameter"),
    };

    // Чтение JSON-файла
    let file_path = "genesis.json";
    let mut file = match File::open(file_path) {
        Ok(file) => file,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to open genesis block file"),
    };

    let mut contents = String::new();
    if let Err(_) = file.read_to_string(&mut contents) {
        return HttpResponse::InternalServerError().body("Failed to read genesis block file");
    }

    let genesis_block: GenesisBlock = match serde_json::from_str(&contents) {
        Ok(block) => block,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to parse genesis block file"),
    };

    // Проверка, есть ли имя пользователя в списке users
    if genesis_block.users.contains(&user_name) {
        HttpResponse::Ok().body(genesis_block.election_name)
    } else {
        HttpResponse::NotFound().body("User not found in genesis block")
    }
}


fn generate_rsa_keys() -> (RsaPrivateKey, RsaPublicKey) {
    // Генерация приватного ключа
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Ошибка при генерации ключа");
    // Извлечение публичного ключа из приватного
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

fn calculate_and_sign_hash(header: &BlockHeader, private_key: &PKey<Private>) -> String {
    let header_json = serde_json::to_string(header).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(header_json.as_bytes());
    let hash = hasher.finalize();

    let mut signer = Signer::new(MessageDigest::sha256(), private_key).unwrap();
    signer.update(&hash).unwrap();
    let signature = signer.sign_to_vec().unwrap();

    base64::encode(signature)
}


fn save_key_to_file(filename: &str, key: &str) -> io::Result<()> {
    // сохраняем ключ в файл
    let mut file = File::create(filename)?;
    file.write_all(key.as_bytes())?;
    Ok(())
}

async fn handle_vote(data: web::Data<AppState>, vote: web::Json<Transaction>) -> impl Responder {
    let mut blocks = load_blocks().unwrap_or_else(|_| vec![]);
    let previous_block_hash = if let Some(last_block) = blocks.last() {
        &last_block.hash
    } else {
        "0"
    }.to_string();

    let new_transaction = Transaction {
        voter: vote.voter.clone(),
        choice: vote.choice.clone(),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
    };

    let new_block_header = BlockHeader {
        previous_block_hash: previous_block_hash.clone(),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        transactions: vec![new_transaction],
    };

    let new_block_hash = calculate_and_sign_hash(&new_block_header, &data.validator_private_key);

    let new_block = Block {
        header: new_block_header,
        hash: new_block_hash,
        validator_public_key: data.validator_public_key.clone(),
    };

    blocks.push(new_block);

    match save_blocks(&blocks) {
        Ok(_) => HttpResponse::Ok().body("Vote received and block added"),
        Err(err) => HttpResponse::InternalServerError().body(format!("Failed to save blocks: {}", err)),
    }
}

async fn get_history() -> impl Responder {
    match load_blocks() {
        Ok(blocks) => {
            let history: Vec<_> = blocks.iter().flat_map(|block| {
                block.header.transactions.iter().map(move |tx| {
                    json!({
                        "voter": tx.voter,
                        "choice": tx.choice.to_string(),
                        "hash": block.hash,
                    })
                })
            }).collect();
            HttpResponse::Ok().json(history)
        },
        Err(err) => HttpResponse::InternalServerError().body(format!("Failed to load blocks: {}", err)),
    }
}

fn load_blocks() -> io::Result<Vec<Block>> {
    let file_path = "blocks.json";
    let mut file = OpenOptions::new().read(true).open(file_path)?;

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let blocks: Vec<Block> = serde_json::from_str(&contents)?;
    Ok(blocks)
}

fn save_blocks(blocks: &Vec<Block>) -> io::Result<()> {
    let file_path = "blocks.json";
    let mut file = OpenOptions::new().write(true).truncate(true).create(true).open(file_path)?;

    let blocks_json = serde_json::to_string_pretty(blocks)?;
    write!(file, "{}", blocks_json)?;

    Ok(())
}

fn calculate_hash(header: &BlockHeader) -> String {
    let header_json = serde_json::to_string(header).unwrap();
    format!("{:x}", md5::compute(header_json))
}


#[tokio::main]
async fn main() -> std::io::Result<()>{
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    // Генерация RSA ключей
    let (private_key, public_key) = generate_rsa_keys();

    // Приватный ключ
    let private_key_pem = private_key.to_pkcs1_pem().expect("Ошибка в получении приватного ключа");
    // println!("Private Key:\n{:?}", private_key_pem);

    // Публичный ключ
    let public_key_pem = public_key.to_pkcs1_pem().expect("Ошибка в получении публичного ключа");
    // println!("Public Key:\n{}", public_key_pem);
    let validator_public_key = load_validator_public_key()
        .expect("Failed to load validator public key");

    let validator_private_key = load_validator_private_key()
        .expect("Failed to load validator private key");

    let state = web::Data::new(AppState {
        genesis_block: Mutex::new(None),
        validator_public_key,
        validator_private_key,
    });

    let port = env::var("SERVER_PORT")
        .unwrap_or_else(|_| "9095".to_string())
        .parse::<u16>()
        .expect("SERVER_PORT must be a valid u16");

    println!("PORT:\n{}", port);


    // Сохраняем ключи локально
    save_key_to_file("private_key.pem", &private_key_pem).expect("Не удалось сохранить");
    save_key_to_file("public_key.pem", &public_key_pem).expect("Не удалось сохранить");
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/genesis", web::post().to(receive_genesis_block))
            .route("/getVotes", web::get().to(get_votes_by_user))
            .route("/vote", web::post().to(handle_vote))
            .route("/getHistory", web::get().to(get_history))


    })
        .bind("127.0.0.1:10040")?
        // .bind(("127.0.0.1", port))?


        .run()
        .await
}


