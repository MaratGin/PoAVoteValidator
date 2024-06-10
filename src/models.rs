use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Transaction {
    pub voter: String,
    pub choice: String,
    pub timestamp: u128,
}

#[derive(Serialize, Deserialize)]
pub struct BlockHeader {
    pub previous_block_hash: String,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
}

#[derive(Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub hash: String,
    pub validator_public_key: String,
}