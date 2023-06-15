#![no_std]
use soroban_sdk::{contractimpl, BytesN, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    // Note that anyone can create a contract here with any salt, so a users call to
    // this could be frontrun and the same salt taken.
    pub fn create(e: Env, wasm_hash: BytesN<32>, salt: BytesN<32>) {
        e.deployer()
            .with_current_contract()
            .deploy(&salt, &wasm_hash);
    }
}
