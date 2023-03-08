#![allow(unused)]

use std::ptr::null;
use std::{collections::HashMap};
use std::marker::PhantomData;
use argon2::{self, Config};
use rand::{Rng, thread_rng};
use std::num::ParseIntError;


struct Locked;
struct Unlocked;

struct PasswordManagerEntry {
    used_for: String,
    password: String,
    username: String,
}

// PasswordManager<Locked> != PasswordManager<Unlocked>
struct PasswordManager<State = Locked> {
    master_pass_hash: String,
    entries: Vec<PasswordManagerEntry>,
    state: PhantomData<State>,
    salt: [u8;32],
}

impl PasswordManager<Locked> {
    pub fn unlock(self, master_pass: String) -> Option<PasswordManager<Unlocked>> {
        if !argon2::verify_encoded(&self.master_pass_hash, master_pass.as_bytes()).unwrap() {
            return None
        }

        Some(PasswordManager {
            master_pass_hash: self.master_pass_hash,
            entries: self.entries,
            state: PhantomData,
            salt: self.salt,
        })
    }
}

impl PasswordManager<Unlocked> {
    pub fn lock(self) -> PasswordManager<Locked> {
        PasswordManager {
            master_pass_hash: self.master_pass_hash,
            entries: self.entries,
            state: PhantomData,
            salt: self.salt,
        }
    }

    pub fn list_passwords(&self) -> &Vec<PasswordManagerEntry> {
        &self.entries
    }

    pub fn add_entry(&mut self, password_manager_entry: PasswordManagerEntry) {

        self.entries.push(password_manager_entry);
    }

    pub fn set_master_password(&self) {

    }
}

impl<State> PasswordManager<State> {
    pub fn encryption(&self, value: String) -> String {
        todo!()
    }


    pub fn version(&self) -> String {
        todo!()
    }
}

impl PasswordManager {
    pub fn new(master_pass: String) -> Self {
        let config = Config::default();
        let salt = thread_rng().gen::<[u8;32]>();
        let master_pass_hash = argon2::hash_encoded(master_pass.as_bytes(), &salt, &config).unwrap();

        PasswordManager {
            master_pass_hash,
            entries: Default::default(),
            state: PhantomData,
            salt,
        }
    }
}

fn main() {
    let mut manager = PasswordManager::new("password123".to_owned());

    
    let unlocked_manager = manager.unlock("password123".to_owned());

    match unlocked_manager {
        Some(manager) => println!("Logged in!"),
        None => println!("Wrong password!"),
    }

    // manager.list_passwords();
    // manager.lock();

    // let password = b"testingareally*&^&*$#oddpasswordsdafsad";
    // let salt = b"randomsalt";
    // let config = Config::default();
    // let hash = argon2::hash_encoded(password, salt, &config).unwrap();
    // let matches = argon2::verify_encoded(&hash, password).unwrap();
    // assert!(matches);
}