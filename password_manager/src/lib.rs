#![allow(unused)]

use std::clone;
use std::io::stdin;
use std::ptr::null;
use std::{collections::HashMap};
use std::marker::PhantomData;
use argon2::{self, Config};
use rand::{Rng, thread_rng};
use std::num::ParseIntError;
use rusqlite::{Connection, Result};
use rusqlite::NO_PARAMS;


#[derive(Clone, PartialEq)]
pub struct PasswordManagerEntry {
    name: String,
    username: String,
    password: String,
}

// PasswordManager<Locked> != PasswordManager<Unlocked
#[derive(Clone, PartialEq)]
pub struct PasswordManager<State: ManagerState> {
    master_pass_hash: String,
    entries: Vec<PasswordManagerEntry>,
    state: PhantomData<State>,
    salt: [u8;32],
}

pub enum Locked {}
pub enum Unlocked {}

pub trait ManagerState {}
impl ManagerState for Locked {}
impl ManagerState for Unlocked {}

impl PasswordManager<Locked> {
    pub fn unlock(self, master_pass: &String) -> Option<PasswordManager<Unlocked>> {
        if !self.is_master_password(master_pass) {
            return None
        }

        Some(PasswordManager {
            master_pass_hash: self.master_pass_hash,
            entries: self.entries,
            state: PhantomData,
            salt: self.salt,
        })
    }

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

impl PasswordManager<Unlocked> {
    pub fn lock(self) -> PasswordManager<Locked> {
        PasswordManager {
            master_pass_hash: self.master_pass_hash,
            entries: self.entries,
            state: PhantomData,
            salt: self.salt,
        }
    }

    pub fn list_entries(&self) -> &Vec<PasswordManagerEntry> {
        &self.entries
    }

    pub fn add_entry(&mut self, password_manager_entry: PasswordManagerEntry) {
        self.entries.push(password_manager_entry);
    }

    pub fn reset_master_password(self, current_password: &String, new_master_password: &String) -> Option<PasswordManager<Unlocked>> {
        if !self.is_master_password(current_password) {
            return None
        }

        let config = Config::default();
        let salt = thread_rng().gen::<[u8;32]>();
        let master_pass_hash = argon2::hash_encoded(new_master_password.as_bytes(), &salt, &config).unwrap();


        Some(PasswordManager {
            master_pass_hash,
            entries: self.entries,
            state: PhantomData,
            salt: self.salt,
        })
    }
}

impl<State: ManagerState> PasswordManager<State> {
    fn is_master_password(&self, master_pass: &String) -> bool {
        return argon2::verify_encoded(&self.master_pass_hash, master_pass.as_bytes()).unwrap();
    }

    fn get_database_connection(&self) -> Connection {
        // TODO: This could be safer
        Connection::open(self.master_pass_hash.clone() + ".db").unwrap()
    }
}

// #################################################
// #################     TESTS     ################# 
// #################################################

#[cfg(test)]
mod tests {
    use crate::{PasswordManager, Unlocked, PasswordManagerEntry};

    fn create_unlocked_password_manager() -> PasswordManager<Unlocked> {
        let manager = PasswordManager::new("correct_password".to_owned());
        let result: PasswordManager<Unlocked> = manager.unlock(&"correct_password".to_string()).unwrap();
        
        result
    }

    #[test]
    fn test_unlock_invalid_password() {
        let manager = PasswordManager::new("test_pass".to_owned());
        let result = manager.unlock(&"wrong_password".to_string());

        assert!(result.is_none());
    }

    #[test]
    fn test_unlock_valid_password() {
        let manager = PasswordManager::new("correct_password".to_owned());
        let result = manager.unlock(&"correct_password".to_string());

        assert!(result.is_some());
    }

    #[test]
    fn test_lock() {
        let manager = PasswordManager::new("correct_password".to_owned());
        let result = manager.unlock(&"correct_password".to_string());

        match result {
            Some(result) => {
                result.lock();
            },
            None => { assert!(false) }
        }
    }

    #[test]
    fn test_list_entries() {
        let mut unlocked_manager = create_unlocked_password_manager(); 

        let entries = unlocked_manager.list_entries();

        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_add_entry() {
        let mut unlocked_manager = create_unlocked_password_manager();

        let password_manager_entry = PasswordManagerEntry {
            name: String::from("test_name"),
            username: String::from("test_username"),
            password: String::from("test_password"), 
        };

        
        unlocked_manager.add_entry(password_manager_entry);

        let entries = unlocked_manager.list_entries();

        assert_eq!(entries.len(), 1);
        
        let entry = entries.get(0).unwrap();

        assert_eq!(entry.name, "test_name");
        assert_eq!(entry.username, "test_username");
        assert_eq!(entry.password, "test_password");
    }

}