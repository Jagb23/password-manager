#![allow(unused)]

use std::clone;
use std::io::stdin;
use std::ptr::null;
use std::{collections::HashMap};
use std::marker::PhantomData;
use argon2::{self, Config};

use std::num::ParseIntError;
use database::{PasswordManagerEntry, Database, User};

// PasswordManager<Locked> != PasswordManager<Unlocked
#[derive(Debug, Clone)]
pub struct PasswordManager<State: ManagerState> {
    username: String,
    master_pass_hash: String,
    entries: Vec<PasswordManagerEntry>,
    state: PhantomData<State>,
    database: Database,
}

pub enum Locked {}
pub enum Unlocked {}

pub trait ManagerState {}
impl ManagerState for Locked {}
impl ManagerState for Unlocked {}

impl PasswordManager<Locked> {
    pub fn unlock(self, username: &String, master_pass: &String) -> Option<PasswordManager<Unlocked>> {
        if !self.is_master_password(username, master_pass) {
            return None
        }

        let user = self.database.get_user(username).unwrap();

        Some(PasswordManager {
            username: user.username,
            master_pass_hash: user.pw_hash,
            entries: Vec::new(),
            state: PhantomData,
            database: self.database
        })
    }
}

impl PasswordManager<Unlocked> {
    pub fn lock(self) -> PasswordManager<Locked> {
        // Wipe any user data and return to locked state
        PasswordManager {
            username: String::new(),
            master_pass_hash: String::new(),
            entries: Vec::new(),
            state: PhantomData,
            database: self.database,
        }
    }

    pub fn list_entries(&self) -> &Vec<PasswordManagerEntry> {
        &self.entries
    }

    pub fn add_entry(&mut self, password_manager_entry: PasswordManagerEntry) {
        self.entries.push(password_manager_entry);
    }

    pub fn reset_master_password(self, current_password: &String, new_master_password: &String) -> Option<PasswordManager<Unlocked>> {
        if !self.is_master_password(&self.username, current_password) {
            return None
        }

        self.database.update_user_password(&self.username, &new_master_password);

        let user = self.database.get_user(&self.username).unwrap();

        Some(PasswordManager {
            username: self.username,
            master_pass_hash: user.pw_hash, // update the password hash
            entries: self.entries,
            state: PhantomData,
            database: self.database,
        })
    }

}

impl<State: ManagerState> PasswordManager<State> {

    // pub fn new(username: &String, master_pass: &String) -> Self {
    //     let config = Config::default();
    //     let salt = thread_rng().gen::<[u8;32]>();
    //     let master_pass_hash = argon2::hash_encoded(master_pass.as_bytes(), &salt, &config).unwrap();
    //     let database = Database::new();

    //     let pm = PasswordManager {
    //         master_pass_hash,
    //         entries: Default::default(),
    //         state: PhantomData,
    //         salt,
    //         database,
    //     };

    //     pm
    // }

    pub fn new() -> Self {
        PasswordManager { 
            username: String::new(),
            master_pass_hash: String::new(),
            entries: Vec::new(),
            state: PhantomData,
            database: Database::new(), 
        }
    }

    fn is_master_password(self, username: &String, master_pass: &String) -> bool {

        // let user = user_db.get_user(username).unwrap();
        let user = self.database.get_user(username).unwrap();
        
        return argon2::verify_encoded(&user.pw_hash, master_pass.as_bytes()).unwrap();
    }
}

// #################################################
// #################     TESTS     ################# 
// #################################################

#[cfg(test)]
mod tests {
    use crate::{PasswordManager, Unlocked, PasswordManagerEntry};

    fn create_unlocked_password_manager() -> PasswordManager<Unlocked> {
        let manager = PasswordManager::new();
        let result: PasswordManager<Unlocked> = manager.unlock(&"test_username".to_string(), &"correct_password".to_string()).unwrap();
        
        result
    }

    // #[test]
    // fn test_unlock_invalid_password() {
    //     let manager = PasswordManager::new("test_pass".to_owned());
    //     let result = manager.unlock(&"wrong_password".to_string());

    //     assert!(result.is_none());
    // }

    // #[test]
    // fn test_unlock_valid_password() {
    //     let manager = PasswordManager::new("correct_password".to_owned());
    //     let result = manager.unlock(&"correct_password".to_string());

    //     assert!(result.is_some());
    // }

    // #[test]
    // fn test_lock() {
    //     let manager = PasswordManager::new("correct_password".to_owned());
    //     let result = manager.unlock(&"correct_password".to_string());

    //     match result {
    //         Some(result) => {
    //             result.lock();
    //         },
    //         None => { assert!(false) }
    //     }
    // }

    // #[test]
    // fn test_list_entries() {
    //     let mut unlocked_manager = create_unlocked_password_manager(); 

    //     let entries = unlocked_manager.list_entries();

    //     assert_eq!(entries.len(), 0);
    // }

    // #[test]
    // fn test_add_entry() {
    //     let mut unlocked_manager = create_unlocked_password_manager();

    //     let password_manager_entry = PasswordManagerEntry {
    //         name: String::from("test_name"),
    //         username: String::from("test_username"),
    //         password: String::from("test_password"), 
    //     };

        
    //     unlocked_manager.add_entry(password_manager_entry);

    //     let entries = unlocked_manager.list_entries();

    //     assert_eq!(entries.len(), 1);
        
    //     let entry = entries.get(0).unwrap();

    //     assert_eq!(entry.name, "test_name");
    //     assert_eq!(entry.username, "test_username");
    //     assert_eq!(entry.password, "test_password");
    // }

}