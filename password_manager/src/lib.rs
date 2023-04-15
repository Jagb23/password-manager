#![allow(unused)]

mod database;
pub mod error;

use std::clone;
use std::io::stdin;
use std::ptr::null;
use std::{collections::HashMap};
use std::marker::PhantomData;
use std::num::ParseIntError;

use argon2::{self, Config};
use database::{Database, PasswordManagerEntry};
use error::Error;
use log::{info, debug, error};


// use crate::database::{PasswordManagerEntry, Database, User};

// pub use crate::error::Error;

pub struct Entry {
    name: String,
    username: String,
    password: String,
}

impl Entry {
    pub fn new(name: String, username: String, password: String) -> Self {
        Entry {
            name,
            username,
            password,
        }
    }
}

// PasswordManager<Locked> != PasswordManager<Unlocked
#[derive(Debug, Clone)]
pub struct PasswordManager<State: ManagerState> {
    username: String,
    master_pass_hash: String,
    state: PhantomData<State>,
    database: Database,
}

pub enum Locked {}

pub enum Unlocked {}

pub trait ManagerState {}
impl ManagerState for Locked {}
impl ManagerState for Unlocked {}

impl PasswordManager<Locked> {
    pub fn unlock(&mut self, username: &String, master_pass: &String) -> Option<PasswordManager<Unlocked>> {
        if !self.is_master_password(username, master_pass) {
            return None
        }

        let user = self.database.get_user(username).unwrap();

        Some(PasswordManager {
            username: user.username,
            master_pass_hash: user.pw_hash,
            state: PhantomData,
            database: self.database.clone(),
        })
    }

    pub fn new_user(&mut self, username: &String, master_pass: &String) -> Result<PasswordManager<Unlocked>, Error> {
        match self.database.add_user(username, master_pass) {
            Ok(_) => print!("User {} created", username),
            Err(e) => {
                error!("{:?}", e);
                // TODO: handle error/return early
            }
        }

        info!("Created new user: {}", username);
        // TODO: move hash generation here
        let user = match self.database.get_user(username) {
            Ok(user) => user,
            Err(e) => {
                error!("{:?}", e);
                panic!("Failed to retrieve user from database");
            }
        };

        Ok(PasswordManager {
            username: username.clone(),
            master_pass_hash: user.pw_hash,
            state: PhantomData,
            database: self.database.clone(),
        })
    }
}

impl PasswordManager<Unlocked> {
    pub fn lock(self) -> PasswordManager<Locked> {
        // Wipe any user data and return to locked state
        PasswordManager {
            username: String::new(),
            master_pass_hash: String::new(),
            state: PhantomData,
            database: self.database,
        }
    }

    pub fn list_entries(&mut self) -> (PasswordManager<Unlocked>, Vec<PasswordManagerEntry>) {
        let entries = self.database.get_password_entries_for_user(&self.username).unwrap();
        (
            PasswordManager { 
                username:self.username.clone(), 
                master_pass_hash: self.master_pass_hash.clone(), 
                state: PhantomData,
                database: self.database.clone(),
            },
            entries
        )
    }

    pub fn add_entry(&mut self, password_manager_entry: &Entry) -> Result<PasswordManager<Unlocked>, Error> {
        let entry = PasswordManagerEntry::new(
            &password_manager_entry.name,
            &password_manager_entry.username,
            &password_manager_entry.password
        ); 

        self.database.add_password_entry(entry);
        Ok(PasswordManager { 
            username:self.username.clone(), 
            master_pass_hash: self.master_pass_hash.clone(), 
            state: PhantomData,
            database: self.database.clone(),
        })
    }

    pub fn reset_master_password(&mut self, current_password: &String, new_master_password: &String) -> Option<PasswordManager<Unlocked>> {
        let username_clone = self.username.clone();

        if !self.is_master_password(&username_clone, current_password) {
            return None
        }

        self.database.update_user_password(&username_clone, &new_master_password);

        let user = self.database.get_user(&username_clone).unwrap();

        Some(PasswordManager {
            username: username_clone,
            master_pass_hash: user.pw_hash, // update the password hash
            state: PhantomData,
            database: self.database.clone(),
        })
    }

}

impl<State: ManagerState> PasswordManager<State> {

    pub fn new() -> Result<PasswordManager<Locked>, Error> {
        let db = Database::new("password_manager.db".to_owned());

        Ok(PasswordManager { 
            username: String::new(),
            master_pass_hash: String::new(),
            state: PhantomData,
            database: db,
        })
    }

    fn is_master_password(&mut self, username: &String, master_pass: &String) -> bool {

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