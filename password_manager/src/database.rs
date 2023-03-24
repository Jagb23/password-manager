use std::str::from_utf8;

use argon2::Config;
use rusqlite::{Connection, Result};
use rusqlite::Error::QueryReturnedNoRows;
use rand::{Rng, thread_rng};

pub struct User {
    id: i32,
    pub username: String,
    pub pw_hash: String,
    pub salt: [u8; 32] // stored as a String of text in the database
}
#[derive(Debug, Clone, Copy)]
pub struct Database { }

#[derive(Debug, Clone)]
pub struct PasswordManagerEntry {
    name: String,
    username: String,
    password: String,
}

impl PasswordManagerEntry {
    pub fn new(name: &String, username: &String, password: &String) -> Self {
        PasswordManagerEntry {
            name: name.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}


impl Database {
    pub fn new() -> Self {
        let connection = Connection::open("password_manager.db").unwrap();
    
        let res = connection.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                pw_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
            )",
            [],
        );

        match res {
            Ok(_) => (),
            Err(e) => println!("{:?}", e),
        }
    
        let res = connection.execute(
            "CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )",
            [],
        );

        match res {
            Ok(_) => (),
            Err(e) => println!("{:?}", e),
        }
             
        Database { }
    }
    
    pub fn get_database_connection() -> Result<Connection> {
        let conn = Connection::open("users.db")?;
        Ok(conn)
    }
    
    pub fn add_user(username: &String, password: &String) -> Result<()> {        
        let (pw_hash, salt) = Self::create_password_hash(password);

        let connection = Self::get_database_connection().unwrap();
        let mut statement = connection.prepare("INSERT INTO users (username, pw_hash, salt) VALUES (?, ?)")?;
        statement.execute([username, &pw_hash, &salt])?;

        Ok(())
    }

    pub fn set_user_pw_hash(self, user: User) -> Result<()> {
        let connection = Self::get_database_connection().unwrap();
        let mut statement = connection.prepare("UPDATE users SET pw_hash = ?, salt = ? WHERE username = ?")?;
        statement.execute(&[&user.pw_hash, &user.username])?;
        Ok(())
    }

    pub fn update_user_password (username: &String, password: &String) -> Result<()> {
        let (pw_hash, salt) = Self::create_password_hash(password);

        let connection = Self::get_database_connection().unwrap();
        let mut statement = connection.prepare("UPDATE users SET pw_hash = ?, salt = ? WHERE username = ?")?;
        statement.execute([pw_hash, salt, username.to_string()])?;

        Ok(())
    }
    
    pub fn get_user(username: &str) -> Result<User, rusqlite::Error> {
        let connection = Self::get_database_connection().unwrap();
        let mut statement = connection.prepare("SELECT * FROM users WHERE username = ?")?;
        let mut results = statement.query(rusqlite::params![username])?;
        
        match results.next().unwrap() {
            Some(row) => {
                let user = User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    pw_hash: row.get(2)?,
                    salt: row.get(3)?,
                };
                Ok(user)
            },
            None => Err(QueryReturnedNoRows),
       }
    }

    pub fn add_password_entry(entry: PasswordManagerEntry) -> Result<()> {
        let connection = Self::get_database_connection().unwrap();
        let mut statement = connection.prepare("INSERT INTO passwords (name, username, password) VALUES (?, ?, ?)")?;
        statement.execute(&[&entry.name, &entry.username, &entry.password])?;
        Ok(())
    }

    pub fn remove_password_entry(self, entry: PasswordManagerEntry) -> Result<()> {
        let connection = Self::get_database_connection().unwrap();
        let mut statement = connection.prepare("DELETE FROM passwords WHERE name = ? AND username = ?")?;
        statement.execute(&[&entry.name, &entry.username])?;
        Ok(())
    }
    
    pub fn create_password_hash(password: &String) -> (String, String) {
        let config = Config::default();
        let salt = &thread_rng().gen::<[u8;32]>();
        let pw_hash = argon2::hash_encoded(password.as_bytes(), salt, &config).unwrap();
        let salt = from_utf8(salt).unwrap();
        (pw_hash, salt.to_string())
    }

    pub fn get_password_entries_for_user(username: &String) -> Result<Vec<PasswordManagerEntry>, rusqlite::Error> {
        let connection = Self::get_database_connection().unwrap();
        let mut statement = connection.prepare("SELECT * FROM passwords WHERE username = ?")?;
        let mut results = statement.query(rusqlite::params![username])?;
        
        let mut entries = Vec::new();
        while let Some(row) = results.next().unwrap() {
            let entry = PasswordManagerEntry {
                name: row.get(1)?,
                username: row.get(2)?,
                password: row.get(3)?,
            };
            entries.push(entry);
        }
        Ok(entries)
    }

}



