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
#[derive(Debug, Clone)]
pub struct Database { 
    connection: Connection,
}

#[derive(Debug, Clone)]
pub struct PasswordManagerEntry {
    name: String,
    username: String,
    password: String,
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
             
        Database { connection }
    }
    
    pub fn get_database_connection() -> Result<Connection> {
        let conn = Connection::open("users.db")?;
        Ok(conn)
    }
    
    pub fn add_user(self, username: &String, password: &String) -> Result<()> {        
        let (pw_hash, salt) = self.create_password_hash(password);

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

    pub fn update_user_password (self, username: &String, password: &String) -> Result<()> {
        let (pw_hash, salt) = self.create_password_hash(password);

        let connection = Self::get_database_connection().unwrap();
        let mut statement = connection.prepare("UPDATE users SET pw_hash = ?, salt = ? WHERE username = ?")?;
        statement.execute([pw_hash, salt, username.to_string()])?;

        Ok(())
    }
    
    pub fn get_user(self, username: &str) -> Result<User, rusqlite::Error> {
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

    pub fn add_password_entry(self, entry: PasswordManagerEntry) -> Result<()> {
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
    
    pub fn create_password_hash(self, password: &String) -> (String, String) {
        let config = Config::default();
        let salt = &thread_rng().gen::<[u8;32]>();
        let pw_hash = argon2::hash_encoded(password.as_bytes(), salt, &config).unwrap();
        let salt = from_utf8(salt).unwrap();
        (pw_hash, salt.to_string())
    }

}



