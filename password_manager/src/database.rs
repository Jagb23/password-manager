use std::str::from_utf8;

use argon2::Config;
use rusqlite::{Connection, Result, ErrorCode, Statement};
use rusqlite::Error::{QueryReturnedNoRows, ExecuteReturnedResults};
use rand::{Rng, thread_rng};
use log::{info, debug, error};

#[derive(Debug)]
pub struct User {
    id: i32,
    pub username: String,
    pub pw_hash: String,
    pub salt: String, // stored as a String of text in the database
}

#[derive(Debug)]
pub enum DatabaseError {
    FailedToAddUser(String),
    UserAlreadyExists(String),
}

#[derive(Debug, Clone)]
pub struct Database {
    name: String,
}

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
    pub fn new(name: String) -> Self {
        let connection = Connection::open(name.clone()).unwrap();
    
        let res = connection.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                pw_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                UNIQUE(username)
            )",
            [],
        );

        match res {
            Ok(_) => debug!("Created users table"),
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
            Ok(_) => debug!("Created passwords table"),
            Err(e) => println!("{:?}", e),
        }
             
        Self {
            name
        }
    }
    
    pub fn get_database_connection(&mut self) -> Result<Connection> {
        let conn = match Connection::open(self.name.clone()) {
            Ok(conn) => conn,
            Err(e) => {
                error!("{:?}", e);
                panic!("Failed to open database connection");
            }
        };

        Ok(conn)
    }
    
    pub fn add_user(&mut self, username: &String, password: &String) -> Result<(), DatabaseError> {        
        let (pw_hash, salt) = Self::create_password_hash(password);
        debug!("Generated a password hash: {} and salt: {} for user: {}", pw_hash, salt, username);

        self.print_users_table();

        let connection = self.get_database_connection().unwrap();
        let mut statement = connection.prepare("INSERT INTO users (username, pw_hash, salt) VALUES (?, ?, ?)").unwrap();
        let res = match statement.execute([username, &pw_hash, &salt]) {
            Ok(_) => {},
            Err(e) => {
                error!("{:?}", e);
                match e { // TODO: this always hits the _ and doesn't give a good error message
                    ExecuteReturnedResults => return Err(DatabaseError::UserAlreadyExists("The user ${username.to_string()} already exists".to_owned())),
                    _ => return Err(DatabaseError::FailedToAddUser(username.to_string())),
                }
            }
        };

        self.print_users_table();

        Ok(())
    }

    pub fn set_user_pw_hash(&mut self, user: User) -> Result<()> {
        let connection = self.get_database_connection().unwrap();
        let mut statement = connection.prepare("UPDATE users SET pw_hash = ?, salt = ? WHERE username = ?")?;
        statement.execute(&[&user.pw_hash, &user.username])?;
        Ok(())
    }

    pub fn update_user_password (&mut self, username: &String, password: &String) -> Result<()> {
        let (pw_hash, salt) = Self::create_password_hash(password);

        let connection = self.get_database_connection().unwrap();
        let mut statement = connection.prepare("UPDATE users SET pw_hash = ?, salt = ? WHERE username = ?")?;
        statement.execute([pw_hash, salt, username.to_string()])?;

        Ok(())
    }
    
    pub fn get_user(&mut self, username: &str) -> Result<User, rusqlite::Error> {
        let connection = self.get_database_connection().unwrap();
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

    pub fn add_password_entry(&mut self, entry: PasswordManagerEntry) -> Result<()> {
        let connection = self.get_database_connection().unwrap();
        let mut statement = connection.prepare("INSERT INTO passwords (name, username, password) VALUES (?, ?, ?)")?;
        statement.execute(&[&entry.name, &entry.username, &entry.password])?;
        Ok(())
    }

    pub fn remove_password_entry(&mut self, entry: PasswordManagerEntry) -> Result<()> {
        let connection = self.get_database_connection().unwrap();
        let mut statement = connection.prepare("DELETE FROM passwords WHERE name = ? AND username = ?")?;
        statement.execute(&[&entry.name, &entry.username])?;
        Ok(())
    }
    
    pub fn create_password_hash(password: &String) -> (String, String) {
        let config = Config::default();
        
        let mut salt: [u8; 32] = [0; 32];
        thread_rng().fill::<[u8;32]>(&mut salt);

        let pw_hash = argon2::hash_encoded(password.as_bytes(), &salt, &config).unwrap();

        let salt = String::from_utf8_lossy(&salt);

        (pw_hash, salt.to_string())
    }

    pub fn get_password_entries_for_user(&mut self, username: &String) -> Result<Vec<PasswordManagerEntry>, rusqlite::Error> {
        let connection = self.get_database_connection().unwrap();
        // let mut statement = connection.prepare("SELECT * FROM passwords WHERE username = ?").unwrap();
        // statement.bind((username)).unwrap();
        
        self.print_passwords_table(); 
        let query = "SELECT * FROM passwords WHERE username = ?";

        let mut entries = Vec::new();

        let mut statement = connection.prepare(query).unwrap();

        let password_entries = statement.query_map([username], |row| {
            Ok(PasswordManagerEntry {
                name: row.get(1)?,
                username: row.get(2)?,
                password: row.get(3)?,
            })
        })?;

        
        for password_entry in password_entries {
            entries.push(password_entry.unwrap());
        }

        Ok(entries)
    }

    fn print_users_table(&mut self) {
        let connection = self.get_database_connection().unwrap();
        let mut statement = connection.prepare("SELECT * FROM users").unwrap();
        
        let mut results = match statement.query([]) {
            Ok(results) => results,
            Err(e) => panic!("{:?}", e),
        };
        
        while let Some(row) = results.next().unwrap() {
            // let salt: String = row.get(3).unwrap();
            // let salt_str = salt.as_bytes();
            let user = User {
                id: row.get(0).unwrap(),
                username: row.get(1).unwrap(),
                pw_hash: row.get(2).unwrap(),
                salt: row.get(3).unwrap(),
            };
            println!("{:?}", user);
        }
    }

    fn print_passwords_table(&mut self) {
        let connection = self.get_database_connection().unwrap();
        let mut statement = connection.prepare("SELECT * FROM passwords").unwrap();
        
        let mut results = match statement.query([]) {
            Ok(results) => results,
            Err(e) => panic!("{:?}", e),
        };
        
        while let Some(row) = results.next().unwrap() {
            let entry = PasswordManagerEntry {
                name: row.get(1).unwrap(),
                username: row.get(2).unwrap(),
                password: row.get(3).unwrap(),
            };
            println!("{:?}", entry);
        }
    }

}

#[cfg(test)]
mod tests { 
    use super::*;

    #[test]
    fn test_add_user() {
        // let connect = Connection::open_in_memory().unwrap(); // TODO use this for writing tests

        match Database::add_user("test", "test") {
            Ok(_) => {},
            Err(e) => panic!("{:?}", e),
        }
    }
}

