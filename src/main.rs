#![allow(unused)]

use password_manager::{PasswordManager, Locked, Entry};


fn main() {
    let manager = PasswordManager::<Locked>::new().unwrap();

    let manager = manager.new_user(&"dustin".to_owned(), &"1234".to_owned()).unwrap();

    let manager = manager.add_entry(
        &Entry::new(
            "test_name".to_owned(), 
            "test_username".to_owned(),
            "test_password".to_owned(),
        )).unwrap();

    let (manager, entries) = manager.list_entries();

    println!("{:?}", entries);
}