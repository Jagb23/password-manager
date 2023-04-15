#![allow(unused)]

use password_manager::{PasswordManager, Locked, Entry};


fn main() {
    let mut manager = PasswordManager::<Locked>::new().unwrap();

    let mut manager = manager.new_user(&"dustin".to_owned(), &"1234".to_owned()).unwrap();

    manager.add_entry(
        &Entry::new(
            "test_name".to_owned(), 
            "test_username".to_owned(),
            "test_password".to_owned(),
        )).unwrap();

    manager.add_entry(
        &Entry::new(
            "test_name2".to_owned(), 
            "test_username2".to_owned(),
            "test_password2".to_owned(),
        )).unwrap();

    let (mut manager, entries) = manager.list_entries();

    println!("{:?}", entries);

    // let manager = manager.add_entry(
    //     &Entry::new(
    //         "test_name".to_owned(), 
    //         "test_username".to_owned(),
    //         "test_password".to_owned(),
    //     )).unwrap();

    // let (manager, entries) = manager.list_entries();

    // println!("{:?}", entries);
}

// libsqlite3_sys::error::ErrorCode::ConstraintViolation
