use password_manager::PasswordManager;
fn main() {
    let manager = PasswordManager::new("123".to_owned());

    let unlocked_manager = manager.unlock(&"123".to_owned()).unwrap();

    unlocked_manager.lock();

    println!("hello world");
}

