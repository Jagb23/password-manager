use password_manager::PasswordManager;


fn main() {
    let manager = PasswordManager::new("test".to_owned());
    manager.unlock(&"test".to_owned());
}