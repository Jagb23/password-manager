#[derive(Debug)]
pub enum Error {
    PasswordManagerFailure(String),

    UserAlreadyExists(String),
}