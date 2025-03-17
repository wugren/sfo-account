pub use sfo_result::err as account_err;
pub use sfo_result::into_err as into_account_err;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccountErrorCode {
    #[default]
    Failed,
    HasExist,
    NotFound,
    AccountStoreError,
    AccountSignerError,
    SessionInvalid,
    SessionExpired,
    InvalidParam,
    IoError,
    InvalidAccount,
    InvalidPassword,
}

impl Into<u16> for AccountErrorCode {
    fn into(self) -> u16 {
        self as u16
    }
}

pub type AccountError = sfo_result::Error<AccountErrorCode>;
pub type AccountResult<T> = sfo_result::Result<T, AccountErrorCode>;
