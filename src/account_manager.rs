use std::fmt::Display;
use std::marker::PhantomData;
use std::ops::Add;
use std::sync::Mutex;
use std::time::Duration;
use base58::ToBase58;
use serde::{Deserialize, Serialize};
use sfo_http::openapi::utoipa::ToSchema;
use sfo_http::openapi::utoipa;
use sfo_http::token_helper::chrono::{Utc};
use sfo_http::token_helper::{Algorithm, DecodingKey, EncodingKey, JWTBuilder, JsonWebToken, Payload};
use sha2::Digest;
use crate::{AccountErrorCode, AccountResult};
use crate::errors::{account_err, into_account_err};

fn random_data(buffer: &mut [u8]) {
    let len = buffer.len();
    let mut gen_count = 0;
    while len - gen_count >= 8 {
        let r = rand::random::<u64>();
        buffer[gen_count..gen_count + 8].copy_from_slice(&r.to_be_bytes());
        gen_count += 8;
    }

    while len - gen_count > 0 {
        let r = rand::random::<u8>();
        buffer[gen_count] = r;
        gen_count += 1;
    }
}

pub trait Account: for<'a> Deserialize<'a> + 'static + Send + Serialize + Clone + ToSchema {
    type Id: Display;
    fn account_id(&self) -> &Self::Id;
    fn account_name(&self) -> &str;
    fn verify_password(&self, password: &str, salt: &[u8]) -> bool;
}

#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct SessionData<A> {
    #[schema(inline)]
    #[serde(flatten)]
    pub account: A,
    /// 本次登录sessionid
    pub session_id: String,
}

pub fn hash_data(data: &[Vec<u8>]) -> Vec<u8> {
    let mut sha256 = sha2::Sha256::new();
    for d in data {
        sha256.update(d);
    }
    sha256.finalize().to_vec()
}

#[async_trait::async_trait]
pub trait AccountStore<A: Account>: 'static + Send + Sync {
    async fn get_account(&self, account_id: &A::Id) -> AccountResult<Option<A>>;
    async fn get_account_by_name(&self, account_name: &str) -> AccountResult<Option<A>>;
    async fn remove_account(&self, account_id: &A::Id) -> AccountResult<()>;
    async fn add_account(&self, account: &A) -> AccountResult<A::Id>;
    async fn update_account(&self, account: &A) -> AccountResult<()>;
}

pub trait SignerType {
    fn ty() -> u16;
}

#[async_trait::async_trait]
pub trait AccountSigner<A: Account, ST: SignerType>: 'static + Send + Sync {
    async fn create_key(&self, account: &A::Id) -> AccountResult<()>;
    async fn sign(&self, ty: ST, account: &A::Id, data: &[u8]) -> AccountResult<Vec<u8>>;
}

#[async_trait::async_trait]
pub trait Captcha: 'static + Send + Sync {
    async fn generate_captcha(&self) -> AccountResult<(String, Vec<u8>)>;
    async fn verify_captcha(&self, captcha: &str) -> bool;
}

#[async_trait::async_trait]
pub trait AccountManager<A: Account>: 'static + Send + Sync {
    #[cfg(feature = "login")]
    async fn login(&self, account_name: &str, password: &str, salt: &[u8], captcha: Option<String>) -> AccountResult<(String, String)>;
    async fn refresh_session(&self, refresh_session: &str) -> AccountResult<(String, String)>;
    async fn decode_session(&self, session: &str) -> AccountResult<SessionData<A>>;
}

pub struct DefaultAccountManager<A: Account, Store: AccountStore<A>> {
    store: Store,
    token_key: Vec<u8>,
    _phantom_data: PhantomData<Mutex<A>>,
}

impl<
    A: Account,
    Store: AccountStore<A>,
> DefaultAccountManager<A, Store> {
    pub async fn create_account(&self, account: &A) -> AccountResult<A::Id> {
        if self.store.get_account_by_name(account.account_name()).await
            .map_err(into_account_err!(AccountErrorCode::AccountStoreError, "account {}", account.account_name()))?.is_some() {
            return Err(account_err!(AccountErrorCode::HasExist, "account {} has exist", account.account_name()));
        }

        let account_id = self.store.add_account(account).await
            .map_err(into_account_err!(AccountErrorCode::AccountStoreError, "add account {} failed", account.account_name()))?;
        Ok(account_id)
    }

    pub async fn get_account(&self, id: &A::Id) -> AccountResult<Option<A>> {
        self.store.get_account(id).await
    }

    pub async fn update_account(&self, account: &A) -> AccountResult<()> {
        self.store.update_account(account).await
            .map_err(into_account_err!(AccountErrorCode::AccountStoreError, "update account {} failed", account.account_name()))
    }

    pub async fn remove_account(&self, id: &A::Id) -> AccountResult<()> {
        self.store.remove_account(id).await
            .map_err(into_account_err!(AccountErrorCode::AccountStoreError, "remove account {} failed", id))
    }

    fn generate_session_id(&self) -> String {
        let mut session_data = [0u8;32];
        random_data(&mut session_data);
        session_data.to_base58()
    }

    fn generate_session(&self, account: A) -> AccountResult<(String, String)> {
        let session_data = SessionData {
            account,
            session_id: self.generate_session_id(),
        };
        let session = JWTBuilder::new(session_data.clone())
            .exp(Utc::now().add(Duration::from_secs(3600)))
            .build(Algorithm::HS256, &EncodingKey::from_secret(self.token_key.as_slice()))
            .map_err(into_account_err!(AccountErrorCode::Failed, "build jwt failed"))?;
        let refresh_session = JWTBuilder::new(session_data)
            .exp(Utc::now().add(Duration::from_secs(3600)))
            .sub("refresh".to_string())
            .build(Algorithm::ES256, &EncodingKey::from_secret(self.token_key.as_slice()))
            .map_err(into_account_err!(AccountErrorCode::Failed, "build jwt failed"))?;
        Ok((session, refresh_session))
    }

}

#[async_trait::async_trait]
impl<
    A: Account,
    Store: AccountStore<A>,
> AccountManager<A> for DefaultAccountManager<A, Store> {
    #[cfg(feature = "login")]
    async fn login(&self, account_name: &str, password: &str, salt: &[u8], _captcha: Option<String>) -> AccountResult<(String, String)> {
        let account = self.store.get_account_by_name(account_name).await
            .map_err(into_account_err!(AccountErrorCode::AccountStoreError, "get account {} failed", account_name))?
            .ok_or(account_err!(AccountErrorCode::NotFound, "account {} not found", account_name))?;

        if account.verify_password(password, salt) {
            return Err(account_err!(AccountErrorCode::Failed, "account {} password error", account_name));
        }

        let (session, refresh_session) = self.generate_session(account.clone())?;
        Ok((session, refresh_session))
    }

    async fn refresh_session(&self, refresh_session: &str) -> AccountResult<(String, String)> {
        let token: Payload<SessionData<A>> = JsonWebToken::decode_payload(refresh_session, &DecodingKey::from_secret(self.token_key.as_slice()))
            .map_err(into_account_err!(AccountErrorCode::SessionInvalid, "decode jwt failed"))?;
        if token.sub.is_none() || token.sub.as_ref().unwrap() != "refresh" {
            return Err(account_err!(AccountErrorCode::SessionInvalid, "refresh token error"));
        }
        if token.is_expire(Duration::from_secs(3600)) {
            return Err(account_err!(AccountErrorCode::SessionExpired, "session expired"));
        }

        let (session, refresh_session) = self.generate_session(token.data.account.clone())?;
        Ok((session, refresh_session))
    }

    async fn decode_session(&self, session: &str) -> AccountResult<SessionData<A>> {
        let token: Payload<SessionData<A>> = JsonWebToken::decode_payload(session, &DecodingKey::from_secret(self.token_key.as_slice()))
            .map_err(into_account_err!(AccountErrorCode::SessionInvalid, "decode jwt failed"))?;

        if token.is_expire(Duration::from_secs(3600)) {
            return Err(account_err!(AccountErrorCode::SessionExpired, "session expired"));
        }

        Ok(token.data)
    }
}
