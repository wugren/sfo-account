use crate::errors::{account_err, into_account_err};
use crate::{Account, AccountErrorCode, AccountManager, AccountResult, SessionData};
use serde::{Deserialize, Serialize};
use sfo_http::{add_openapi_item, def_openapi};
use sfo_http::http::header::{AUTHORIZATION};
use sfo_http::http_server::{HttpMethod, HttpServer, Request, Response};
use sfo_http::openapi::utoipa::ToSchema;
use sfo_http::openapi::{utoipa, OpenApiServer, OpenapiNoValueResult, OpenapiResult};
use std::sync::Arc;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct LoginReq {
    pub user_name: String,
    pub password: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct LoginResp {
    session: String,
    refresh_session: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct Session {
    /// 登录session
    pub session: String,
}

pub struct AccountServer;

impl AccountServer {
    pub fn register_server<
        A: Account,
        AM: AccountManager<A>,
        Req: Request,
        Resp: Response,
        S: HttpServer<Req, Resp> + OpenApiServer,
    >(
        server: &mut S,
        account_manager: Arc<AM>,
    ) {
        #[cfg(feature = "login")]
        {
            def_openapi! {
                [login]
                #[utoipa::path(
                    post,
                    path = "/account/login",
                    summary = "Login",
                    responses (
                        (status = 200,
                            body = inline(LoginReq))
                    ),
                    request_body = inline(OpenapiResult<LoginResp>),
                    tag = "account"
                )]
            }
            add_openapi_item!(server, login);
            let manager = account_manager.clone();
            server.serve("/account/login", HttpMethod::POST, move |mut req: Req| {
                let account_manager = manager.clone();
                async move {
                    let ret: AccountResult<LoginResp> = async move {
                        let req: LoginReq = req
                            .body_json()
                            .await
                            .map_err(into_account_err!(AccountErrorCode::InvalidParam))?;
                        let (session, refresh_session) = account_manager
                            .login(
                                req.user_name.as_str(),
                                req.password.as_str(),
                                req.timestamp,
                                None,
                            )
                            .await?;
                        Ok(LoginResp {
                            session,
                            refresh_session,
                        })
                    }
                    .await;
                    Ok(Resp::from_result(ret))
                }
            });
        }

        def_openapi!(
            [get_account_info_of_session]
            #[utoipa::path(
                post,
                summary = "获取session关联的用户信息",
                path = "/account/get_account_info_of_session",
                responses (
                    (status = 200,
                    body = inline(OpenapiNoValueResult)),
                ),
                request_body = inline(Session),
                tag = "account"
            )]
        );
        add_openapi_item!(server, get_account_info_of_session);
        let manager = account_manager.clone();
        server
            .serve("/account/get_account_info_of_session", HttpMethod::POST, move |mut req: Req| {
                let account_manager = manager.clone();
                async move {
                    let ret = async move {
                        let session: Session = req
                            .body_json()
                            .await
                            .map_err(into_account_err!(AccountErrorCode::InvalidParam))?;
                        account_manager.decode_session(&session.session).await
                    }.await;
                    Ok(Resp::from_result(ret))
                }
            });

        def_openapi!(
            [get_account_info]
            #[utoipa::path(
                get,
                summary = "获取用户信息",
                path = "/account/get_account_info",
                responses (
                    (status = 200,
                    body = inline(OpenapiNoValueResult)),
                ),
                tag = "account"
            )]
        );
        add_openapi_item!(server, get_account_info);
        let manager = account_manager.clone();
        server.serve("/account/get_account_info", HttpMethod::GET, move |req: Req| {
            let account_manager = manager.clone();
            async move {
                let ret: AccountResult<SessionData<A>> = async move {
                    let session = req
                        .header(AUTHORIZATION)
                        .ok_or_else(|| account_err!(AccountErrorCode::InvalidParam))?
                        .to_str().map_err(|_| account_err!(AccountErrorCode::InvalidParam))?.to_string();
                    if !session.to_lowercase().starts_with("bearer ") {
                        return Err(account_err!(AccountErrorCode::InvalidParam));
                    }
                    let session = session.split_at("Bearer ".len()).1;
                    account_manager.decode_session(session).await
                }.await;
                Ok(Resp::from_result(ret))
            }
        });

        def_openapi!(
            [refresh_session]
            #[utoipa::path(
                post,
                path = "/account/refresh_session",
                responses (
                    (status = 200,
                    description = "refresh session",
                    body = inline(OpenapiResult<LoginResp>)),
                ),
                request_body = inline(Session),
                tag = "account"
            )]
        );
        add_openapi_item!(server, refresh_session);
        let manager = account_manager.clone();
        server.serve("/account/refresh_session", HttpMethod::POST, move |req: Req| {
            let account_manager = manager.clone();
            async move {
                let ret: AccountResult<LoginResp> = async move {
                    let session = req
                        .header(AUTHORIZATION)
                        .ok_or_else(|| account_err!(AccountErrorCode::InvalidParam))?
                        .to_str().map_err(|_| account_err!(AccountErrorCode::InvalidParam))?.to_string();
                    if !session.to_lowercase().starts_with("bearer ") {
                        return Err(account_err!(AccountErrorCode::InvalidParam));
                    }
                    let session = session.split_at("Bearer ".len()).1;
                    let (session, refresh_session) = account_manager.refresh_session(session).await?;
                    Ok(LoginResp {
                        session,
                        refresh_session,
                    })
                }.await;
                Ok(Resp::from_result(ret))
            }
        });
    }
}
