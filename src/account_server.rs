use crate::errors::{account_err, into_account_err};
use crate::{Account, AccountErrorCode, AccountManager, AccountResult, SessionData};
use cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use sfo_http::{add_openapi_item, def_openapi};
use sfo_http::http::header::SET_COOKIE;
use sfo_http::http::{HeaderValue};
use sfo_http::http_server::{HttpServer, Request, Response, Route};
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
        R: Route<Req, Resp>,
        S: HttpServer<Req, Resp, R> + OpenApiServer,
    >(
        server: &mut S,
        account_manager: Arc<AM>,
        cookie_secure: bool,
        cookie_domain: String,
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
                    request_body = inline(OpenapiResult<String>),
                    tag = "account"
                )]
            }
            add_openapi_item!(server, login);
            let manager = account_manager.clone();
            let tmp_cookie_domain = cookie_domain.clone();
            server.at("/account/login").post(move |mut req: Req| {
                let account_manager = manager.clone();
                let cookie_domain = tmp_cookie_domain.clone();
                async move {
                    let ret: AccountResult<(String, String)> = async move {
                        let req: LoginReq = req
                            .body_json()
                            .await
                            .map_err(into_account_err!(AccountErrorCode::InvalidParam))?;
                        let (session, refresh_session) = account_manager
                            .login(
                                req.user_name.as_str(),
                                req.password.as_str(),
                                format!("{}", req.timestamp).as_bytes(),
                                None,
                            )
                            .await?;
                        Ok((session, refresh_session))
                    }
                    .await;
                    if ret.is_ok() {
                        let (session, refresh_session) = ret.unwrap();
                        let mut resp = Resp::from_result::<_, AccountErrorCode>(Ok(session.clone()));
                        let mut build = Cookie::build("session", session)
                            .path("/")
                            .secure(cookie_secure)
                            .same_site(SameSite::Strict)
                            .http_only(true);
                        if !cookie_domain.is_empty() {
                            build = build.domain(cookie_domain.clone());
                        }
                        let cookie = build.finish();
                        resp.insert_header(SET_COOKIE, HeaderValue::from_str(cookie.to_string().as_str()).unwrap());

                        let mut build = Cookie::build("refresh_session", refresh_session)
                            .path("/")
                            .secure(cookie_secure)
                            .same_site(SameSite::Strict)
                            .http_only(true);
                        if !cookie_domain.is_empty() {
                            build = build.domain(cookie_domain);
                        }
                        let cookie = build.finish();
                        resp.insert_header(SET_COOKIE, HeaderValue::from_str(cookie.to_string().as_str()).unwrap());
                        Ok(resp)
                    } else {
                        Ok(Resp::from_result(ret))
                    }
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
            .at("/account/get_account_info_of_session")
            .post(move |mut req: Req| {
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
        server.at("/account/get_account_info").get(move |req: Req| {
            let account_manager = manager.clone();
            async move {
                let ret: AccountResult<SessionData<A>> = async move {
                    let session = req
                        .get_cookie("session")
                        .ok_or_else(|| account_err!(AccountErrorCode::InvalidParam))?;
                    account_manager.decode_session(session.as_str()).await
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
                    body = inline(OpenapiResult<String>)),
                ),
                request_body = inline(Session),
                tag = "account"
            )]
        );
        add_openapi_item!(server, refresh_session);
        let manager = account_manager.clone();
        let tmp_cookie_domain = cookie_domain.clone();
        server.at("/account/refresh_session").post(move |req: Req| {
            let account_manager = manager.clone();
            let cookie_domain = tmp_cookie_domain.clone();
            async move {
                let ret: AccountResult<(String, String)> = async move {
                    let session = req
                        .get_cookie("refresh_session")
                        .ok_or_else(|| account_err!(AccountErrorCode::InvalidParam))?;
                    account_manager.refresh_session(session.as_str()).await
                }.await;
                if ret.is_ok() {
                    let (session, refresh_session) = ret.unwrap();
                    let mut resp = Resp::from_result::<_, AccountErrorCode>(Ok(()));
                    let mut build = Cookie::build("session", session)
                        .path("/")
                        .secure(cookie_secure)
                        .same_site(SameSite::Strict)
                        .http_only(true);
                    if !cookie_domain.is_empty() {
                        build = build.domain(cookie_domain.clone());
                    }
                    let cookie = build.finish();
                    resp.insert_header(SET_COOKIE, HeaderValue::from_str(cookie.to_string().as_str()).unwrap());

                    let mut build = Cookie::build("refresh_session", refresh_session)
                        .path("/")
                        .secure(cookie_secure)
                        .same_site(SameSite::Strict)
                        .http_only(true);
                    if !cookie_domain.is_empty() {
                        build = build.domain(cookie_domain);
                    }
                    let cookie = build.finish();
                    resp.insert_header(SET_COOKIE, HeaderValue::from_str(cookie.to_string().as_str()).unwrap());
                    Ok(resp)
                } else {
                    Ok(Resp::from_result(ret))
                }
            }
        });
    }
}
