use std::sync::Arc;

use axum::{
    http::{header, response, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Extension, Json, Router,
};
use axum_extra::extract::cookie::Cookie;
use chrono::{Duration, Utc};
use validator::Validate;

use crate::{
    dtos::{
        ForgotPasswordRequestDto, LoginUserDto, RegisterUserDto, ResetPasswordRequestDto, Response,
        UserLoginResponseDto, UserPasswordUpdateDto,
    },
    error::{AppError, ErrorMessage},
    utils::{password, token},
    AppState,
};

pub fn auth_handler() -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))

}

async fn register(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<RegisterUserDto>,
) -> Result<impl IntoResponse, AppError> {
    // check req params
    body.validate()
        .map_err(|e| AppError::bad_request(e.to_string()))?;

    // send verification token
    let verification_token = uuid::Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::hours(24);

    // hash the password again
    let hash_pwd = password::hash(&body.password).map_err(|e| AppError::bad_request(e.to_str()))?;

    // save user into db
    let result = app_state
        .db_client
        .save_user(
            &body.name,
            &body.email,
            &hash_pwd,
            &verification_token,
            expires_at,
        )
        .await;

    match result {
        Ok(user) => Ok((
            StatusCode::CREATED,
            Json(Response {
                status: "success",
                message: "Registration successful! Please check your email to verify your account."
                    .to_string(),
            }),
        )),

        Err(sqlx::Error::Database(db_err)) => {
            if db_err.is_unique_violation() {
                Err(AppError::unique_constraint_violation(
                    ErrorMessage::EmailExist.to_str(),
                ))
            } else {
                Err(AppError::server_error(db_err.to_string()))
            }
        }

        Err(e) => Err(AppError::server_error(e.to_string())),
    }
}

async fn login(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<LoginUserDto>,
) -> Result<impl IntoResponse, AppError> {
    body.validate().map_err(|e| AppError {
        message: e.to_string(),
        status: StatusCode::BAD_REQUEST,
    })?;

    // query user
    let user = app_state
        .db_client
        .get_user(None, None, Some(&body.email), None)
        .await
        .map_err(|e| AppError::server_error(e.to_string()))?;

    match user {
        Some(u) => {
            // check password
            let password_matched = password::compare(&body.password, &u.password)
                .map_err(|_| AppError::bad_request(ErrorMessage::WrongCredentials.to_str()))?;

            if password_matched {
                // construct jwt and set into cookies
                let token = token::create_token(
                    &u.id.to_string(),
                    &app_state.env.jwt_secret.as_bytes(),
                    app_state.env.jwt_maxage,
                )
                .map_err(|e| AppError::server_error(e.to_string()))?;

                let cookie_duration = time::Duration::minutes(app_state.env.jwt_maxage);
                let cookie = Cookie::build(("token", token.clone()))
                    .path("/")
                    .max_age(cookie_duration)
                    .http_only(true)
                    .build();

                let response_dto = Json(UserLoginResponseDto {
                    status: "success".to_string(),
                    token,
                });

                let mut headers = HeaderMap::new();
                headers.append(header::SET_COOKIE, cookie.to_string().parse().unwrap());

                let mut response = response_dto.into_response();
                response.headers_mut().extend(headers);

                Ok((StatusCode::OK, "true".to_string()))
            } else {
                Err(AppError {
                    message: ErrorMessage::WrongCredentials.to_str(),
                    status: StatusCode::BAD_GATEWAY,
                })
            }
        }
        None => Err(AppError::new("", StatusCode::BAD_GATEWAY)),
    }
}
