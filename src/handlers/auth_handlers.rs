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
