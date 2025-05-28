use std::fmt;

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

#[derive(Debug, PartialEq)]
pub enum ErrorMessage {
    EmptyPassword,
    ExceededMaxPasswordLength(usize),
    InvalidHashFormat,
    HashingError,
    InvalidToken,
    ServerError,
    WrongCredentials,
    EmailExist,
    UserNoLongerExist,
    TokenNotProvided,
    PermissionDenied,
    UserNotAuthenticated,
}

impl ErrorMessage {
    pub fn to_str(&self) -> String {
        match self {
            ErrorMessage::ServerError => "Server Error. Please try again later".to_string(),
            ErrorMessage::WrongCredentials => "Email or password is wrong".to_string(),
            ErrorMessage::EmailExist => "A user with this email already exists".to_string(),
            ErrorMessage::UserNoLongerExist => {
                "User belonging to this token no longer exists".to_string()
            }
            ErrorMessage::EmptyPassword => "Password cannot be empty".to_string(),
            ErrorMessage::HashingError => "Error while hashing password".to_string(),
            ErrorMessage::InvalidHashFormat => "Invalid password hash format".to_string(),
            ErrorMessage::ExceededMaxPasswordLength(max_length) => {
                format!("Password must not be more than {} characters", max_length)
            }
            ErrorMessage::InvalidToken => "Authentication token is invalid or expired".to_string(),
            ErrorMessage::TokenNotProvided => {
                "You are not logged in, please provide a token".to_string()
            }
            ErrorMessage::PermissionDenied => {
                "You are not allowed to perform this action".to_string()
            }
            ErrorMessage::UserNotAuthenticated => {
                "Authentication required. Please log in.".to_string()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppError {
    pub message: String,
    pub status: StatusCode,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HttpError: message: {}, status: {}",
            self.message, self.status
        )
    }
}

impl std::error::Error for AppError {}

impl AppError {
    pub fn new(message: impl Into<String>, status: StatusCode) -> Self {
        AppError {
            message: message.into(),
            status,
        }
    }

    // 内部执行错误
    pub fn server_error(message: impl Into<String>) -> Self {
        AppError {
            message: message.into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    // 客户端参数错误
    pub fn bad_request(message: impl Into<String>) -> Self {
        AppError {
            message: message.into(),
            status: StatusCode::BAD_REQUEST,
        }
    }

    // 未授权访问错误
    pub fn unauthorized(message: impl Into<String>) -> Self {
        AppError {
            message: message.into(),
            status: StatusCode::UNAUTHORIZED,
        }
    }

    // 
    pub fn unique_constraint_violation(message: impl Into<String>) -> Self {
        AppError {
            message: message.into(),
            status: StatusCode::CONFLICT,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(ErrorResponse{
            status: "fail".to_string(),
            message: self.message.clone()
        })).into_response()
    }
}
