use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{User, UserRole};

#[derive(Debug, Clone)]
pub struct DbClient {
    pub pool: PgPool,
}

impl DbClient {
    pub async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        verification_token: T,
        token_expires_at: DateTime<Utc>,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (name, email, password,verification_token, token_expires_at) 
            VALUES ($1, $2, $3, $4, $5) 
            RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole"
            "#,
            name.into(),
            email.into(),
            password.into(),
            verification_token.into(),
            token_expires_at
        ).fetch_one(&self.pool).await?;

        Ok(user)
    }

    pub async fn add_verified_token(
        &self,
        id: &Uuid,
        token: &str,
        token_expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        let _ = sqlx::query!(r#"UPDATE users SET verification_token=$1, token_expires_at=$2, updated_at=Now() where id=$3"#, 
                        token, 
                        token_expires_at, 
                        id)
                        .execute(&self.pool).await?;

        Ok(())
    }

    pub async fn update_pwd(&self,  user_id: &Uuid, new_password: &String)-> Result<(), sqlx::Error>  {
        let _= sqlx::query!(r#"UPDATE users SET password=$1 where id=$2"#, new_password, user_id)
                    .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn verifed_token(&self, token: &str) -> Result<(), sqlx::Error> {
        let _ = sqlx::query!(
            r#"
            UPDATE users
            SET verified = true, 
                updated_at = Now(),
                verification_token = NULL,
                token_expires_at = NULL
            WHERE verification_token = $1
            "#,
            token
        )
        .execute(&self.pool)
        .await;

        Ok(())
    }

    pub async fn get_user(
        &self,
        user_id: Option<Uuid>,
        name: Option<&str>,
        email: Option<&str>,
        token: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error> {
        let mut user: Option<User> = None;
        if let Some(user_id) = user_id {
            user = sqlx::query_as!(User, r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE id = $1"#,
            user_id).fetch_optional(&self.pool).await?;
        } else if let Some(name) = name {
            user = sqlx::query_as!(User, r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE name = $1"#,
            name).fetch_optional(&self.pool).await?;
        } else if let Some(email) = email {
            user = sqlx::query_as!(User, r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE email = $1"#,
            email).fetch_optional(&self.pool).await?;
        } else if let Some(token) = token {
            user = sqlx::query_as!(User, r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE verification_token = $1"#,
            token).fetch_optional(&self.pool).await?;
        }

        Ok(user)
    }

    pub async fn get_users(&self, page: u32, limit: u32) -> Result<Vec<User>, sqlx::Error> {
        let offset = (page - 1) * limit;

        let users = sqlx::query_as!(
            User,
            r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users 
            ORDER BY created_at DESC LIMIT $1 OFFSET $2"#,
            limit as i64,
            offset as i64).fetch_all(&self.pool).await?;

        Ok(users)
    }

    pub async fn get_user_count(&self) -> Result<i64, sqlx::Error> {
        let cnt = sqlx::query_scalar!(r#"SELECT count(*) FROM users"#).fetch_one(&self.pool).await?;
        Ok(cnt.unwrap_or(0))
    }
}
