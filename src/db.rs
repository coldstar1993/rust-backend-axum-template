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

}
