use anyhow::Result;
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::session::Session;

#[derive(Debug, sqlx::FromRow)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
}

#[derive(Debug, sqlx::FromRow)]
pub struct UserRoleRow {
    pub role: String,
    pub branch_id: String,
    pub branch_name: String,
}

pub async fn get_session(db: &PgPool, id: &str) -> Result<Option<Session>> {
    let session = sqlx::query_as::<_, Session>(
        "SELECT id, user_id, active_role, active_branch_id, expires_at, kratos_session_id
         FROM sessions WHERE id = $1 AND expires_at > NOW()",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(session)
}

pub async fn create_session(
    db: &PgPool,
    session_id: &str,
    user_id: &str,
    active_role: &str,
    active_branch_id: &str,
    kratos_session_id: Option<&str>,
) -> Result<()> {
    let expires_at = OffsetDateTime::now_utc() + time::Duration::hours(8);
    sqlx::query(
        "INSERT INTO sessions (id, user_id, active_role, active_branch_id, expires_at, kratos_session_id)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(active_role)
    .bind(active_branch_id)
    .bind(expires_at)
    .bind(kratos_session_id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_session(db: &PgPool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn update_session_role(
    db: &PgPool,
    session_id: &str,
    active_role: &str,
    active_branch_id: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE sessions SET active_role = $1, active_branch_id = $2, last_seen_at = NOW()
         WHERE id = $3",
    )
    .bind(active_role)
    .bind(active_branch_id)
    .bind(session_id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn get_user_by_email(db: &PgPool, email: &str) -> Result<Option<UserInfo>> {
    let user =
        sqlx::query_as::<_, UserInfo>("SELECT id, email FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(db)
            .await?;
    Ok(user)
}

pub async fn get_user_by_id(db: &PgPool, id: &str) -> Result<Option<UserInfo>> {
    let user = sqlx::query_as::<_, UserInfo>("SELECT id, email FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(user)
}

pub async fn get_user_roles(db: &PgPool, user_id: &str) -> Result<Vec<UserRoleRow>> {
    let roles = sqlx::query_as::<_, UserRoleRow>(
        "SELECT ubr.role, ubr.branch_id, b.name AS branch_name
         FROM user_branch_roles ubr
         JOIN branches b ON b.id = ubr.branch_id
         WHERE ubr.user_id = $1
         ORDER BY b.name, ubr.role",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(roles)
}

pub async fn has_role(
    db: &PgPool,
    user_id: &str,
    role: &str,
    branch_id: &str,
) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_branch_roles WHERE user_id = $1 AND role = $2 AND branch_id = $3",
    )
    .bind(user_id)
    .bind(role)
    .bind(branch_id)
    .fetch_one(db)
    .await?;
    Ok(count > 0)
}
