pub const SESSION_COOKIE_NAME: &str = "sp_session";

#[derive(Debug, sqlx::FromRow)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub active_role: String,
    pub active_branch_id: String,
    pub expires_at: time::OffsetDateTime,
    pub kratos_session_id: Option<String>,
}
