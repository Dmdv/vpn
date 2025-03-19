use anyhow::Result;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub last_login: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // User ID
    pub exp: i64,     // Expiration time
    pub iat: i64,     // Issued at
}

pub struct AuthManager {
    users: Arc<RwLock<HashMap<Uuid, User>>>,
    jwt_secret: String,
    session_timeout: Duration,
}

impl AuthManager {
    pub fn new(jwt_secret: String, session_timeout_minutes: i64) -> Self {
        AuthManager {
            users: Arc::new(RwLock::new(HashMap::new())),
            jwt_secret,
            session_timeout: Duration::minutes(session_timeout_minutes),
        }
    }

    pub async fn create_user(&self, username: String) -> Result<User> {
        let now = Utc::now();
        let user = User {
            id: Uuid::new_v4(),
            username,
            created_at: now,
            last_login: now,
            is_active: true,
        };

        let mut users = self.users.write().await;
        users.insert(user.id, user.clone());

        Ok(user)
    }

    pub async fn authenticate(&self, user_id: Uuid) -> Result<String> {
        let mut users = self.users.write().await;
        
        if let Some(user) = users.get_mut(&user_id) {
            user.last_login = Utc::now();
            
            let claims = Claims {
                sub: user.id.to_string(),
                exp: (Utc::now() + self.session_timeout).timestamp(),
                iat: Utc::now().timestamp(),
            };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
            )?;

            Ok(token)
        } else {
            Err(anyhow::anyhow!("User not found"))
        }
    }

    pub async fn validate_token(&self, token: &str) -> Result<Uuid> {
        let validation = Validation::default();
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )?;

        let user_id = Uuid::parse_str(&token_data.claims.sub)?;
        let users = self.users.read().await;

        if let Some(user) = users.get(&user_id) {
            if user.is_active {
                Ok(user_id)
            } else {
                Err(anyhow::anyhow!("User is inactive"))
            }
        } else {
            Err(anyhow::anyhow!("User not found"))
        }
    }

    pub async fn deactivate_user(&self, user_id: Uuid) -> Result<()> {
        let mut users = self.users.write().await;
        
        if let Some(user) = users.get_mut(&user_id) {
            user.is_active = false;
            Ok(())
        } else {
            Err(anyhow::anyhow!("User not found"))
        }
    }

    pub async fn get_user(&self, user_id: &Uuid) -> Option<User> {
        let users = self.users.read().await;
        users.get(user_id).cloned()
    }
} 