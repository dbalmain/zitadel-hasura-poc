use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

pub struct JwtKeys {
    encoding_key: EncodingKey,
    jwks: Value,
    kid: String,
}

#[derive(Serialize)]
struct HasuraClaims {
    #[serde(rename = "x-hasura-default-role")]
    default_role: String,
    #[serde(rename = "x-hasura-allowed-roles")]
    allowed_roles: Vec<String>,
    #[serde(rename = "x-hasura-user-id")]
    user_id: String,
    #[serde(rename = "x-hasura-branch-id")]
    branch_id: String,
}

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: i64,
    iat: i64,
    iss: String,
    #[serde(rename = "https://hasura.io/jwt/claims")]
    hasura: HasuraClaims,
}

impl JwtKeys {
    pub fn generate() -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let public_key = private_key.to_public_key();

        let pem = private_key.to_pkcs8_pem(LineEnding::LF)?;
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())?;

        let kid = Uuid::new_v4().to_string();

        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let jwks = json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": n,
                "e": e,
            }]
        });

        Ok(Self {
            encoding_key,
            jwks,
            kid,
        })
    }

    pub fn mint_hasura_jwt(
        &self,
        user_id: &str,
        active_role: &str,
        branch_id: &str,
        issuer: &str,
    ) -> Result<String> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let exp = now + 30; // 30-second TTL

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        let claims = Claims {
            sub: user_id.to_string(),
            exp,
            iat: now,
            iss: issuer.to_string(),
            hasura: HasuraClaims {
                default_role: active_role.to_string(),
                allowed_roles: vec![active_role.to_string()],
                user_id: user_id.to_string(),
                branch_id: branch_id.to_string(),
            },
        };

        Ok(encode(&header, &claims, &self.encoding_key)?)
    }

    pub fn jwks_document(&self) -> &Value {
        &self.jwks
    }
}
