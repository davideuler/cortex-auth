use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use cortex_server::{build_router, config::AppConfig, db, state::AppState};

async fn setup_test_app() -> axum::Router {
    let config = AppConfig::test_config();
    let pool = db::create_pool("sqlite::memory:").await.unwrap();
    db::run_migrations(&pool).await.unwrap();
    let state = AppState::new(pool, config);
    build_router(state)
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn make_agent_jwt(agent_id: &str, jwt_secret: &str) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Claims {
        sub: String,
        iat: u64,
    }

    let claims = Claims {
        sub: agent_id.to_string(),
        iat: chrono::Utc::now().timestamp() as u64,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .unwrap()
}

/// Creates app with two KEY_VALUE secrets and a default agent. Returns (app, auth_proof).
async fn setup_app_with_secrets() -> (axum::Router, String) {
    let app = setup_test_app().await;

    // Create agent in default namespace
    let req = Request::builder()
        .method("POST")
        .uri("/admin/agents")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({"agent_id": "discover-agent", "jwt_secret": "discover-jwt-secret"})
                .to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    // Create two KEY_VALUE secrets in default namespace
    for (path, val) in [
        ("openai_api_key", "sk-openai-123"),
        ("dashscope_api_key", "dsk-dash-456"),
    ] {
        let req = Request::builder()
            .method("POST")
            .uri("/admin/secrets")
            .header("content-type", "application/json")
            .header("x-admin-token", "test-admin-token")
            .body(Body::from(
                json!({"key_path": path, "secret_type": "KEY_VALUE", "value": val}).to_string(),
            ))
            .unwrap();
        app.clone().oneshot(req).await.unwrap();
    }

    let auth_proof = make_agent_jwt("discover-agent", "discover-jwt-secret");
    (app, auth_proof)
}

// ====================== SECRET CRUD TESTS ======================

#[tokio::test]
async fn test_create_and_list_secrets() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .method("POST")
        .uri("/admin/secrets")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({
                "key_path": "openai_api_key",
                "secret_type": "KEY_VALUE",
                "value": "sk-test-12345",
                "description": "OpenAI API Key"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = body_json(resp.into_body()).await;
    assert_eq!(body["key_path"], "openai_api_key");
    assert_eq!(body["namespace"], "default");
    let secret_id = body["id"].as_str().unwrap().to_string();

    // List secrets
    let req = Request::builder()
        .method("GET")
        .uri("/admin/secrets")
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list: Vec<Value> = serde_json::from_value(body_json(resp.into_body()).await).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["key_path"], "openai_api_key");
    assert_eq!(list[0]["namespace"], "default");

    // Get secret by id (should return decrypted value)
    let req = Request::builder()
        .method("GET")
        .uri(format!("/admin/secrets/{}", secret_id))
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let detail = body_json(resp.into_body()).await;
    assert_eq!(detail["value"], "sk-test-12345");
    assert_eq!(detail["namespace"], "default");
}

#[tokio::test]
async fn test_update_and_delete_secret() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .method("POST")
        .uri("/admin/secrets")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({"key_path": "test_key", "secret_type": "KEY_VALUE", "value": "original"})
                .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = body_json(resp.into_body()).await;
    let id = body["id"].as_str().unwrap().to_string();

    let req = Request::builder()
        .method("PUT")
        .uri(format!("/admin/secrets/{}", id))
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(json!({"value": "updated"}).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/admin/secrets/{}", id))
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let detail = body_json(resp.into_body()).await;
    assert_eq!(detail["value"], "updated");

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/admin/secrets/{}", id))
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/admin/secrets/{}", id))
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_token_required() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .method("GET")
        .uri("/admin/secrets")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ====================== AGENT TESTS ======================

#[tokio::test]
async fn test_create_list_delete_agent() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .method("POST")
        .uri("/admin/agents")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({
                "agent_id": "agent-test-01",
                "jwt_secret": "my-super-secret-jwt-key",
                "description": "Test agent"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["namespace"], "default");

    let req = Request::builder()
        .method("GET")
        .uri("/admin/agents")
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list: Vec<Value> = serde_json::from_value(body_json(resp.into_body()).await).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["agent_id"], "agent-test-01");

    let req = Request::builder()
        .method("DELETE")
        .uri("/admin/agents/agent-test-01")
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .method("GET")
        .uri("/admin/agents")
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let list: Vec<Value> = serde_json::from_value(body_json(resp.into_body()).await).unwrap();
    assert_eq!(list.len(), 0);
}

// ====================== POLICY TESTS ======================

#[tokio::test]
async fn test_create_list_delete_policy() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .method("POST")
        .uri("/admin/policies")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({
                "policy_name": "dev-policy",
                "agent_pattern": "agent-claude-*",
                "allowed_paths": ["secrets/openai", "secrets/google/*"],
                "denied_paths": ["secrets/database/production"]
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp.into_body()).await;
    let policy_id = body["id"].as_str().unwrap().to_string();

    let req = Request::builder()
        .method("GET")
        .uri("/admin/policies")
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let list: Vec<Value> = serde_json::from_value(body_json(resp.into_body()).await).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["policy_name"], "dev-policy");

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/admin/policies/{}", policy_id))
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ====================== DISCOVER + SECRETS TESTS ======================

#[tokio::test]
async fn test_discover_full_match() {
    let (app, auth_proof) = setup_app_with_secrets().await;

    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "discover-agent",
                "auth_proof": auth_proof,
                "context": {
                    "project_name": "movie-translator",
                    "file_content": "OPENAI_API_KEY=\nDASHSCOPE_API_KEY="
                }
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["full_matched"], true);
    assert!(body["project_token"].as_str().is_some());
    assert!(!body["project_token"].as_str().unwrap().is_empty());
    assert_eq!(body["unmatched_keys"].as_array().unwrap().len(), 0);
    assert_eq!(body["namespace"], "default");
}

#[tokio::test]
async fn test_discover_requires_valid_auth() {
    let (app, _) = setup_app_with_secrets().await;

    // Missing agent_id and auth_proof returns 422 (unprocessable entity)
    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"context": {"project_name": "test", "file_content": "OPENAI_API_KEY="}})
                .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status() == StatusCode::UNPROCESSABLE_ENTITY
            || resp.status() == StatusCode::BAD_REQUEST
    );

    // Wrong jwt_secret returns 401
    let bad_proof = make_agent_jwt("discover-agent", "wrong-secret");
    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "discover-agent",
                "auth_proof": bad_proof,
                "context": {"project_name": "test", "file_content": "OPENAI_API_KEY="}
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_discover_partial_match() {
    let (app, auth_proof) = setup_app_with_secrets().await;

    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "discover-agent",
                "auth_proof": auth_proof,
                "context": {
                    "project_name": "partial-project",
                    "file_content": "OPENAI_API_KEY=\nMISSING_KEY="
                }
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["full_matched"], false);
    let unmatched = body["unmatched_keys"].as_array().unwrap();
    assert_eq!(unmatched.len(), 1);
    assert_eq!(unmatched[0], "MISSING_KEY");
}

#[tokio::test]
async fn test_get_secrets_with_valid_token() {
    let (app, auth_proof) = setup_app_with_secrets().await;

    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "discover-agent",
                "auth_proof": auth_proof,
                "context": {
                    "project_name": "my-project",
                    "file_content": "OPENAI_API_KEY=\nDASHSCOPE_API_KEY="
                }
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    let discover_body = body_json(resp.into_body()).await;
    let project_token = discover_body["project_token"].as_str().unwrap().to_string();

    let req = Request::builder()
        .method("GET")
        .uri("/project/secrets/my-project")
        .header("authorization", format!("Bearer {}", project_token))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let secrets = body_json(resp.into_body()).await;
    assert_eq!(secrets["env_vars"]["OPENAI_API_KEY"], "sk-openai-123");
    assert_eq!(secrets["env_vars"]["DASHSCOPE_API_KEY"], "dsk-dash-456");
}

#[tokio::test]
async fn test_get_secrets_invalid_token() {
    let (app, auth_proof) = setup_app_with_secrets().await;

    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "discover-agent",
                "auth_proof": auth_proof,
                "context": {"project_name": "guarded-project", "file_content": "OPENAI_API_KEY="}
            })
            .to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/project/secrets/guarded-project")
        .header("authorization", "Bearer wrong-token-here")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ====================== CONFIG TEMPLATE TESTS ======================

#[tokio::test]
async fn test_get_config_template() {
    let (app, auth_proof) = setup_app_with_secrets().await;

    let template = "[smtp]\npassword = {{openai_api_key}}\nhost = mail.example.com";
    let req = Request::builder()
        .method("POST")
        .uri("/admin/secrets")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({
                "key_path": "himalaya",
                "secret_type": "TEMPLATE_CONFIG",
                "value": template
            })
            .to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "discover-agent",
                "auth_proof": auth_proof,
                "context": {"project_name": "mail-project", "file_content": "OPENAI_API_KEY="}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = body_json(resp.into_body()).await;
    let token = body["project_token"].as_str().unwrap().to_string();

    let req = Request::builder()
        .method("GET")
        .uri("/project/config/mail-project/himalaya")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rendered = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let rendered_str = std::str::from_utf8(&rendered).unwrap();
    assert!(rendered_str.contains("sk-openai-123"));
    assert!(rendered_str.contains("host = mail.example.com"));
}

// ====================== RE-DISCOVER CONFLICT TEST ======================

#[tokio::test]
async fn test_discover_conflict_on_rediscover() {
    let (app, auth_proof) = setup_app_with_secrets().await;

    let make_discover_req = |proof: &str, regenerate: bool| {
        let mut body = json!({
            "agent_id": "discover-agent",
            "auth_proof": proof,
            "context": {
                "project_name": "conflict-project",
                "file_content": "OPENAI_API_KEY="
            }
        });
        if regenerate {
            body["regenerate_token"] = json!(true);
        }
        body.to_string()
    };

    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(make_discover_req(&auth_proof, false)))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second discover of same project without regenerate_token → conflict
    let proof2 = make_agent_jwt("discover-agent", "discover-jwt-secret");
    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(make_discover_req(&proof2, false)))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // With regenerate_token=true → OK and new token
    let proof3 = make_agent_jwt("discover-agent", "discover-jwt-secret");
    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(make_discover_req(&proof3, true)))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert!(body["project_token"].as_str().is_some());
    assert!(!body["project_token"].as_str().unwrap().starts_with("__existing__"));
}

// ====================== NAMESPACE ISOLATION TEST ======================

#[tokio::test]
async fn test_namespace_isolation() {
    let app = setup_test_app().await;

    // Create secret in "prod" namespace
    let req = Request::builder()
        .method("POST")
        .uri("/admin/secrets")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({"key_path": "prod_secret", "secret_type": "KEY_VALUE", "value": "prod-value", "namespace": "prod"})
                .to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    // Create secret in "default" namespace
    let req = Request::builder()
        .method("POST")
        .uri("/admin/secrets")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({"key_path": "default_secret", "secret_type": "KEY_VALUE", "value": "default-value"})
                .to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    // Create agent in "default" namespace
    let req = Request::builder()
        .method("POST")
        .uri("/admin/agents")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({"agent_id": "default-agent", "jwt_secret": "default-secret"}).to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    let auth_proof = make_agent_jwt("default-agent", "default-secret");

    // Discover: default-agent should only see "default_secret", not "prod_secret"
    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "default-agent",
                "auth_proof": auth_proof,
                "context": {"project_name": "ns-test", "file_content": "PROD_SECRET=\nDEFAULT_SECRET="}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    let mapped = body["mapped_keys"].as_object().unwrap();
    assert!(mapped.contains_key("DEFAULT_SECRET"), "should map DEFAULT_SECRET");
    assert!(!mapped.contains_key("PROD_SECRET"), "should NOT map PROD_SECRET from different namespace");
    let unmatched = body["unmatched_keys"].as_array().unwrap();
    assert!(unmatched.iter().any(|k| k == "PROD_SECRET"));
}

// ====================== POLICY ENFORCEMENT TEST ======================

#[tokio::test]
async fn test_policy_denies_path() {
    let app = setup_test_app().await;

    // Create two secrets
    for (path, val) in [("allowed_key", "allowed-val"), ("denied_key", "denied-val")] {
        let req = Request::builder()
            .method("POST")
            .uri("/admin/secrets")
            .header("content-type", "application/json")
            .header("x-admin-token", "test-admin-token")
            .body(Body::from(
                json!({"key_path": path, "secret_type": "KEY_VALUE", "value": val}).to_string(),
            ))
            .unwrap();
        app.clone().oneshot(req).await.unwrap();
    }

    // Create policy denying "denied_key" for this agent
    let req = Request::builder()
        .method("POST")
        .uri("/admin/policies")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({
                "policy_name": "deny-policy",
                "agent_pattern": "policy-agent",
                "allowed_paths": [],
                "denied_paths": ["denied_key"]
            })
            .to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    // Create agent
    let req = Request::builder()
        .method("POST")
        .uri("/admin/agents")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({"agent_id": "policy-agent", "jwt_secret": "policy-secret"}).to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    let auth_proof = make_agent_jwt("policy-agent", "policy-secret");

    // Discover: denied_key should not be mapped
    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "policy-agent",
                "auth_proof": auth_proof,
                "context": {"project_name": "policy-project", "file_content": "ALLOWED_KEY=\nDENIED_KEY="}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    let mapped = body["mapped_keys"].as_object().unwrap();
    assert!(mapped.contains_key("ALLOWED_KEY"), "allowed_key should be mapped");
    assert!(!mapped.contains_key("DENIED_KEY"), "denied_key should be blocked by policy");
}

// ====================== AUDIT LOG TEST ======================

#[tokio::test]
async fn test_audit_log_list() {
    let (app, auth_proof) = setup_app_with_secrets().await;

    // Perform a discover to generate an audit log entry
    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "discover-agent",
                "auth_proof": auth_proof,
                "context": {"project_name": "audit-project", "file_content": "OPENAI_API_KEY="}
            })
            .to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    // List audit logs
    let req = Request::builder()
        .method("GET")
        .uri("/admin/audit-logs")
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let logs: Vec<Value> = serde_json::from_value(body_json(resp.into_body()).await).unwrap();
    assert!(!logs.is_empty());
    let actions: Vec<&str> = logs.iter().filter_map(|l| l["action"].as_str()).collect();
    assert!(actions.contains(&"discover"), "discover action should be logged");
}

// ====================== KEY ROTATION TEST ======================

#[tokio::test]
async fn test_rotate_key() {
    let (app, auth_proof) = setup_app_with_secrets().await;

    // Discover first to register a project
    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "discover-agent",
                "auth_proof": auth_proof,
                "context": {"project_name": "rotate-project", "file_content": "OPENAI_API_KEY="}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = body_json(resp.into_body()).await;
    let project_token = body["project_token"].as_str().unwrap().to_string();

    // Rotate key with a new 32-byte hex key
    let new_key = "a".repeat(64); // 64 hex chars = 32 bytes
    let req = Request::builder()
        .method("POST")
        .uri("/admin/rotate-key")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({"new_encryption_key": new_key}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["rotated"], true);
    assert!(body["secrets_updated"].as_u64().unwrap() > 0);

    // After rotation, the old server config key is stale — secrets are re-encrypted with new_key.
    // The server must restart with the new ENCRYPTION_KEY to read them correctly.
    // For the test, we just verify the rotation endpoint returns success and row counts.
    assert!(body["agents_updated"].as_u64().unwrap() > 0);

    // Project token still exists (not rotated)
    let req = Request::builder()
        .method("GET")
        .uri("/project/secrets/rotate-project")
        .header("authorization", format!("Bearer {}", project_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    // After key rotation, decryption with old key will fail — secrets return empty
    // This is expected and documented: server restart with new key required
    assert_eq!(resp.status(), StatusCode::OK);
}

// ====================== TOKEN LIFECYCLE TESTS ======================

async fn discover_for(app: &axum::Router, auth_proof: &str, project: &str) -> (String, String) {
    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "discover-agent",
                "auth_proof": auth_proof,
                "context": {"project_name": project, "file_content": "OPENAI_API_KEY="}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    let token = body["project_token"].as_str().unwrap().to_string();
    let expires = body["token_expires_at"].as_str().unwrap().to_string();
    (token, expires)
}

#[tokio::test]
async fn test_discover_returns_token_expiration_metadata() {
    let (app, auth_proof) = setup_app_with_secrets().await;

    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "discover-agent",
                "auth_proof": auth_proof,
                "context": {"project_name": "lifecycle-project", "file_content": "OPENAI_API_KEY="}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = body_json(resp.into_body()).await;

    assert!(body["token_expires_at"].as_str().is_some());
    // Default TTL: 120 minutes = 7200 seconds.
    assert_eq!(body["token_ttl_seconds"], 7200);
}

#[tokio::test]
async fn test_revoke_project_token_blocks_secrets_access() {
    let (app, auth_proof) = setup_app_with_secrets().await;

    let (token, _) = discover_for(&app, &auth_proof, "revoke-project").await;

    // Sanity check: token works.
    let req = Request::builder()
        .method("GET")
        .uri("/project/secrets/revoke-project")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Revoke via admin endpoint.
    let req = Request::builder()
        .method("POST")
        .uri("/admin/projects/revoke-project/revoke")
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["revoked"], true);

    // Same token now returns 401 with error_code=token_revoked.
    let req = Request::builder()
        .method("GET")
        .uri("/project/secrets/revoke-project")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["error_code"], "token_revoked");
}

#[tokio::test]
async fn test_revoke_unknown_project_returns_404() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .method("POST")
        .uri("/admin/projects/does-not-exist/revoke")
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_auto_rotation_after_revoke_via_discover() {
    let (app, auth_proof) = setup_app_with_secrets().await;

    let (original_token, _) = discover_for(&app, &auth_proof, "auto-rot-project").await;

    // Revoke the token.
    let req = Request::builder()
        .method("POST")
        .uri("/admin/projects/auto-rot-project/revoke")
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    // Re-discover WITHOUT regenerate_token=true should still succeed (auto-rotation).
    let proof2 = make_agent_jwt("discover-agent", "discover-jwt-secret");
    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "discover-agent",
                "auth_proof": proof2,
                "context": {"project_name": "auto-rot-project", "file_content": "OPENAI_API_KEY="}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    let new_token = body["project_token"].as_str().unwrap().to_string();
    assert_ne!(new_token, original_token, "auto-rotation must mint a fresh token");

    // New token works.
    let req = Request::builder()
        .method("GET")
        .uri("/project/secrets/auto-rot-project")
        .header("authorization", format!("Bearer {}", new_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_admin_projects_list_includes_token_status() {
    let (app, auth_proof) = setup_app_with_secrets().await;

    discover_for(&app, &auth_proof, "status-project").await;

    let req = Request::builder()
        .method("GET")
        .uri("/admin/projects")
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let list: Vec<Value> = serde_json::from_value(body_json(resp.into_body()).await).unwrap();
    let project = list.iter().find(|p| p["project_name"] == "status-project").unwrap();
    assert_eq!(project["token_status"], "active");
    assert!(project["token_expires_at"].as_str().is_some());

    // Revoke and re-check.
    let req = Request::builder()
        .method("POST")
        .uri("/admin/projects/status-project/revoke")
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/admin/projects")
        .header("x-admin-token", "test-admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let list: Vec<Value> = serde_json::from_value(body_json(resp.into_body()).await).unwrap();
    let project = list.iter().find(|p| p["project_name"] == "status-project").unwrap();
    assert_eq!(project["token_status"], "revoked");
}

#[tokio::test]
async fn test_expired_token_returns_token_expired_error_code() {
    use cortex_server::{build_router, config::AppConfig, db, state::AppState};

    // Build app on a pool we keep a handle to, so we can backdate the token
    // expiry directly in SQL to simulate the 120-minute boundary elapsing.
    let config = AppConfig::test_config();
    let pool = db::create_pool("sqlite::memory:").await.unwrap();
    db::run_migrations(&pool).await.unwrap();
    let state = AppState::new(pool.clone(), config);
    let app = build_router(state);

    // Seed an agent + secret + project via the admin/discover endpoints.
    let req = Request::builder()
        .method("POST")
        .uri("/admin/agents")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({"agent_id": "discover-agent", "jwt_secret": "discover-jwt-secret"})
                .to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/admin/secrets")
        .header("content-type", "application/json")
        .header("x-admin-token", "test-admin-token")
        .body(Body::from(
            json!({"key_path": "openai_api_key", "secret_type": "KEY_VALUE", "value": "sk-x"})
                .to_string(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    let auth_proof = make_agent_jwt("discover-agent", "discover-jwt-secret");
    let (token, _) = discover_for(&app, &auth_proof, "expiry-project").await;

    // Backdate the token expiry to one minute ago.
    sqlx::query(
        "UPDATE projects SET token_expires_at = datetime('now', '-1 minutes') WHERE project_name = ?",
    )
    .bind("expiry-project")
    .execute(&pool)
    .await
    .unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/project/secrets/expiry-project")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["error_code"], "token_expired");

    // Re-discover should auto-rotate (no regenerate_token=true needed).
    let auth_proof2 = make_agent_jwt("discover-agent", "discover-jwt-secret");
    let req = Request::builder()
        .method("POST")
        .uri("/agent/discover")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "agent_id": "discover-agent",
                "auth_proof": auth_proof2,
                "context": {"project_name": "expiry-project", "file_content": "OPENAI_API_KEY="}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    let new_token = body["project_token"].as_str().unwrap();
    assert_ne!(new_token, token);
}

#[tokio::test]
async fn test_token_status_helper() {
    use cortex_server::models::project::Project;

    let mut p = Project {
        id: "x".into(),
        project_name: "x".into(),
        project_token_hash: "x".into(),
        env_mappings: "{}".into(),
        namespace: "default".into(),
        created_at: "2026-01-01 00:00:00".into(),
        updated_at: "2026-01-01 00:00:00".into(),
        token_expires_at: Some(
            (chrono::Utc::now() + chrono::Duration::minutes(60))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
        ),
        token_revoked_at: None,
    };
    assert_eq!(p.token_status(), "active");

    p.token_expires_at = Some(
        (chrono::Utc::now() - chrono::Duration::minutes(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
    );
    assert_eq!(p.token_status(), "expired");

    p.token_revoked_at = Some("2026-01-01 00:00:00".into());
    assert_eq!(p.token_status(), "revoked");
}
