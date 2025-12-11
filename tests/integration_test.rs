use matchbox_server::helpers;
use reqwest::Client;
use serde_json::{json, Value};
use serial_test::serial;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};

async fn spawn_app() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    tokio::spawn(async move {
        matchbox_server::run(addr).await.unwrap();
    });
    sleep(Duration::from_millis(100)).await;
    addr
}

#[tokio::test]
#[serial]
async fn test_authentication_flow() {
    let addr = spawn_app().await;
    let client = Client::new();

    // 1. Get a challenge
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let challenge = body["challenge"].as_str().unwrap();

    // 2. Generate login payload
    let login_payload = helpers::generate_login_payload("testuser", "testpass", challenge).unwrap();

    // 3. Log in
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    assert!(body["token"].as_str().is_some());
}

#[tokio::test]
#[serial]
async fn test_authentication_flow_invalid_signature() {
    let addr = spawn_app().await;
    let client = Client::new();

    // 1. Get a challenge
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let challenge = body["challenge"].as_str().unwrap();

    // 2. Generate a valid login payload
    let login_payload_str =
        helpers::generate_login_payload("testuser", "testpass", challenge).unwrap();
    let mut login_payload: Value = serde_json::from_str(&login_payload_str).unwrap();

    // 3. Tamper with the signature, replacing it with a bogus value
    login_payload["signature_b64"] = Value::String("aW52YWxpZCBzaWduYXR1cmU=".to_string()); // "invalid signature" in base64

    // 4. Log in with the invalid signature
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload.to_string())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
#[serial]
async fn test_public_lobby_flow() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A ---
    // 1. Authenticate
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    // 2. Create a lobby
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // Creator (Player A) should also see the public lobby in the discovery endpoint
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body_a: Vec<Value> = response.json().await.unwrap();
    assert_eq!(body_a.len(), 1);
    assert_eq!(body_a[0]["id"].as_str().unwrap(), lobby_id);

    // --- Player B ---
    // 1. Authenticate
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b =
        helpers::generate_login_payload("player_b", "pass_b", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();

    // 2. Discover lobbies
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Vec<Value> = response.json().await.unwrap();
    assert_eq!(body.len(), 1);
    assert_eq!(body[0]["id"].as_str().unwrap(), lobby_id);

    // 3. Join the lobby
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
#[serial]
async fn test_private_lobby_flow() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A ---
    // 1. Authenticate and create a private lobby
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // --- Player B ---
    // 1. Authenticate
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b =
        helpers::generate_login_payload("player_b", "pass_b", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();

    // 2. Discover lobbies
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Vec<Value> = response.json().await.unwrap();
    assert_eq!(body.len(), 0);

    // Creator (Player A) should see their own private lobby
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body_owner: Vec<Value> = response.json().await.unwrap();
    assert_eq!(body_owner.len(), 1);
}

// Focused test: owner can discover their own private lobby
#[tokio::test]
#[serial]
async fn test_owner_sees_private_lobby_discovery() {
    let addr = spawn_app().await;
    let client = Client::new();

    // Authenticate owner
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge = body["challenge"].as_str().unwrap();
    let login_payload = helpers::generate_login_payload("owner", "pass", challenge).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token = body["token"].as_str().unwrap();

    // Create private lobby that whitelists only the owner
    let pubkey_owner = helpers::get_public_key("owner", "pass").unwrap();
    let create_lobby_body = json!({
        "is_private": true,
        "whitelist": [pubkey_owner]
    });
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(create_lobby_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // Owner should see it via discovery
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let lobbies: Vec<Value> = response.json().await.unwrap();
    assert!(!lobbies.is_empty());

    // Create another user (intruder) who should NOT see or join the private lobby
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_intruder = body["challenge"].as_str().unwrap();
    let login_payload_intruder =
        helpers::generate_login_payload("intruder", "pass", challenge_intruder).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_intruder)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_intruder = body["token"].as_str().unwrap();

    // Intruder should not see the private lobby
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_intruder))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let intruder_lobbies: Vec<Value> = response.json().await.unwrap();
    assert_eq!(intruder_lobbies.len(), 0);

    // Intruder should not be able to join
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_intruder))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 403);
}

// Focused test: whitelisted player sees private lobby in discovery
#[tokio::test]
#[serial]
async fn test_whitelisted_player_discovery() {
    let addr = spawn_app().await;
    let client = Client::new();

    // Player A (host)
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a = helpers::generate_login_payload("host", "pass", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    // Player B (guest)
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b = helpers::generate_login_payload("guest", "pass", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();

    let pubkey_b = helpers::get_public_key("guest", "pass").unwrap();

    // Host creates a private lobby whitelisting guest
    let create_lobby_body = json!({
        "is_private": true,
        "whitelist": [pubkey_b]
    });
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(create_lobby_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Guest should see the private lobby in discovery
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body_b: Vec<Value> = response.json().await.unwrap();
    assert_eq!(body_b.len(), 1);
    let lobby_id = body_b[0]["id"].as_str().unwrap();

    // Now create a non-whitelisted user and assert they cannot see or join
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_other = body["challenge"].as_str().unwrap();
    let login_payload_other =
        helpers::generate_login_payload("other", "pass", challenge_other).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_other)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_other = body["token"].as_str().unwrap();

    // Other should not see the private lobby
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_other))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let other_lobbies: Vec<Value> = response.json().await.unwrap();
    assert_eq!(other_lobbies.len(), 0);

    // Other should not be able to join
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_other))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 403);
}

#[tokio::test]
#[serial]
async fn test_whitelist_allows_whitelisted_player() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (Host) ---
    // 1. Authenticate
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    // --- Player B (Guest) ---
    // 1. Authenticate
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b =
        helpers::generate_login_payload("player_b", "pass_b", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();

    // Get player B's public key
    let pubkey_b = helpers::get_public_key("player_b", "pass_b").unwrap();

    // 2. Create a lobby with player B whitelisted
    let create_lobby_body = json!({
        "is_private": true,
        "whitelist": [pubkey_b]
    });
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(create_lobby_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // Player B (whitelisted) should be able to discover the private lobby
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body_b: Vec<Value> = response.json().await.unwrap();
    assert_eq!(body_b.len(), 1);
    assert_eq!(body_b[0]["id"].as_str().unwrap(), lobby_id);

    // 3. Player B should be able to join (they're whitelisted)
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
#[serial]
async fn test_whitelist_blocks_non_whitelisted_player() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (Host) ---
    // 1. Authenticate
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    // --- Player B (Whitelisted) ---
    let pubkey_b = helpers::get_public_key("player_b", "pass_b").unwrap();

    // --- Player C (Not whitelisted) ---
    // 1. Authenticate
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_c = body["challenge"].as_str().unwrap();
    let login_payload_c =
        helpers::generate_login_payload("player_c", "pass_c", challenge_c).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_c)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_c = body["token"].as_str().unwrap();

    // 2. Create a lobby with only player B whitelisted
    let create_lobby_body = json!({
        "is_private": true,
        "whitelist": [pubkey_b]
    });
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(create_lobby_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // 3. Player C should NOT be able to join (not whitelisted)
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_c))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 403); // Forbidden
}

#[tokio::test]
#[serial]
async fn test_whitelist_multiple_players() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (Host) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    // --- Player B ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b =
        helpers::generate_login_payload("player_b", "pass_b", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();
    let pubkey_b = helpers::get_public_key("player_b", "pass_b").unwrap();

    // --- Player C ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_c = body["challenge"].as_str().unwrap();
    let login_payload_c =
        helpers::generate_login_payload("player_c", "pass_c", challenge_c).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_c)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_c = body["token"].as_str().unwrap();
    let pubkey_c = helpers::get_public_key("player_c", "pass_c").unwrap();

    // --- Player D (not whitelisted) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_d = body["challenge"].as_str().unwrap();
    let login_payload_d =
        helpers::generate_login_payload("player_d", "pass_d", challenge_d).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_d)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_d = body["token"].as_str().unwrap();

    // Create a lobby with players B and C whitelisted
    let create_lobby_body = json!({
        "is_private": true,
        "whitelist": [pubkey_b, pubkey_c]
    });
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(create_lobby_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // Player B should be able to join
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Player C should be able to join
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_c))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Player D should NOT be able to join
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_d))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 403); // Forbidden
}

#[tokio::test]
#[serial]
async fn test_lobby_without_whitelist_allows_all_players() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (Host) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    // --- Player B ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b =
        helpers::generate_login_payload("player_b", "pass_b", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();

    // Create a lobby WITHOUT whitelist
    let create_lobby_body = json!({
        "is_private": true
    });
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(create_lobby_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // Player B should be able to join (no whitelist = all allowed)
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
#[serial]
async fn test_delete_lobby() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (Host) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    // Create a public lobby
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // Verify the lobby exists
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let lobbies: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies.len(), 1);
    assert_eq!(lobbies[0]["id"].as_str().unwrap(), lobby_id);

    // Delete the lobby
    let response = client
        .delete(format!("http://{}/lobbies/{}", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Verify the lobby no longer exists
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let lobbies: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies.len(), 0);

    // Attempt to delete a non-existent lobby should return 404
    let response = client
        .delete(format!("http://{}/lobbies/{}", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
#[serial]
async fn test_delete_lobby_with_multiple_players() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (Host) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    // --- Player B (Joins the lobby) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b =
        helpers::generate_login_payload("player_b", "pass_b", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();

    // Create a public lobby
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // Player B joins the lobby
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Both players should see the lobby
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let lobbies_a: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies_a.len(), 1);

    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let lobbies_b: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies_b.len(), 1);

    // The owner (Player A) deletes the lobby
    let response = client
        .delete(format!("http://{}/lobbies/{}", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Neither player should see the lobby anymore
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let lobbies_a: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies_a.len(), 0);

    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let lobbies_b: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies_b.len(), 0);
}

#[tokio::test]
#[serial]
async fn test_player_can_leave_lobby() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (creates lobby) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    // Create a public lobby
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // --- Player B (joins lobby) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b =
        helpers::generate_login_payload("player_b", "pass_b", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();

    // Player B joins
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Verify both players are in the lobby
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    let lobbies: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies.len(), 1);
    assert_eq!(lobbies[0]["player_count"], 2);

    // Player B leaves (using DELETE endpoint)
    let response = client
        .delete(format!("http://{}/lobbies/{}", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Verify Player B is no longer in the lobby but lobby still exists
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    let lobbies: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies.len(), 1); // Lobby still exists
    assert_eq!(lobbies[0]["player_count"], 1); // Only owner left
}

#[tokio::test]
#[serial]
async fn test_owner_deletes_lobby_completely() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (creates lobby) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    // --- Player B (joins lobby) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b =
        helpers::generate_login_payload("player_b", "pass_b", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();

    // Create lobby
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // Player B joins
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Owner (Player A) deletes the lobby
    let response = client
        .delete(format!("http://{}/lobbies/{}", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Verify lobby no longer exists for anyone
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    let lobbies_a: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies_a.len(), 0);

    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    let lobbies_b: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies_b.len(), 0);
}

#[tokio::test]
#[serial]
async fn test_cannot_create_multiple_lobbies() {
    let addr = spawn_app().await;
    let client = Client::new();

    // Authenticate
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge = body["challenge"].as_str().unwrap();
    let login_payload = helpers::generate_login_payload("player_a", "pass_a", challenge).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token = body["token"].as_str().unwrap();

    // Create first lobby
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Attempt to create second lobby should fail with 409 CONFLICT
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 409);
}

#[tokio::test]
#[serial]
async fn test_cannot_join_multiple_lobbies() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (creates lobby 1) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let _lobby_1_id = body["id"].as_str().unwrap();

    // --- Player B (creates lobby 2) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b =
        helpers::generate_login_payload("player_b", "pass_b", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();

    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_b))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_2_id = body["id"].as_str().unwrap();

    // --- Player A attempts to join lobby 2 (should fail with 409) ---
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_2_id))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 409); // CONFLICT
}

#[tokio::test]
#[serial]
async fn test_can_rejoin_same_lobby() {
    let addr = spawn_app().await;
    let client = Client::new();

    // Authenticate
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge = body["challenge"].as_str().unwrap();
    let login_payload = helpers::generate_login_payload("player_a", "pass_a", challenge).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token = body["token"].as_str().unwrap();

    // Create lobby
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // Rejoin same lobby should succeed (idempotent)
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
#[serial]
async fn test_invite_friends_to_private_lobby() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (creates private lobby without whitelist) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    // Create private lobby without whitelist
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // --- Player B (tries to join without being invited) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b =
        helpers::generate_login_payload("player_b", "pass_b", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();

    // Player B should not see the private lobby
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    let lobbies: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies.len(), 0);

    // Get Player B's public key
    let pubkey_b = helpers::get_public_key("player_b", "pass_b").unwrap();

    // Player A invites Player B
    let invite_body = json!({
        "player_public_keys": [pubkey_b]
    });
    let response = client
        .post(format!("http://{}/lobbies/{}/invite", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(invite_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Now Player B should see the lobby
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    let lobbies: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies.len(), 1);
    assert_eq!(lobbies[0]["id"].as_str().unwrap(), lobby_id);

    // Player B should be able to join
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
#[serial]
async fn test_only_owner_can_invite() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (creates lobby) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    // --- Player B (joins lobby) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b =
        helpers::generate_login_payload("player_b", "pass_b", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();

    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // --- Player C ---
    let pubkey_c = helpers::get_public_key("player_c", "pass_c").unwrap();

    // Player B (non-owner) tries to invite Player C - should fail
    let invite_body = json!({
        "player_public_keys": [pubkey_c]
    });
    let response = client
        .post(format!("http://{}/lobbies/{}/invite", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_b))
        .header("Content-Type", "application/json")
        .body(invite_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 403); // Forbidden
}

#[tokio::test]
#[serial]
async fn test_lobby_response_visibility() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (creates lobby) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    let pubkey_a = helpers::get_public_key("player_a", "pass_a").unwrap();

    // --- Player B ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_b = body["challenge"].as_str().unwrap();
    let login_payload_b =
        helpers::generate_login_payload("player_b", "pass_b", challenge_b).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_b)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_b = body["token"].as_str().unwrap();

    let pubkey_b = helpers::get_public_key("player_b", "pass_b").unwrap();

    // --- Player C (Non-member) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_c = body["challenge"].as_str().unwrap();
    let login_payload_c =
        helpers::generate_login_payload("player_c", "pass_c", challenge_c).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_c)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_c = body["token"].as_str().unwrap();

    // Create a public lobby (Player A)
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let lobby_create_response: Value = response.json().await.unwrap();

    // Verify that the create lobby response DOES contain player public keys (since creator is in lobby)
    assert!(lobby_create_response.get("players").is_some(), "Create lobby response should contain 'players' field");
    let players = lobby_create_response["players"].as_array().unwrap();
    assert_eq!(players.len(), 1);
    assert_eq!(players[0]["publicKey"], pubkey_a);
    assert_eq!(players[0]["is_you"], true);

    assert!(lobby_create_response.get("owner").is_none(), "Create lobby response should not contain 'owner' field");
    assert!(lobby_create_response.get("whitelist").is_none(), "Create lobby response should not contain 'whitelist' field");
    
    // Verify it contains sanitized fields
    assert!(lobby_create_response.get("id").is_some(), "Create lobby response should contain 'id' field");
    assert!(lobby_create_response.get("player_count").is_some(), "Create lobby response should contain 'player_count' field");
    assert!(lobby_create_response.get("is_owner").is_some(), "Create lobby response should contain 'is_owner' field");
    assert_eq!(lobby_create_response["is_owner"], true, "Creator should be marked as owner");
    
    let lobby_id = lobby_create_response["id"].as_str().unwrap();

    // Player B joins
    let response = client
        .post(format!("http://{}/lobbies/{}/join", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // List lobbies as Player A (Member/Owner)
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let lobbies: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies.len(), 1);
    
    let lobby = &lobbies[0];
    
    // Verify public keys ARE exposed to members
    assert!(lobby.get("players").is_some(), "Lobby list should contain 'players' field for members");
    let players = lobby["players"].as_array().unwrap();
    assert_eq!(players.len(), 2);
    
    // Verify response contains the actual public keys
    let lobby_json_str = serde_json::to_string(&lobby).unwrap();
    assert!(lobby_json_str.contains(&pubkey_a), "Response should contain Player A's public key");
    assert!(lobby_json_str.contains(&pubkey_b), "Response should contain Player B's public key");
    
    // Verify sanitized fields are present
    assert_eq!(lobby["player_count"], 2, "Should show correct player count");
    assert_eq!(lobby["is_owner"], true, "Player A should be marked as owner");
    assert!(lobby.get("is_private").is_some());
    assert!(lobby.get("status").is_some());

    // List lobbies as Player B (Member)
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_b))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let lobbies_b: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies_b.len(), 1);
    
    let lobby_b = &lobbies_b[0];
    assert_eq!(lobby_b["is_owner"], false, "Player B should NOT be marked as owner");
    assert!(lobby_b.get("players").is_some(), "Player B's view should contain 'players' field");
    let players_b = lobby_b["players"].as_array().unwrap();
    assert_eq!(players_b.len(), 2);

    // List lobbies as Player C (Non-member)
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_c))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let lobbies_c: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies_c.len(), 1);
    
    let lobby_c = &lobbies_c[0];
    assert_eq!(lobby_c["is_owner"], false, "Player C should NOT be marked as owner");
    
    // Verify NO public keys are exposed to non-members
    // Note: players field is present but empty array []
    assert!(lobby_c.get("players").is_some(), "Player C's view should contain 'players' field (empty)");
    let players_c = lobby_c["players"].as_array().unwrap();
    assert_eq!(players_c.len(), 0, "Player C should see empty players list");
    
    let lobby_c_json_str = serde_json::to_string(&lobby_c).unwrap();
    assert!(!lobby_c_json_str.contains(&pubkey_a), "Player C should not see Player A's public key");
    assert!(!lobby_c_json_str.contains(&pubkey_b), "Player C should not see Player B's public key");
}

#[tokio::test]
#[serial]
async fn test_cache_control_headers_on_sensitive_endpoints() {
    let addr = spawn_app().await;
    let client = Client::new();

    // Test challenge endpoint
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let headers = response.headers();
    assert!(headers.contains_key("cache-control"), "Challenge endpoint should have Cache-Control header");
    let cache_control = headers.get("cache-control").unwrap().to_str().unwrap();
    assert!(cache_control.contains("no-store"), "Should contain no-store");
    assert!(cache_control.contains("no-cache"), "Should contain no-cache");

    // Test login endpoint
    let body: Value = response.json().await.unwrap();
    let challenge = body["challenge"].as_str().unwrap();
    let login_payload = helpers::generate_login_payload("player_a", "pass_a", challenge).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let headers = response.headers();
    assert!(headers.contains_key("cache-control"), "Login endpoint should have Cache-Control header");

    let body: Value = response.json().await.unwrap();
    let token = body["token"].as_str().unwrap();

    // Test lobby list endpoint
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let headers = response.headers();
    assert!(headers.contains_key("cache-control"), "Lobby list endpoint should have Cache-Control header");

    // Test create lobby endpoint
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let headers = response.headers();
    assert!(headers.contains_key("cache-control"), "Create lobby endpoint should have Cache-Control header");
}

#[tokio::test]
#[serial]
async fn test_sse_stream_cache_headers() {
    let addr = spawn_app().await;
    let client = Client::new();

    // Authenticate
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge = body["challenge"].as_str().unwrap();
    let login_payload = helpers::generate_login_payload("player_a", "pass_a", challenge).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token = body["token"].as_str().unwrap();

    // Create lobby first so stream has data
    client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": false}"#)
        .send()
        .await
        .unwrap();

    // Check SSE stream headers (don't try to read the stream, just check headers)
    let response = client
        .get(format!("http://{}/lobbies/stream", addr))
        .header("Authorization", format!("Bearer {}", token))
        .timeout(std::time::Duration::from_millis(500))
        .send()
        .await
        .unwrap();

    // Check cache control headers on SSE stream
    let headers = response.headers();
    assert!(headers.contains_key("cache-control"), "SSE stream should have Cache-Control header");
    let cache_control = headers.get("cache-control").unwrap().to_str().unwrap();
    assert!(cache_control.contains("no-store"), "SSE stream should have no-store");
    assert!(cache_control.contains("no-cache"), "SSE stream should have no-cache");
}

#[tokio::test]
#[serial]
async fn test_whitelist_not_exposed_to_non_whitelisted_players() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (creates private lobby) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    let pubkey_b = helpers::get_public_key("player_b", "pass_b").unwrap();
    let pubkey_c = helpers::get_public_key("player_c", "pass_c").unwrap();

    // Create private lobby with whitelist
    let create_lobby_body = json!({
        "is_private": true,
        "whitelist": [pubkey_b.clone(), pubkey_c.clone()]
    });
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(create_lobby_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let lobby_response: Value = response.json().await.unwrap();

    // Verify whitelist is not in the response
    assert!(lobby_response.get("whitelist").is_none(), "Whitelist should not be in response");
    
    // Verify the response doesn't contain the whitelisted public keys
    let response_str = serde_json::to_string(&lobby_response).unwrap();
    assert!(!response_str.contains(&pubkey_b), "Response should not contain whitelisted public key B");
    assert!(!response_str.contains(&pubkey_c), "Response should not contain whitelisted public key C");

    // --- Player D (not whitelisted) tries to discover lobbies ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_d = body["challenge"].as_str().unwrap();
    let login_payload_d =
        helpers::generate_login_payload("player_d", "pass_d", challenge_d).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_d)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_d = body["token"].as_str().unwrap();

    // Player D should not see the lobby
    let response = client
        .get(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_d))
        .send()
        .await
        .unwrap();
    let lobbies: Vec<Value> = response.json().await.unwrap();
    assert_eq!(lobbies.len(), 0, "Non-whitelisted player should not see private lobby");
}

#[tokio::test]
#[serial]
async fn test_invite_response_does_not_leak_public_keys() {
    let addr = spawn_app().await;
    let client = Client::new();

    // --- Player A (creates lobby) ---
    let response = client
        .post(format!("http://{}/auth/challenge", addr))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let challenge_a = body["challenge"].as_str().unwrap();
    let login_payload_a =
        helpers::generate_login_payload("player_a", "pass_a", challenge_a).unwrap();
    let response = client
        .post(format!("http://{}/auth/login", addr))
        .header("Content-Type", "application/json")
        .body(login_payload_a)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap();

    // Create lobby
    let response = client
        .post(format!("http://{}/lobbies", addr))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(r#"{"is_private": true}"#)
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    let lobby_id = body["id"].as_str().unwrap();

    let pubkey_b = helpers::get_public_key("player_b", "pass_b").unwrap();
    let pubkey_c = helpers::get_public_key("player_c", "pass_c").unwrap();

    // Invite players
    let invite_body = json!({
        "player_public_keys": [pubkey_b.clone(), pubkey_c.clone()]
    });
    let response = client
        .post(format!("http://{}/lobbies/{}/invite", addr, lobby_id))
        .header("Authorization", format!("Bearer {}", token_a))
        .header("Content-Type", "application/json")
        .body(invite_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let invite_response: Value = response.json().await.unwrap();

    // Verify response does NOT contain the public keys
    assert!(invite_response.get("invited").is_none(), "Invite response should not return list of invited public keys");
    assert!(invite_response.get("invited_count").is_some(), "Invite response should return count of invited players");
    
    let response_str = serde_json::to_string(&invite_response).unwrap();
    assert!(!response_str.contains(&pubkey_b), "Invite response should not contain Player B's public key");
    assert!(!response_str.contains(&pubkey_c), "Invite response should not contain Player C's public key");
}
