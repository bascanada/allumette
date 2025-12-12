use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

pub type PlayerId = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Player {
    pub id: PlayerId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LobbyStatus {
    Waiting,
    InProgress,
}

#[derive(Debug, Clone, Serialize)]
pub struct Lobby {
    pub id: Uuid,
    pub owner: PlayerId,
    pub game_id: String,
    pub players: HashSet<PlayerId>,
    pub status: LobbyStatus,
    pub is_private: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whitelist: Option<HashSet<PlayerId>>,
}

/// Sanitized player info that only exposes if it's the current user
#[derive(Debug, Clone, Serialize)]
pub struct PlayerInfo {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub is_you: bool,
}

/// Sanitized lobby response DTO that hides sensitive information
#[derive(Debug, Clone, Serialize)]
pub struct LobbyResponse {
    pub id: Uuid,
    pub game_id: String,
    pub is_owner: bool,
    pub player_count: usize,
    pub players: Vec<PlayerInfo>,
    pub status: LobbyStatus,
    pub is_private: bool,
    pub is_whitelisted: bool,
}

impl Lobby {
    /// Convert to sanitized response DTO for a specific player
    pub fn to_response(&self, player_pubkey: Option<&String>) -> LobbyResponse {
        let is_owner = player_pubkey.map_or(false, |pk| pk == &self.owner);
        let is_whitelisted = player_pubkey.map_or(false, |pk| {
            self.whitelist.as_ref().map_or(true, |wl| wl.contains(pk))
        });

        // Only show full player public keys if the requester is in the lobby
        let is_in_lobby = player_pubkey.map_or(false, |pk| self.players.contains(pk));
        
        let players = if is_in_lobby {
            // If player is in the lobby, show all player public keys with is_you marker
            self.players
                .iter()
                .map(|p| PlayerInfo {
                    public_key: p.clone(),
                    is_you: player_pubkey.map_or(false, |pk| pk == p),
                })
                .collect()
        } else {
            // If player is not in the lobby, don't expose public keys - just show count as empty array
            vec![]
        };
        LobbyResponse {
            id: self.id,
            game_id: self.game_id.clone(),
            is_owner,
            player_count: self.players.len(),
            players,
            status: self.status.clone(),
            is_private: self.is_private,
            is_whitelisted,
        }
    }
}
