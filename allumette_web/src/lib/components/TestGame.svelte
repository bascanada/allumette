<script>
  import Avatar from "./Avatar.svelte";
  import { friendsStore, currentUser } from "../allumette-service.js";

  export let lobbyId;
  export let players = []; // Array of public keys or player objects
  export let token;

  let moves = Array(9).fill(null);
  let currentPlayer = 'X';

  // Force reactivity when friends list changes
  $: friends = $friendsStore;

  /**
   * Resolves a player's public key to a display name.
   * Priority: current user > player.username > friend name > truncated public key
   */
  function getPlayerDisplayName(player, friendsList) {
    const publicKey = typeof player === 'string' ? player : player.publicKey;

    // Check if it's the current user
    if ($currentUser?.publicKey === publicKey) {
      return $currentUser.username + ' (You)';
    }

    // If player object has a username, use it
    if (typeof player === 'object' && player.username) {
      return player.username;
    }

    // Check if this player is in our friends list
    const friend = friendsList.find(f => f.publicKey === publicKey);
    if (friend) {
      return friend.name;
    }

    // Fallback to truncated public key
    return publicKey.slice(0, 8) + '...';
  }

  function handleMove(index) {
    if (!moves[index]) {
      moves[index] = currentPlayer;
      currentPlayer = currentPlayer === 'X' ? 'O' : 'X';
      // In a real game, you'd send this move to the server here
      console.log(`Move at ${index} in lobby ${lobbyId} with token ${token}`);
    }
  }
</script>

<div class="test-game">
  <h2>Test Game (Tic Tac Toe style)</h2>
  <p>Lobby: {lobbyId}</p>

  <div class="players-container">
    {#each players as player}
      <div class="player">
          <Avatar value={typeof player === 'string' ? player : player.publicKey} size={80} />
          <span>{getPlayerDisplayName(player, friends)}</span>
      </div>
    {/each}
  </div>

  <div class="board">
    {#each moves as move, i}
      <button class="cell" on:click={() => handleMove(i)}>
        {move || ''}
      </button>
    {/each}
  </div>
</div>

<style>
  .test-game {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
    padding: 2rem;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  }
  .players-container {
      display: flex;
      gap: 2rem;
      margin-bottom: 1rem;
  }
  .player {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 0.5rem;
  }
  .board {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 5px;
    background: #ccc;
    padding: 5px;
  }
  .cell {
    width: 60px;
    height: 60px;
    background: white;
    border: none;
    font-size: 24px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .cell:hover {
    background: #f0f0f0;
  }
</style>
