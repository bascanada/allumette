<script>
  import AllumetteAuth from '$lib/components/AllumetteAuth.svelte';
  import AllumetteFriendsList from '$lib/components/AllumetteFriendsList.svelte';
  import AllumetteLobbies from '$lib/components/AllumetteLobbies.svelte';
  import TestGame from '$lib/components/TestGame.svelte';
  import { toast } from '@zerodevx/svelte-toast';

  let activeGame = null;
  const availableGames = [
    { id: 'test-game', name: 'Test Game (TicTacToe)' }
  ];

  // Clipboard helper with fallback for environments where navigator.clipboard isn't available
  async function copyToClipboard(text) {
    if (!text) throw new Error('No token provided');
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        // Preferred modern API - requires secure context (https or localhost)
        await navigator.clipboard.writeText(text);
        return;
      }

      // Fallback: show a prompt with the token so the user can copy manually.
      // This avoids using the deprecated document.execCommand('copy').
      const manual = window.prompt('Copy the token below (Ctrl/Cmd+C + Enter):', text);
      if (manual === null) {
        throw new Error('Manual copy cancelled');
      }
    } catch (err) {
      throw new Error('Copy failed: ' + (err?.message || err));
    }
  }

  // onJoinLobby callback: receives { lobbyId, token, players, isPrivate }
  async function handleStartFromLobby(params) {
    const { lobbyId, token, players, isPrivate } = params;
    try {
      if (!token) {
        toast.push('No token available; please log in.');
        return;
      }
      await copyToClipboard(token);
      toast.push('Token copied to clipboard — ready to start.');
      console.log('Start game', { lobbyId, players, isPrivate });
      activeGame = params;
    } catch (err) {
      toast.push(err.message || 'Failed to process start');
      console.error(err);
    }
  }
</script>

<div class="page-container">
  <h1>Allumette Auth Component Test</h1>

  <div class="info">
    <h3>📦 Svelte Integration Demo</h3>
    <p>This page demonstrates the Allumette authentication component and friends list as Svelte components.</p>
    <p>Use the auth component to create/login; the friends list will appear when you're logged in.</p>
  </div>

  {#if activeGame}
    <div class="active-game-container">
      <button class="btn-back" on:click={() => activeGame = null}>← Back to Lobbies</button>
      <TestGame {...activeGame} />
    </div>
  {:else}
    <div class="components">
      <AllumetteAuth />
      <AllumetteFriendsList />
      <AllumetteLobbies {availableGames} onJoinLobby={handleStartFromLobby} />
    </div>
  {/if}
</div>

<style>
  :global(body) {
    font-family: Arial, sans-serif;
    margin: 0;
    background-color: #f0f2f5;
  }

  .page-container {
    max-width: 900px;
    margin: 40px auto;
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    align-items: center;
  }

  h1 {
    color: #333;
    margin: 0;
  }

  .info {
    background-color: #e3f2fd;
    border-left: 4px solid #2196f3;
    padding: 15px;
    width: 100%;
    border-radius: 4px;
  }

  .components {
    display: flex;
    gap: 20px;
    width: 100%;
    justify-content: center;
    align-items: flex-start;
  }

  .active-game-container {
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 20px;
  }

  .btn-back {
    align-self: flex-start;
    padding: 8px 16px;
    background-color: #eee;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }
  .btn-back:hover {
    background-color: #ddd;
  }

  /* Ensure components stack on small screens */
  @media (max-width: 800px) {
    .components {
      flex-direction: column;
      align-items: stretch;
    }
  }
</style>
