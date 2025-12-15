<script>
  import { createLobby, friendsList } from "../allumette-service.js";
  import { toast } from "@zerodevx/svelte-toast";

  export let availableGames = [];

  let isPrivate = false;
  let gameId = availableGames.length > 0 ? availableGames[0].id : "";
  let selectedFriends = [];
  let isLoading = false;

  $: if (availableGames.length > 0 && !gameId) {
    gameId = availableGames[0].id;
  }

  async function handleCreateLobby() {
    isLoading = true;
    try {
      const whitelist = isPrivate ? selectedFriends : [];
      await createLobby(isPrivate, gameId, whitelist);
      toast.push("Lobby created successfully!", {
        classes: ["success-toast"],
      });
    } catch (error) {
      toast.push(error.message || "Failed to create lobby", {
        classes: ["error-toast"],
      });
    } finally {
      isLoading = false;
    }
  }
</script>

<div class="create-lobby-container card p-4 variant-soft-surface">
  <h3 class="h4 mb-3">Create New Lobby</h3>
  <form on:submit|preventDefault={handleCreateLobby} class="space-y-3">
    <label class="label">
      <span>Game:</span>
      <select class="select w-full" bind:value={gameId} required>
        {#each availableGames as game}
          <option value={game.id}>{game.name}</option>
        {/each}
      </select>
    </label>

    <label class="label flex items-center gap-2">
      <input type="checkbox" class="checkbox" bind:checked={isPrivate} />
      <span>Private Lobby</span>
    </label>

    {#if isPrivate && $friendsList.length > 0}
      <div class="label">
        <span>Whitelist Friends:</span>
        <div class="friends-checkbox-list space-y-2 mt-2 p-3 card variant-soft">
          {#each $friendsList as friend}
            <label class="flex items-center gap-2">
              <input
                type="checkbox"
                class="checkbox"
                value={friend.publicKey}
                bind:group={selectedFriends}
              />
              <span>{friend.username}</span>
            </label>
          {/each}
        </div>
      </div>
    {/if}

    <button
      type="submit"
      class="btn variant-filled-primary w-full"
      disabled={isLoading}
    >
      {#if isLoading}
        Creating...
      {:else}
        Create Lobby
      {/if}
    </button>
  </form>
</div>
