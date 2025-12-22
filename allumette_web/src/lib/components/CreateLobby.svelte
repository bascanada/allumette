<script>
  import { createLobby, friendsStore } from "../allumette-service.js";
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
      // Reset form fields
      gameId = availableGames.length > 0 ? availableGames[0].id : "";
      isPrivate = false;
      selectedFriends = [];
    } catch (error) {
      toast.push(error.message || "Failed to create lobby", {
        classes: ["error-toast"],
      });
    } finally {
      isLoading = false;
    }
  }

  function toggleFriend(friendKey) {
    if (selectedFriends.includes(friendKey)) {
        selectedFriends = selectedFriends.filter(k => k !== friendKey);
    } else {
        selectedFriends = [...selectedFriends, friendKey];
    }
  }
</script>

<div class="create-lobby-container">
  <h3 class="h3 mb-6 font-bold text-center">Create New Lobby</h3>
  <form on:submit|preventDefault={handleCreateLobby} class="space-y-6">
    <!-- Game Selection -->
    <label class="label">
      <span class="font-semibold text-lg ml-1">Select Game</span>
      <select class="select w-full mt-2 p-3 text-lg" bind:value={gameId} required>
        {#each availableGames as game}
          <option value={game.id}>{game.name}</option>
        {/each}
      </select>
    </label>

    <!-- Private Lobby Toggle -->
    <div class="flex items-center justify-between p-4 rounded-container-token border border-surface-400-500-token bg-surface-200-700-token shadow-sm">
        <div class="flex flex-col">
            <span class="font-bold text-lg flex items-center gap-2">
                {#if isPrivate}
                    🔒 Private Lobby
                {:else}
                    🌐 Public Lobby
                {/if}
            </span>
            <span class="text-sm opacity-80 mt-1">
                {#if isPrivate}
                    Only invited friends can join
                {:else}
                    Anyone can join this lobby
                {/if}
            </span>
        </div>
        <!-- Using a standard styled checkbox that acts as a switch/toggle visually -->
        <label class="flex items-center cursor-pointer relative">
            <input type="checkbox" class="sr-only peer" bind:checked={isPrivate}>
            <div class="w-11 h-6 bg-surface-600-300-token peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-surface-700-400-token peer-checked:after:translate-x-full peer-checked:after:border-surface-900-50-token after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-surface-900-50-token after:border-surface-500 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-surface-500 peer-checked:bg-primary-500"></div>
        </label>
    </div>

    <!-- Friends Whitelist -->
    {#if isPrivate}
      <div class="animate-fade-in card p-4 variant-ringed-surface bg-surface-50-900-token">
        <div class="flex justify-between items-end mb-4 border-b border-surface-400-500-token pb-2">
            <span class="font-bold text-lg">Invite Friends</span>
            <span class="badge variant-filled-secondary">{selectedFriends.length} selected</span>
        </div>
        
        {#if $friendsStore.length === 0}
            <div class="p-6 text-center opacity-70 italic">
                No friends found to invite. Add friends from the Friends tab!
            </div>
        {:else}
            <div class="friends-list space-y-3 max-h-60 overflow-y-auto p-1">
              {#each $friendsStore as friend (friend.publicKey)}
                <button 
                    type="button"
                    class="w-full text-left p-3 rounded-container-token flex items-center justify-between transition-all duration-200 border-2 cursor-pointer group {selectedFriends.includes(friend.publicKey) ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20' : 'border-surface-600-300-token hover:border-primary-400 hover:bg-surface-200 dark:hover:bg-surface-700'}"
                    on:click={() => toggleFriend(friend.publicKey)}
                >
                    <div class="flex items-center gap-3">
                        <!-- Visual Checkbox Indicator -->
                        <div class="w-6 h-6 rounded border-2 flex items-center justify-center transition-colors {selectedFriends.includes(friend.publicKey) ? 'bg-primary-500 border-primary-500' : 'bg-surface-900-50-token border-surface-600-300-token group-hover:border-primary-400'}">
                            {#if selectedFriends.includes(friend.publicKey)}
                                <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"></path></svg>
                            {/if}
                        </div>
                        <div class="flex flex-col">
                            <span class="font-bold text-base">{friend.name}</span>
                            <code class="text-xs opacity-70">{friend.publicKey.substring(0, 8)}...</code>
                        </div>
                    </div>
                </button>
              {/each}
            </div>
        {/if}
      </div>
    {/if}

    <button
      type="submit"
      class="btn variant-filled-primary w-full py-3 text-lg font-bold shadow-md hover:shadow-lg transition-shadow"
      disabled={isLoading}
    >
      {#if isLoading}
        <span class="opacity-70">Creating Lobby...</span>
      {:else}
        Create Lobby
      {/if}
    </button>
  </form>
</div>

<style>
    .animate-fade-in {
        animation: fadeIn 0.3s ease-in-out;
    }
    
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-5px); }
        to { opacity: 1; transform: translateY(0); }
    }
</style>
