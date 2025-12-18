<script>
    import { onDestroy } from "svelte";
    import {
        lobbies,
        getLobbies,
        connectLobbyStream,
        disconnectLobbyStream,
        joinLobby,
        deleteLobby,
        inviteToLobby,
        friendsList,
        currentUser,
        isLoggedIn,
        jwt,
    } from "../allumette-service.js";
    import { toast } from "@zerodevx/svelte-toast";

    // Callback function that will be called when joining a lobby
    // Provides: { lobbyId, token, players, isPrivate }
    export let onJoinLobby = null;
    export let availableGames = [];

    let isLoading = false;
    let showInviteModal = false;
    let selectedLobbyForInvite = null;
    let selectedFriendsToInvite = [];

    // Filtering & Sorting State
    let searchQuery = "";
    let filterGame = "All";
    let filterPrivacy = "All";
    let filterStatus = "All";
    let sortBy = "created"; // "created" | "players"
    let sortDirection = "desc"; // "asc" | "desc"

    // Pagination State
    let currentPage = 1;
    let itemsPerPage = 5;

    // Reactive Logic
    $: filteredLobbies = $lobbies.filter((lobby) => {
        // Search Query (ID or Owner)
        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            const idMatch = lobby.id.toLowerCase().includes(query);
            // We don't have owner name easily accessible without looking it up, 
            // but we can check if any player name matches if we wanted.
            // For now, let's stick to Lobby ID.
            if (!idMatch) return false;
        }

        // Game Filter
        if (filterGame !== "All" && lobby.game_id !== filterGame) return false;

        // Privacy Filter
        if (filterPrivacy === "Public" && lobby.is_private) return false;
        if (filterPrivacy === "Private" && !lobby.is_private) return false;

        // Status Filter
        if (filterStatus === "Waiting" && lobby.status === "InProgress") return false;
        if (filterStatus === "InProgress" && lobby.status !== "InProgress") return false;

        return true;
    });

    $: sortedLobbies = [...filteredLobbies].sort((a, b) => {
        let comparison = 0;
        if (sortBy === "created") {
            // Assuming newer lobbies have higher/lexicographically later IDs or we rely on array order.
            // If IDs are not time-sortable, we might just rely on index.
            // Let's assume simple string comparison of IDs is a proxy for time if UUIDv7 or similar,
            // otherwise just stable sort.
            comparison = a.id.localeCompare(b.id);
        } else if (sortBy === "players") {
            comparison = a.players.length - b.players.length;
        }

        return sortDirection === "asc" ? comparison : -comparison;
    });

    $: totalPages = Math.ceil(sortedLobbies.length / itemsPerPage);
    $: paginatedLobbies = sortedLobbies.slice(
        (currentPage - 1) * itemsPerPage,
        currentPage * itemsPerPage
    );

    // Reset to page 1 when filters change
    $: {
        searchQuery;
        filterGame;
        filterPrivacy;
        filterStatus;
        sortBy;
        sortDirection;
        itemsPerPage;
        if (currentPage > totalPages && totalPages > 0) currentPage = 1;
        if (totalPages === 0) currentPage = 1;
    }

    // A map for quick friend lookups
    let friendMap = {};
    friendsList.subscribe((friends) => {
        friendMap = friends.reduce((acc, friend) => {
            acc[friend.publicKey] = friend.username;
            return acc;
        }, {});
    });

    // Helper function to get display name for a player
    // Accepts either a publicKey string or a player object { publicKey }
    function getPlayerDisplayName(player) {
        const publicKey =
            typeof player === "string" ? player : player?.publicKey;
        if (!publicKey) return "Unknown Player";
        // Check if it's the current user
        if ($currentUser?.publicKey === publicKey) {
            return $currentUser.username;
        }
        // Check if it's a friend
        return friendMap[publicKey] || `Player ${publicKey.substring(0, 8)}...`;
    }

    async function fetchLobbies() {
        isLoading = true;
        try {
            await getLobbies();
        } catch (error) {
            toast.push(error.message || "Failed to fetch lobbies", {
                classes: ["error-toast"],
            });
        } finally {
            isLoading = false;
        }
    }

    async function handleJoin(lobby) {
        const inLobby = isUserInLobby(lobby);

        // If user is already in the lobby, treat this as "Start Game" and call the callback
        if (inLobby) {
            if (onJoinLobby && typeof onJoinLobby === "function") {
                try {
                    const token = $jwt;
                    await onJoinLobby({
                        lobbyId: lobby.id,
                        token: token,
                        players: lobby.players,
                        isPrivate: lobby.is_private,
                        gameId: lobby.game_id,
                        userPublicKey: $currentUser?.publicKey,
                    });
                } catch (error) {
                    toast.push(error.message || "Failed to start game", {
                        classes: ["error-toast"],
                    });
                }
            } else {
                toast.push("No start-game callback provided", {
                    classes: ["error-toast"],
                });
            }
            return;
        }

        // Not in lobby -> join via API endpoint
        try {
            await joinLobby(lobby.id);
            toast.push("Joined lobby successfully!", {
                classes: ["success-toast"],
            });
        } catch (error) {
            toast.push(error.message || "Failed to join lobby", {
                classes: ["error-toast"],
            });
        }
    }

    async function handleDelete(lobbyId) {
        // Check if user is owner to show appropriate message
        const lobby = $lobbies.find((l) => l.id === lobbyId);
        const isOwner = lobby?.owner === $currentUser?.publicKey;

        try {
            await deleteLobby(lobbyId);
            toast.push(
                isOwner
                    ? "Lobby deleted successfully!"
                    : "Left lobby successfully!",
                { classes: ["success-toast"] },
            );
        } catch (error) {
            toast.push(
                error.message ||
                    (isOwner
                        ? "Failed to delete lobby"
                        : "Failed to leave lobby"),
                { classes: ["error-toast"] },
            );
        }
    }

    // Check if current user is in a lobby
    function isUserInLobby(lobby) {
        const userKey = $currentUser?.publicKey;
        if (!userKey || !lobby?.players) return false;
        // Players may be an array of publicKey strings or player objects { publicKey }
        return lobby.players.some(
            (p) => (typeof p === "string" ? p : p?.publicKey) === userKey,
        );
    }

    function openInviteModal(lobby) {
        selectedLobbyForInvite = lobby;
        selectedFriendsToInvite = [];
        showInviteModal = true;
    }

    function closeInviteModal() {
        showInviteModal = false;
        selectedLobbyForInvite = null;
        selectedFriendsToInvite = [];
    }

    async function handleInvite() {
        if (!selectedLobbyForInvite || selectedFriendsToInvite.length === 0) {
            toast.push("Please select at least one friend to invite", {
                classes: ["error-toast"],
            });
            return;
        }

        try {
            await inviteToLobby(
                selectedLobbyForInvite.id,
                selectedFriendsToInvite,
            );
            toast.push(
                `Invited ${selectedFriendsToInvite.length} friend(s) successfully!`,
                { classes: ["success-toast"] },
            );
            closeInviteModal();
        } catch (error) {
            toast.push(error.message || "Failed to invite friends", {
                classes: ["error-toast"],
            });
        }
    }

    // Get friends that are not already in the lobby and not in whitelist
    function getInvitableFriends(lobby) {
        const players = lobby?.players || [];
        return $friendsList.filter((friend) => {
            // Don't show if already in lobby (players may be strings or objects)
            if (
                players.some(
                    (p) =>
                        (typeof p === "string" ? p : p?.publicKey) ===
                        friend.publicKey,
                )
            )
                return false;
            // Don't show if already whitelisted
            if (lobby.whitelist && lobby.whitelist.includes(friend.publicKey))
                return false;
            return true;
        });
    }

    // Connect to SSE stream when login status changes
    $: if ($isLoggedIn) {
        // Connect to real-time lobby updates via SSE
        connectLobbyStream();
        // Do an initial fetch to get current state immediately
        fetchLobbies();
    } else {
        disconnectLobbyStream();
    }

    // Disconnect from SSE stream when component is destroyed
    onDestroy(() => {
        disconnectLobbyStream();
    });
</script>

{#if $isLoggedIn}
    <div class="lobby-list-container w-full">
        <div class="flex justify-between items-center mb-4">
            <h2 class="h3">Lobbies</h2>
            <span class="badge variant-filled-success">🟢 Live Updates</span>
        </div>

        {#if $lobbies.length === 0}
            <p class="text-center">No lobbies found.</p>
        {:else}
            <!-- Controls Bar -->
            <div class="card p-4 mb-4 space-y-4 variant-soft-surface">
                <div class="flex flex-col md:flex-row gap-4 justify-between">
                    <!-- Search -->
                    <div class="flex-1">
                        <input
                            class="input"
                            type="text"
                            placeholder="Search Lobby ID..."
                            bind:value={searchQuery}
                        />
                    </div>
                    
                    <!-- Filters -->
                    <div class="flex flex-wrap gap-2">
                        <select class="select w-auto" bind:value={filterGame}>
                            <option value="All">All Games</option>
                            {#each availableGames as game}
                                <option value={game.id}>{game.name}</option>
                            {/each}
                        </select>
                        <select class="select w-auto" bind:value={filterPrivacy}>
                            <option value="All">All Privacy</option>
                            <option value="Public">Public</option>
                            <option value="Private">Private</option>
                        </select>
                        <select class="select w-auto" bind:value={filterStatus}>
                            <option value="All">All Status</option>
                            <option value="Waiting">Waiting</option>
                            <option value="InProgress">In Progress</option>
                        </select>
                    </div>
                </div>

                <div class="flex flex-col md:flex-row gap-4 justify-between items-center text-sm">
                    <div class="flex gap-2 items-center">
                        <span>Sort by:</span>
                        <select class="select select-sm w-auto" bind:value={sortBy}>
                            <option value="created">Creation</option>
                            <option value="players">Players</option>
                        </select>
                        <button 
                            class="btn-icon btn-icon-sm variant-soft" 
                            on:click={() => sortDirection = sortDirection === 'asc' ? 'desc' : 'asc'}
                            title="Toggle Sort Direction"
                        >
                            {#if sortDirection === 'asc'}
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-4 h-4">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 10.5 12 3m0 0 7.5 7.5M12 3v18" />
                                </svg>
                            {:else}
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-4 h-4">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 13.5 12 21m0 0-7.5-7.5M12 21V3" />
                                </svg>
                            {/if}
                        </button>
                    </div>
                    <div>
                        Showing {paginatedLobbies.length} of {filteredLobbies.length} lobbies
                    </div>
                </div>
            </div>

            <div class="table-container w-full">
                <table class="table table-hover w-full text-center">
                    <thead>
                        <tr>
                            <th class="text-center">Privacy</th>
                            <th class="text-center">Game</th>
                            <th class="text-center w-1/4">Lobby ID</th>
                            <th class="text-center">State</th>
                            <th class="text-center">Players</th>
                            <th class="text-center">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {#each paginatedLobbies as lobby (lobby.id)}
                            <tr
                                class:variant-soft-success={isUserInLobby(
                                    lobby,
                                )}
                            >
                                <td data-label="Privacy" class="align-middle">
                                    <span
                                        class="badge {lobby.is_private
                                            ? 'variant-soft-warning'
                                            : 'variant-soft-tertiary'}"
                                        title={lobby.is_private ? "Private" : "Public"}
                                    >
                                        {lobby.is_private ? "🔒" : "🌐"}
                                    </span>
                                </td>
                                <td data-label="Game" class="align-middle">
                                    <span class="badge variant-soft-primary"
                                        >{lobby.game_id || "Unknown"}</span
                                    >
                                </td>
                                <td data-label="Lobby ID" class="align-middle max-w-[150px] sm:max-w-[250px] md:max-w-xs">
                                    <div class="truncate" title={lobby.id}>
                                        <code class="code text-xs">{lobby.id}</code>
                                    </div>
                                </td>
                                <td data-label="State" class="align-middle">
                                    <span
                                        class="badge {lobby.status ===
                                        'InProgress'
                                            ? 'variant-soft-error'
                                            : 'variant-soft-surface'}"
                                    >
                                        {lobby.status === "InProgress"
                                            ? "In Progress"
                                            : "Waiting"}
                                    </span>
                                </td>
                                <td data-label="Players" class="align-middle">
                                    {#if !lobby.is_private && !isUserInLobby(lobby)}
                                        <span class="opacity-70">N/A</span>
                                    {:else}
                                        <div class="flex flex-wrap gap-1 justify-center">
                                            {#each lobby.players as player}
                                                <span class="badge variant-soft-surface">
                                                    {#if (typeof player === "string" ? player : player?.publicKey) === $currentUser?.publicKey}
                                                        <strong>{getPlayerDisplayName(player)}</strong>
                                                    {:else}
                                                        {getPlayerDisplayName(player)}
                                                    {/if}
                                                </span>
                                            {/each}
                                        </div>
                                    {/if}
                                </td>
                                <td class="whitespace-nowrap align-middle" data-label="Actions">
                                    <div class="flex justify-center w-full actions-container">
                                    {#if !isUserInLobby(lobby)}
                                        {#if lobby.status === "InProgress"}
                                            <button
                                                class="btn btn-sm variant-filled-surface"
                                                disabled
                                            >
                                                In Progress
                                            </button>
                                        {:else}
                                            <button
                                                class="btn btn-sm variant-filled-success"
                                                on:click={() =>
                                                    handleJoin(lobby)}
                                            >
                                                Join
                                            </button>
                                        {/if}
                                    {:else}
                                        <div class="flex gap-2 flex-wrap justify-center">
                                            {#if onJoinLobby}
                                                <button
                                                    class="btn variant-filled-success btn-sm"
                                                    on:click={() =>
                                                        handleJoin(lobby)}
                                                >
                                                    Start Game
                                                </button>
                                            {/if}

                                            {#if lobby.owner === $currentUser?.publicKey}
                                                {#if lobby.is_private && getInvitableFriends(lobby).length > 0}
                                                    <button
                                                        class="btn variant-filled-primary btn-sm"
                                                        on:click={() =>
                                                            openInviteModal(
                                                                lobby,
                                                            )}
                                                    >
                                                        ➕ Invite
                                                    </button>
                                                {/if}
                                                <button
                                                    class="btn variant-filled-error btn-sm"
                                                    on:click={() =>
                                                        handleDelete(lobby.id)}
                                                >
                                                    Delete
                                                </button>
                                            {:else}
                                                <button
                                                    class="btn variant-filled-warning btn-sm"
                                                    on:click={() =>
                                                        handleDelete(lobby.id)}
                                                >
                                                    Quit
                                                </button>
                                            {/if}
                                        </div>
                                    {/if}
                                    </div>
                                </td>
                            </tr>
                        {/each}
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            {#if totalPages > 1}
                <div class="flex justify-center items-center gap-2 mt-4">
                    <button
                        class="btn btn-sm variant-soft"
                        disabled={currentPage === 1}
                        on:click={() => currentPage--}
                    >
                        Previous
                    </button>
                    <span class="text-sm">
                        Page {currentPage} of {totalPages}
                    </span>
                    <button
                        class="btn btn-sm variant-soft"
                        disabled={currentPage === totalPages}
                        on:click={() => currentPage++}
                    >
                        Next
                    </button>
                </div>
            {/if}
        {/if}
    </div>
{:else}
    <div class="lobby-list-container">
        <p class="text-center">Please log in to view and manage lobbies.</p>
    </div>
{/if}

<!-- Invite Modal -->
{#if showInviteModal && selectedLobbyForInvite}
    <div
        class="modal-backdrop"
        on:click={closeInviteModal}
        on:keydown={(e) => e.key === "Escape" && closeInviteModal()}
        role="button"
        tabindex="0"
    >
        <div
            class="modal-content card p-6 variant-filled-surface"
            on:click|stopPropagation
            on:keydown
            role="dialog"
            aria-modal="true"
            tabindex="-1"
        >
            <h3 class="h4">Invite Friends to Lobby</h3>
            <p class="text-sm opacity-75 mb-4">
                Lobby ID: <code class="code"
                    >{selectedLobbyForInvite.id.substring(0, 8)}...</code
                >
            </p>

            {#if getInvitableFriends(selectedLobbyForInvite).length === 0}
                <p>All your friends are already invited or in this lobby.</p>
            {:else}
                <div
                    class="friend-select-list space-y-2 p-3 card variant-soft max-h-60 overflow-y-auto"
                >
                    {#each getInvitableFriends(selectedLobbyForInvite) as friend}
                        <label
                            class="flex items-center gap-2 p-2 hover:variant-soft-primary cursor-pointer rounded"
                        >
                            <input
                                type="checkbox"
                                class="checkbox"
                                value={friend.publicKey}
                                bind:group={selectedFriendsToInvite}
                            />
                            <span>{friend.username}</span>
                        </label>
                    {/each}
                </div>
            {/if}

            <div class="flex gap-2 justify-end mt-4">
                <button class="btn variant-ghost" on:click={closeInviteModal}
                    >Cancel</button
                >
                <button
                    class="btn variant-filled-success"
                    on:click={handleInvite}
                    disabled={selectedFriendsToInvite.length === 0}
                >
                    Invite ({selectedFriendsToInvite.length})
                </button>
            </div>
        </div>
    </div>
{/if}

<style>
    .modal-backdrop {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
    }

    .modal-content {
        max-width: 500px;
        width: 90%;
        max-height: 80vh;
        overflow-y: auto;
    }

    @media (max-width: 768px) {
        /* Force table to not be like tables anymore */
        table,
        thead,
        tbody,
        th,
        td,
        tr {
            display: block;
        }

        /* Hide table headers (but not display: none;, for accessibility) */
        thead tr {
            position: absolute;
            top: -9999px;
            left: -9999px;
        }

        tr {
            border: 1px solid rgba(128, 128, 128, 0.2);
            margin-bottom: 1rem;
            border-radius: 8px;
            padding: 1rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        td {
            /* Behave  like a "row" */
            border: none;
            position: relative;
            padding: 0.5rem 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            text-align: right;
        }

        td:not(:last-child) {
            border-bottom: 1px solid rgba(128, 128, 128, 0.1);
        }

        td:before {
            /* Now like a table header */
            content: attr(data-label);
            font-weight: bold;
            margin-right: auto;
            padding-right: 1rem;
            opacity: 0.7;
        }

        td[data-label="Actions"] {
            flex-direction: column;
            align-items: stretch;
            margin-top: 0.5rem;
            border-bottom: none;
        }

        td[data-label="Actions"]:before {
            display: none;
        }
        
        /* Make buttons container full width */
        .actions-container {
            width: 100%;
            justify-content: stretch;
        }
        
        .actions-container button {
            flex: 1;
        }
    }
</style>
