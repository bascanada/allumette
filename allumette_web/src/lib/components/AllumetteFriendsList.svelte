<script>
    import {
        friendsList,
        generateMyFriendCode,
        addFriendFromCode,
        removeFriend,
        isLoggedIn,
    } from "../allumette-service.js";
    import { toast } from "@zerodevx/svelte-toast";
    import PubKeyDisplay from "./PubKeyDisplay.svelte";

    let friendCodeToAdd = "";

    function handleAddFriend() {
        if (!friendCodeToAdd) return;
        try {
            addFriendFromCode(friendCodeToAdd);
            friendCodeToAdd = "";
            toast.push("Friend added successfully!", {
                classes: ["success-toast"],
            });
        } catch (error) {
            toast.push(error.message, {
                classes: ["error-toast"],
            });
        }
    }

    async function handleCopyFriendCode() {
        try {
            const myFriendCode = generateMyFriendCode();
            await navigator.clipboard.writeText(myFriendCode);
            toast.push("Your Friend Code has been copied to the clipboard!", {
                classes: ["success-toast"],
            });
        } catch (error) {
            toast.push("Failed to copy Friend Code.", {
                classes: ["error-toast"],
            });
        }
    }
</script>

<div class="friends-list-container">
    {#if $isLoggedIn}
        <h2>Friends</h2>

        {#if $friendsList.length === 0}
            <p class="text-center">
                Your friends list is empty. Add a friend using their Friend
                Code!
            </p>
        {/if}

        <ul class="list">
            {#each $friendsList as friend (friend.publicKey)}
                <li
                    class="card p-3 variant-soft-surface flex justify-between items-center"
                >
                    <div class="friend-info">
                        <strong>{friend.username}</strong>
                        <PubKeyDisplay pubkey={friend.publicKey} />
                    </div>
                    <button
                        class="btn-icon variant-filled-error"
                        on:click={() => removeFriend(friend.publicKey)}
                        title="Remove friend"
                        aria-label="Remove {friend.username}"
                    >
                        <svg
                            xmlns="http://www.w3.org/2000/svg"
                            width="20"
                            height="20"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        >
                            <path d="M3 6h18"></path>
                            <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"
                            ></path>
                            <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path>
                        </svg>
                    </button>
                </li>
            {/each}
        </ul>

        <div class="add-friend-section">
            <h3>Add Friend</h3>
            <input
                type="text"
                bind:value={friendCodeToAdd}
                placeholder="Enter Friend Code"
                class="input"
            />
            <button
                class="btn variant-filled-primary"
                on:click={handleAddFriend}>Add</button
            >
        </div>

        <div class="my-friend-code-section">
            <button
                class="btn variant-filled-success"
                on:click={handleCopyFriendCode}>Share my Friend Code</button
            >
        </div>
    {:else}
        <p class="text-center">Please log in to see your friends list.</p>
    {/if}
</div>

<style>
    .friends-list-container {
        max-width: 400px;
    }

    h2,
    h3 {
        color: rgb(var(--color-surface-900));
    }

    :global(.dark) h2,
    :global(.dark) h3 {
        color: rgb(var(--color-surface-50));
    }

    .list {
        list-style: none;
        padding: 0;
        margin: 0;
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }

    .list li {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 1rem;
    }

    .friend-info {
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 0.25rem;
    }

    .friend-info strong {
        color: rgb(var(--color-surface-900));
    }

    :global(.dark) .friend-info strong {
        color: rgb(var(--color-surface-50));
    }

    .add-friend-section,
    .my-friend-code-section {
        margin-top: 1rem;
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }
</style>
