<script>
    import {
        friendsList,
        generateMyFriendCode,
        addFriendFromCode,
        removeFriend,
        isLoggedIn,
        encryptionKey,
    } from "../allumette-service.js";
    import { toast } from "@zerodevx/svelte-toast";
    import PubKeyDisplay from "./PubKeyDisplay.svelte";
    import { encryptData, decryptData } from "../crypto-utils.js";

    let friendCodeToAdd = "";
    let showImport = false;
    let importString = "";

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

    async function handleExportFriends() {
        if ($friendsList.length === 0) {
            toast.push("No friends to export.", { classes: ["warning-toast"] });
            return;
        }
        try {
            if (!$encryptionKey) throw new Error("Encryption key not available");
            const encrypted = await encryptData($friendsList, $encryptionKey);
            const json = JSON.stringify(encrypted);
            const exportString = btoa(json);
            await navigator.clipboard.writeText(exportString);
            toast.push("Friend list backup copied to clipboard!", { classes: ["success-toast"] });
        } catch (e) {
            console.error(e);
            toast.push("Failed to export friends.", { classes: ["error-toast"] });
        }
    }

    async function handleImportFriends() {
        if (!importString) return;
        try {
            const json = atob(importString);
            const encryptedObj = JSON.parse(json);
            
            if (!$encryptionKey) throw new Error("Encryption key not available");
            const importedList = await decryptData(encryptedObj, $encryptionKey);
            
            if (!Array.isArray(importedList)) throw new Error("Invalid format");
            

            const currentKeys = new Set($friendsList.map(f => f.publicKey));
            
            // We can't update the store directly inside a loop cleanly if it's not a method on service, 
            // but we can update the store via the service or just update the list here since we have the store import.
            // But `friendsList` is a writable store.
            
            // Filter out existing friends
            const newFriends = importedList.filter(f => {
                if (!f.username || !f.publicKey) return false;
                return !currentKeys.has(f.publicKey);
            });

            if (newFriends.length > 0) {
                friendsList.update(current => [...current, ...newFriends]);
                toast.push(`Successfully restored ${newFriends.length} friends!`, { classes: ["success-toast"] });
            } else {
                toast.push("No new friends found in backup.", { classes: ["warning-toast"] });
            }
            
            importString = "";
            showImport = false;
        } catch (e) {
            console.error(e);
            toast.push("Failed to import: Invalid backup string.", { classes: ["error-toast"] });
        }
    }
</script>

<div class="friends-list-container">
    {#if $isLoggedIn}
        <div class="flex justify-between items-center">
            <h2>Friends</h2>
            <div class="flex gap-2">
                <button class="btn-icon btn-icon-sm variant-soft" on:click={handleExportFriends} title="Backup Friends">
                    💾
                </button>
                <button class="btn-icon btn-icon-sm variant-soft" on:click={() => showImport = !showImport} title="Restore Friends">
                    📥
                </button>
            </div>
        </div>

        {#if showImport}
            <div class="card p-3 mb-4 variant-soft-secondary">
                <h4 class="h5 mb-2">Restore Backup</h4>
                <textarea class="textarea mb-2 text-xs" rows="3" placeholder="Paste backup string here..." bind:value={importString}></textarea>
                <div class="flex justify-end gap-2">
                    <button class="btn btn-sm variant-ghost" on:click={() => showImport = false}>Cancel</button>
                    <button class="btn btn-sm variant-filled-primary" on:click={handleImportFriends}>Restore</button>
                </div>
            </div>
        {/if}

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
