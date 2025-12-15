<script>
  import {
    createAccount,
    loginWithSecret,
    loginWithWallet,
    logout,
    recoverAccount,
    isLoggedIn,
    currentUser,
  } from "../allumette-service.js";
  import { toast } from "@zerodevx/svelte-toast";

  // Component state
  let view = "initial"; // 'initial', 'secretKeyLogin', 'secretKeySignUp', 'walletLogin', 'secretKeyRecover'
  let username = "";
  let secret = "";
  let recoveryPhrase = "";
  let generatedRecoveryPhrase = "";
  let error = null;
  let isLoading = false;

  const handleSecretKeySignUp = async () => {
    if (!username) {
      error = "Username is required.";
      return;
    }
    isLoading = true;
    error = null;
    try {
      const result = await createAccount(username);
      // Store the generated credentials to show to user
      secret = result.secretKey;
      generatedRecoveryPhrase = result.recoveryPhrase;
      // Show success view with credentials
      view = "accountCreated";
    } catch (e) {
      error = e.message;
    } finally {
      isLoading = false;
    }
  };

  const handleSecretKeyLogin = async () => {
    if (!username || !secret) {
      error = "Username and Secret Key are required.";
      return;
    }
    isLoading = true;
    error = null;
    try {
      await loginWithSecret(username, secret);
      view = "loggedIn";
    } catch (e) {
      error = e.message;
    } finally {
      isLoading = false;
    }
  };

  const handleWalletLogin = async () => {
    isLoading = true;
    error = null;
    try {
      await loginWithWallet();
      view = "loggedIn";
    } catch (e) {
      error = e.message;
    } finally {
      isLoading = false;
    }
  };

  const handleRecovery = async () => {
    if (!username || !recoveryPhrase) {
      error = "Username and Recovery Phrase are required.";
      return;
    }
    isLoading = true;
    error = null;
    try {
      // This will currently fail, as the service function is a placeholder
      await recoverAccount(username, recoveryPhrase);
    } catch (e) {
      error = e.message;
    } finally {
      isLoading = false;
    }
  };

  const handleLogout = () => {
    logout();
    view = "initial";
    username = "";
    secret = "";
    recoveryPhrase = "";
    generatedRecoveryPhrase = "";
  };

  const handleContinueAfterSignup = () => {
    view = "loggedIn";
  };

  // Reset error on input change
  $: if (username || secret || recoveryPhrase) error = null;

  // Reactive view based on login state
  $: if ($isLoggedIn) {
    view = "loggedIn";
  }
</script>

<div class="allumette-auth-container">
  {#if view === "loggedIn"}
    <div class="welcome-view">
      <h3>Welcome, {$currentUser?.username}</h3>
      {#if $currentUser?.publicKey}
        <div class="pubkey-section card p-4 variant-soft-surface">
          <p class="pubkey-label font-semibold">Your Public Key:</p>
          <input
            type="text"
            readonly
            class="input"
            value={$currentUser.publicKey}
            on:click={(e) => e.target.select()}
          />
          <button
            class="btn variant-filled-success btn-sm mt-2"
            on:click={() => {
              navigator.clipboard.writeText($currentUser.publicKey);
              toast.push("Public key copied!", { classes: ["success-toast"] });
            }}
          >
            Copy Public Key
          </button>
        </div>
      {/if}
      <button class="btn variant-filled-surface" on:click={handleLogout}
        >Log Out</button
      >
    </div>
  {:else if view === "accountCreated"}
    <div class="credentials-view">
      <h2>Account Created!</h2>
      <div class="alert variant-filled-warning">
        <p>⚠️ Save these credentials securely. You won't see them again!</p>
      </div>

      <div class="credential-section">
        <p class="credential-label font-semibold">
          Secret Key (like a password)
        </p>
        <input
          type="text"
          readonly
          class="input"
          value={secret}
          on:click={(e) => e.target.select()}
        />
        <button
          class="btn variant-filled-success btn-sm mt-2"
          on:click={() => {
            navigator.clipboard.writeText(secret);
            toast.push("Secret key copied!", { classes: ["success-toast"] });
          }}
        >
          Copy Secret Key
        </button>
      </div>

      <div class="credential-section">
        <p class="credential-label font-semibold">Recovery Phrase (24 words)</p>
        <textarea
          readonly
          rows="4"
          class="textarea"
          value={generatedRecoveryPhrase}
          on:click={(e) => e.target.select()}
        ></textarea>
        <button
          class="btn variant-filled-success btn-sm mt-2"
          on:click={() => {
            navigator.clipboard.writeText(generatedRecoveryPhrase);
            toast.push("Recovery phrase copied!", {
              classes: ["success-toast"],
            });
          }}
        >
          Copy Recovery Phrase
        </button>
      </div>

      <button
        class="btn variant-filled-primary"
        on:click={handleContinueAfterSignup}
      >
        I've Saved My Credentials - Continue
      </button>
    </div>
  {:else if view === "initial"}
    <div class="initial-view">
      <h2>Join or Log In</h2>
      <button
        class="btn variant-filled-primary"
        on:click={() => (view = "secretKeySignUp")}
      >
        Create Account with Secret Key
      </button>
      <button
        class="btn variant-filled-primary"
        on:click={() => (view = "secretKeyLogin")}
      >
        Log In with Secret Key
      </button>
      <button
        class="btn variant-filled-secondary"
        on:click={() => (view = "secretKeyRecover")}
      >
        Recover Account
      </button>
      <button
        class="btn variant-filled-tertiary"
        on:click={handleWalletLogin}
        disabled={isLoading}
      >
        {isLoading ? "Connecting..." : "Log In with Wallet"}
      </button>
    </div>
  {:else if view === "secretKeySignUp" || view === "secretKeyLogin"}
    <div class="form-view">
      <h2>{view === "secretKeySignUp" ? "Create Account" : "Log In"}</h2>
      <input
        type="text"
        placeholder="Username"
        class="input"
        bind:value={username}
        disabled={isLoading}
      />
      {#if view === "secretKeyLogin"}
        <input
          type="password"
          placeholder="Secret Key (like a password)"
          class="input"
          bind:value={secret}
          disabled={isLoading}
          autocomplete="off"
        />
      {/if}
      {#if view === "secretKeySignUp"}
        <p class="info-text text-sm">
          A secret key will be generated for you after account creation.
        </p>
        <button
          class="btn variant-filled-primary"
          on:click={handleSecretKeySignUp}
          disabled={isLoading}
        >
          {isLoading ? "Creating..." : "Create Account"}
        </button>
      {:else}
        <button
          class="btn variant-filled-primary"
          on:click={handleSecretKeyLogin}
          disabled={isLoading}
        >
          {isLoading ? "Logging in..." : "Log In"}
        </button>
      {/if}
      <button
        class="btn variant-ghost-surface"
        on:click={() => (view = "initial")}
        disabled={isLoading}
      >
        &larr; Back
      </button>
    </div>
  {:else if view === "secretKeyRecover"}
    <div class="form-view">
      <h2>Recover Account</h2>
      <input
        type="text"
        placeholder="Username"
        class="input"
        bind:value={username}
        disabled={isLoading}
      />
      <input
        type="password"
        placeholder="Recovery Phrase"
        class="input"
        bind:value={recoveryPhrase}
        disabled={isLoading}
      />
      <button
        class="btn variant-filled-primary"
        on:click={handleRecovery}
        disabled={isLoading}
      >
        {isLoading ? "Recovering..." : "Recover"}
      </button>
      <button
        class="btn variant-ghost-surface"
        on:click={() => (view = "initial")}
        disabled={isLoading}
      >
        &larr; Back
      </button>
    </div>
  {/if}

  {#if error}
    <div class="alert variant-filled-error mt-4">
      <p>{error}</p>
    </div>
  {/if}
</div>

<style>
  .allumette-auth-container {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    max-width: 350px;
  }

  h2,
  h3 {
    text-align: center;
    color: rgb(var(--color-surface-900));
  }

  :global(.dark) h2,
  :global(.dark) h3 {
    color: rgb(var(--color-surface-50));
  }

  .initial-view,
  .form-view,
  .welcome-view,
  .credentials-view {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .credential-section {
    margin: 0.5rem 0;
  }

  .info-text {
    color: rgb(var(--color-surface-600));
    text-align: center;
    margin: 0.5rem 0;
  }

  :global(.dark) .info-text {
    color: rgb(var(--color-surface-400));
  }

  textarea {
    font-family: ui-monospace, "Cascadia Code", "Source Code Pro", Menlo,
      Consolas, "DejaVu Sans Mono", monospace;
    resize: vertical;
    min-height: 100px;
  }
</style>
