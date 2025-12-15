<script>
  export let pubkey = "";
  export let start = 8; // chars to show at start
  export let end = 4; // chars to show at end

  const short = () => {
    if (!pubkey) return "";
    if (pubkey.length <= start + end + 3) return pubkey;
    return `${pubkey.slice(0, start)}...${pubkey.slice(-end)}`;
  };

  // copyFull removed — copy via select + Ctrl/Cmd+C is available
</script>

<span class="pubkey-component">
  <input
    type="text"
    readonly
    class="input input-sm font-mono"
    value={pubkey}
    title={pubkey}
    on:click={(e) => e.target.select()}
    aria-label="Public key"
  />
</span>

<style>
  .pubkey-component {
    display: inline-flex;
    gap: 8px;
    align-items: center;
  }

  .input-sm {
    padding: 0.375rem 0.5rem;
    font-size: 0.75rem;
  }

  .font-mono {
    font-family: ui-monospace, "Cascadia Code", "Source Code Pro", Menlo,
      Consolas, "DejaVu Sans Mono", monospace;
  }
</style>
