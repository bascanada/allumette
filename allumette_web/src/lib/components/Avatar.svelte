<script>
  import { onMount, afterUpdate } from 'svelte';
  import * as jdenticon from 'jdenticon';

  export let value = "";
  export let size = 40;

  let svgElement;

  onMount(() => {
    jdenticon.configure({
      hues: [207, 270],
      lightness: { color: [0.40, 0.80], grayscale: [0.30, 0.90] },
      saturation: { color: 0.50, grayscale: 0.50 },
      backColor: "#00000000"
    });
    // Initial update
    if (svgElement && value) {
        jdenticon.update(svgElement, value);
    }
  });

  // Reactivity: Update when `value` changes
  $: if (svgElement && value) {
      jdenticon.update(svgElement, value);
  }
</script>

<svg bind:this={svgElement} width={size} height={size} viewBox="0 0 {size} {size}" class="avatar"></svg>

<style>
  .avatar {
    border-radius: 50%;
    background-color: #00000000;
  }
</style>
