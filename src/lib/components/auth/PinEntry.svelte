<script lang="ts">
  import Button from '../ui/Button.svelte';
  import { t } from '#lib/i18n/index.svelte';

  let {
    pin = '',
    length = 8,
    maxLength = 64,
    busy = false,
    minLength = 0,
    showDisplay = true,
    oninput,
    onsubmit
  }: {
    pin?: string;
    /** Dots rendered — the visual minimum the backend requires. */
    length?: number;
    /** Hard input cap — backend accepts 8–64. */
    maxLength?: number;
    /** Disable every key while an auth request is in flight. */
    busy?: boolean;
    /** OK stays disabled until pin reaches this length (0 = always armed). */
    minLength?: number;
    /** OPT-F03: callers with a richer display (clear button, hints) hide
     *  the built-in one and keep only the shared numpad. */
    showDisplay?: boolean;
    oninput?: (value: string) => void;
    onsubmit?: (value: string) => void;
  } = $props();

  function handleKey(key: string) {
    // FE-22: a PIN must never touch console.log — credentials in plaintext
    // logs are a credential-exposure bug, not a debugging aid.
    if (key === 'C') {
      oninput?.('');
    } else if (key === '⌫') {
      oninput?.(pin.slice(0, -1));
    } else if (key === 'OK') {
      onsubmit?.(pin);
    } else if (pin.length < maxLength) {
      oninput?.(pin + key);
    }
  }
</script>

{#if showDisplay}
<div class="pin-display animate-fade-in">
  {#each Array(length) as _, i}
    <div class="pin-dot {pin.length > i ? 'active' : ''}"></div>
  {/each}
  {#if pin.length > length}
    <span class="pin-extra">+{pin.length - length}</span>
  {/if}
</div>
{/if}

<div class="numpad" class:busy>
  {#each ["1", "2", "3", "4", "5", "6", "7", "8", "9", "⌫", "0", "OK"] as key}
    <Button
      variant={key === 'OK' || key === '⌫' ? 'primary' : 'secondary'}
      size="lg"
      onclick={() => handleKey(key)}
      className={key === 'OK' || key === '⌫' ? 'special' : ''}
      disabled={busy || (key === 'OK' && pin.length < minLength)}
      type="button"
      ariaLabel={key === '⌫' ? t('auth.pin.backspace') : key}
    >
      {key}
    </Button>
  {/each}
</div>

<style>
  .pin-display {
    display: flex;
    gap: 12px;
    margin: 40px 0;
  }

  .pin-dot {
    width: 14px;
    height: 14px;
    border-radius: var(--radius-full);
    border: 2px solid var(--border-subtle);
    transition: all var(--duration-fast) var(--ease-default);
  }

  .pin-dot.active {
    background: var(--primary);
    border-color: var(--primary);
    transform: scale(1.2);
    box-shadow: 0 0 10px var(--primary-glow);
  }

  .pin-extra {
    align-self: center;
    font-size: 14px;
    color: var(--text-secondary);
    margin-left: 4px;
  }

  .numpad {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    width: 100%;
    max-width: 320px;
  }

  .numpad.busy {
    opacity: 0.5;
    pointer-events: none;
  }

  .numpad :global(.btn) {
    touch-action: manipulation;
    user-select: none;
    -webkit-tap-highlight-color: transparent;
  }
</style>
