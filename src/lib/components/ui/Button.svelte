<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    variant = 'primary' as 'primary' | 'secondary' | 'ghost' | 'danger',
    size = 'md' as 'sm' | 'md' | 'lg',
    disabled = false,
    loading = false,
    type = 'button' as 'button' | 'submit' | 'reset',
    className = '',
    style = '',
    ariaLabel = '',
    onclick,
    onsubmit,
    children
  }: {
    variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
    size?: 'sm' | 'md' | 'lg';
    disabled?: boolean;
    loading?: boolean;
    type?: 'button' | 'submit' | 'reset';
    className?: string;
    style?: string;
    ariaLabel?: string;
    onclick?: () => void;
    onsubmit?: () => void;
    children: Snippet;
  } = $props();
</script>

<button
  {type}
  class="btn btn-{variant} btn-{size} {className}"
  class:loading
  class:disabled
  style={style}
  aria-label={ariaLabel || undefined}
  onclick={onclick}
  onsubmit={onsubmit}
  disabled={disabled || loading}
>
  {#if loading}
    <span class="spinner spinner-sm"></span>
  {/if}
  <span class="content">
    {@render children()}
  </span>
</button>

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    border: none;
    border-radius: var(--radius-lg);
    font-family: var(--font-main);
    font-weight: var(--font-semibold);
    cursor: pointer;
    transition: all var(--duration-fast) var(--ease-default);
    position: relative;
    overflow: hidden;
    pointer-events: auto;
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    pointer-events: none;
  }

  .btn:not(:disabled):hover {
    transform: translateY(-1px);
  }

  .btn:not(:disabled):active {
    transform: translateY(0);
  }

  .btn .content {
    pointer-events: none;
  }

  /* Variants */
  .btn-primary {
    background: var(--primary);
    color: var(--text-inverse);
    box-shadow: var(--shadow-sm);
  }

  .btn-primary:hover:not(:disabled) {
    background: var(--primary-hover);
    box-shadow: var(--shadow-md), 0 0 20px var(--primary-glow);
  }

  .btn-secondary {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border-default);
  }

  .btn-secondary:hover:not(:disabled) {
    background: var(--bg-elevated);
    border-color: var(--border-strong);
  }

  .btn-ghost {
    background: transparent;
    color: var(--text-primary);
  }

  .btn-ghost:hover:not(:disabled) {
    background: var(--bg-tertiary);
  }

  .btn-danger {
    background: var(--error);
    color: white;
  }

  .btn-danger:hover:not(:disabled) {
    background: var(--error);
  }

  /* Sizes */
  .btn-sm {
    padding: 8px 16px;
    font-size: var(--text-sm);
    height: 36px;
  }

  .btn-md {
    padding: 12px 24px;
    font-size: var(--text-base);
    height: 44px;
  }

  .btn-lg {
    padding: 16px 32px;
    font-size: var(--text-lg);
    height: 52px;
  }

  .loading .content {
    opacity: 0;
  }
</style>
