<script lang="ts">
  import { onMount } from "svelte";
  import { getProxyConfig, setProxyConfig, testProxy, type ProxyMode } from "#lib/services/proxy_service";
  import { t } from "#lib/i18n/index.svelte";

  let mode = $state<ProxyMode>("off");
  let host = $state("");
  let username = $state("");
  let password = $state("");
  let busy = $state(false);
  let status = $state("");
  let error = $state("");

  onMount(async () => {
    try {
      const cfg = await getProxyConfig();
      mode = cfg.mode;
      host = cfg.host;
      username = cfg.username ?? "";
      password = cfg.password ?? "";
    } catch (e) {
      error = String(e);
    }
  });

  async function save() {
    busy = true;
    status = "";
    error = "";
    try {
      await setProxyConfig(mode, host, username || undefined, password || undefined);
      status = "saved";
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function test() {
    busy = true;
    status = "";
    error = "";
    try {
      status = await testProxy();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="proxy-settings" style="padding:12px;display:flex;flex-direction:column;gap:10px;">
  <span class="label">Proxy (outbound — TCP/WS only)</span>
  <p style="font-size:12px;color:var(--text-dim);margin:0;">
    Routes outbound TCP/WebSocket connections through a proxy. QUIC stays direct.
    A proxy cannot make this node reachable from outside.
  </p>
  <select bind:value={mode} style="padding:8px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:8px;">
    <option value="off">Off</option>
    <option value="http">HTTP CONNECT</option>
    <option value="socks5">SOCKS5</option>
  </select>
  {#if mode !== "off"}
    <input bind:value={host} placeholder="host:port (e.g. 127.0.0.1:9050)" style="padding:8px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:8px;" />
    <input bind:value={username} placeholder="username (optional)" style="padding:8px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:8px;" />
    <input bind:value={password} type="password" placeholder="password (optional)" style="padding:8px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:8px;" />
  {/if}
  <div style="display:flex;gap:8px;">
    <button class="num-btn" disabled={busy} onclick={save}>Save</button>
    {#if mode !== "off"}
      <button class="num-btn special" disabled={busy} onclick={test}>Test</button>
    {/if}
  </div>
  {#if status}<span style="color:var(--accent);font-size:12px;">{status}</span>{/if}
  {#if error}<span style="color:var(--error);font-size:12px;">{error}</span>{/if}
</div>
