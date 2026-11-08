import { invoke } from "@tauri-apps/api/core";

export type ProxyMode = "off" | "http" | "socks5";

export interface ProxyConfig {
  mode: ProxyMode;
  host: string;
  username?: string | null;
  password?: string | null;
}

export async function getProxyConfig(): Promise<ProxyConfig> {
  return invoke<ProxyConfig>("get_proxy_config");
}

export async function setProxyConfig(
  mode: ProxyMode,
  host: string,
  username?: string,
  password?: string
): Promise<void> {
  return invoke("set_proxy_config", { mode, host, username, password });
}

export async function testProxy(): Promise<string> {
  return invoke<string>("test_proxy");
}
