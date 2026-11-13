// Relay / NAT types — mirror serde shapes in src-tauri/src/p2p/relay_*.rs

/** Node relay role (serde snake_case). */
export type NodeRole = "auto" | "relay" | "client";

/** Privacy mode (serde snake_case). */
export type PrivacyMode = "direct" | "relayed_only";

/** Persisted relay configuration (relay_config.json, snake_case fields). */
export interface RelayConfig {
  role: NodeRole;
  privacy: PrivacyMode;
  listen_port: number;
  max_reservations: number;
  max_reservations_per_peer: number;
  reservation_duration_secs: number;
  max_circuits: number;
  max_circuits_per_peer: number;
  max_circuit_duration_secs: number;
  max_circuit_bytes: number;
}

/** NAT reachability measured by AutoNAT/UPnP (serde snake_case). */
export type NatStatus = "unknown" | "public" | "private";

/** Live relay/NAT snapshot (serde camelCase). */
export interface RelayStatus {
  natStatus: NatStatus;
  isRelaying: boolean;
  externalAddrs: string[];
  relayedAddrs: string[];
  activeReservations: number;
  inboundReservations: number;
  activeCircuits: number;
  knownRelays: number;
  peersConnected: number;
  /** External QUIC addr kept alive by the 20s STUN PersistentKeepalive. */
  stunAddr?: string | null;
  /** NAT mapping mode: "public_port_mapped" | "stun_cone" | "stun_symmetric" | "stun_mapped" | "unknown". */
  natMapping?: string;
  /** AutoNAT probe window expired with no verdict — honest "unreachable". */
  probeExhausted?: boolean;
  /** Per-addr reachability evidence: canonical addr → state. */
  addrEvidence?: Record<string, "verified" | "candidate" | "failed">;
}
