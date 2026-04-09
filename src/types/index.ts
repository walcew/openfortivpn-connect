export interface VpnProfile {
  id: string;
  name: string;
  host: string;
  port: number;
  auth_type: "Password" | "Saml";
  username: string | null;
  realm: string | null;
  trusted_certs: string[];
  extra_args: string[];
}

export interface ConnectionStatus {
  state:
    | "Disconnected"
    | "Connecting"
    | "WaitingSaml"
    | "Connected"
    | "Disconnecting"
    | "Error";
  profile_id: string | null;
  ip: string | null;
  since: string | null;
  message: string | null;
}

export interface LogLine {
  timestamp: string;
  level: string;
  message: string;
}

export interface CertWarningPayload {
  digest: string;
  profile_id: string;
}

export interface BandwidthData {
  rx_bytes: number;
  tx_bytes: number;
  rx_speed: number;
  tx_speed: number;
  timestamp: string;
}

export function newProfile(): VpnProfile {
  return {
    id: "",
    name: "",
    host: "",
    port: 8443,
    auth_type: "Password",
    username: null,
    realm: null,
    trusted_certs: [],
    extra_args: [],
  };
}
