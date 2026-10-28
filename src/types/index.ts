export interface VpnProfile {
  id: string;
  name: string;
  host: string;
  port: number;
  auth_type: "Password" | "Saml";
  username: string | null;
  otp_required: boolean;
  realm: string | null;
  trusted_certs: string[];
  ignore_cert_errors: boolean;
  dns_match_domains: string[];
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
  dns_servers: string[];
  dns_domains: string[];
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

export function needsOtp(p: VpnProfile): boolean {
  return p.auth_type === "Password" && p.otp_required;
}

export function newProfile(): VpnProfile {
  return {
    id: "",
    name: "",
    host: "",
    port: 8443,
    auth_type: "Password",
    username: null,
    otp_required: false,
    realm: null,
    trusted_certs: [],
    ignore_cert_errors: false,
    dns_match_domains: [],
    extra_args: [],
  };
}
