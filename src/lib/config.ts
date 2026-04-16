/**
 * CyberBuddy Configuration
 */

export type ThreatModule = 'phishing' | 'ddos' | 'sqli' | 'malware';
export type ThreatLabel = 'Malicious' | 'Safe' | 'Suspicious';

export interface ThreatScanResult {
  label: ThreatLabel;
  confidence: number;
  details: string;
  timestamp: string;
  module: ThreatModule;
  error?: string;
}

export interface ApiErrorResponse {
  error: string;
  code?: string;
}

export interface PhishingScanRequest {
  emailBody?: string;
  url?: string;
}

export interface DDoSScanRequest {
  trafficData?: string;
  logFile?: File;
}

export interface SQLiScanRequest {
  url?: string;
  requestString?: string;
}

export interface MalwareScanRequest {
  fileName?: string;
  fileContent?: string;
}

export const MODULE_CONFIG: Record<ThreatModule, {
  name: string;
  description: string;
  endpoint: string;
  icon: string;
}> = {
  phishing: {
    name: 'Phishing Scanner',
    description: 'Detects phishing attempts in emails and URLs',
    endpoint: '/scan/phishing',
    icon: '🎣',
  },
  ddos: {
    name: 'DDoS/Intrusion Scanner',
    description: 'Analyzes network traffic for DDoS and intrusion patterns',
    endpoint: '/scan/ddos',
    icon: '🛡️',
  },
  sqli: {
    name: 'SQL Injection Scanner',
    description: 'Detects SQL injection vulnerabilities in URLs and requests',
    endpoint: '/scan/sqli',
    icon: '💉',
  },
  malware: {
    name: 'Malware Scanner',
    description: 'Scans files for malware signatures and suspicious patterns',
    endpoint: '/scan/malware',
    icon: '🦠',
  },
};

export const LABEL_COLORS: Record<ThreatLabel, {
  bg: string;
  text: string;
  border: string;
}> = {
  Safe: {
    bg: 'bg-cyber-green/10',
    text: 'text-cyber-green',
    border: 'border-cyber-green/30',
  },
  Suspicious: {
    bg: 'bg-cyber-amber/10',
    text: 'text-cyber-amber',
    border: 'border-cyber-amber/30',
  },
  Malicious: {
    bg: 'bg-cyber-red/10',
    text: 'text-cyber-red',
    border: 'border-cyber-red/30',
  },
};
