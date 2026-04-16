/**
 * CyberBuddy API Client
 * 
 * Handles all API calls. Uses mock/simulated responses for demonstration.
 */

import type { 
  ThreatScanResult, 
  ThreatModule,
  PhishingScanRequest,
  DDoSScanRequest,
  SQLiScanRequest,
  MalwareScanRequest,
} from './config';

// Simulated scan function (since no real backend is connected)
async function simulateScan(
  module: ThreatModule,
  _payload: object
): Promise<ThreatScanResult> {
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 1500 + Math.random() * 1000));
  
  const labels: Array<'Safe' | 'Suspicious' | 'Malicious'> = ['Safe', 'Suspicious', 'Malicious'];
  const label = labels[Math.floor(Math.random() * labels.length)];
  const confidence = 0.65 + Math.random() * 0.3;
  
  const detailsMap: Record<ThreatModule, Record<string, string>> = {
    phishing: {
      Safe: 'No phishing indicators detected. The content appears legitimate.',
      Suspicious: 'Some phishing patterns detected. The email contains suspicious links and urgency cues.',
      Malicious: 'High confidence phishing detected. Multiple indicators: spoofed sender, malicious URLs, credential harvesting attempt.',
    },
    ddos: {
      Safe: 'Network traffic appears normal. No DDoS patterns detected.',
      Suspicious: 'Unusual traffic spike detected. Possible volumetric attack in early stages.',
      Malicious: 'DDoS attack confirmed. High volume of SYN flood packets from multiple sources detected.',
    },
    sqli: {
      Safe: 'No SQL injection vulnerabilities found in the provided input.',
      Suspicious: 'Potential SQL injection pattern detected. Input contains suspicious characters.',
      Malicious: 'SQL injection attack detected. Payload contains UNION-based injection with data exfiltration attempt.',
    },
    malware: {
      Safe: 'File scan complete. No malware signatures or suspicious behaviors detected.',
      Suspicious: 'File contains obfuscated code that may indicate malicious intent.',
      Malicious: 'Malware detected! File matches known trojan signature with keylogging capabilities.',
    },
  };

  return {
    label,
    confidence,
    details: detailsMap[module][label],
    timestamp: new Date().toISOString(),
    module,
  };
}

export async function scanPhishing(request: PhishingScanRequest): Promise<ThreatScanResult> {
  return simulateScan('phishing', request);
}

export async function scanDDoS(request: DDoSScanRequest): Promise<ThreatScanResult> {
  return simulateScan('ddos', { trafficData: request.trafficData });
}

export async function scanSQLi(request: SQLiScanRequest): Promise<ThreatScanResult> {
  return simulateScan('sqli', request);
}

export async function scanMalware(request: MalwareScanRequest): Promise<ThreatScanResult> {
  return simulateScan('malware', request);
}

export async function scanThreat(
  module: ThreatModule,
  data: PhishingScanRequest | DDoSScanRequest | SQLiScanRequest | MalwareScanRequest
): Promise<ThreatScanResult> {
  switch (module) {
    case 'phishing': return scanPhishing(data as PhishingScanRequest);
    case 'ddos': return scanDDoS(data as DDoSScanRequest);
    case 'sqli': return scanSQLi(data as SQLiScanRequest);
    case 'malware': return scanMalware(data as MalwareScanRequest);
    default: throw new Error(`Unknown module: ${module}`);
  }
}

export interface IncidentLogRequest {
  scanResult: ThreatScanResult;
  userId: string;
}

export interface IncidentLogResponse {
  success: boolean;
  ipfsCid?: string;
  blockchainTxHash?: string;
  message: string;
}

export async function logIncidentToBlockchain(
  request: IncidentLogRequest
): Promise<IncidentLogResponse> {
  console.log('Logging incident to IPFS & Blockchain:', request);
  await new Promise(resolve => setTimeout(resolve, 1500));
  
  return {
    success: true,
    ipfsCid: `Qm${generateMockHash(44)}`,
    blockchainTxHash: `0x${generateMockHash(64)}`,
    message: 'Incident logged successfully (placeholder - wire actual logic later)',
  };
}

function generateMockHash(length: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}
