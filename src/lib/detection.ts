/**
 * Rule-based threat detection. Provides high-precision deterministic
 * verdicts. The edge function (Lovable AI) is used as a fallback for
 * ambiguous cases.
 */

import type {
  ThreatLabel,
  ThreatModule,
  PhishingScanRequest,
  DDoSScanRequest,
  SQLiScanRequest,
  MalwareScanRequest,
} from './config';

export interface RuleVerdict {
  label: ThreatLabel;
  confidence: number;
  details: string;
  ambiguous: boolean; // true => caller should consult AI fallback
  source?: string;
  destination?: string;
}

const PHISHING_KEYWORDS = [
  'verify your account', 'urgent action required', 'suspended', 'click here to confirm',
  'update your payment', 'unusual sign-in', 'limited time', 'wire transfer', 'gift card',
  'reset your password', 'banking alert', 'lottery', 'inheritance', 'crypto giveaway',
  'we noticed unusual activity', 'login immediately', 'avoid account closure',
];
const PHISHING_BRANDS = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'netflix', 'bank'];
const SUSPICIOUS_TLDS = ['.zip', '.xyz', '.top', '.click', '.country', '.gq', '.tk', '.ml'];

function countMatches(text: string, list: string[]) {
  const t = text.toLowerCase();
  return list.reduce((n, k) => n + (t.includes(k) ? 1 : 0), 0);
}

export function detectPhishing(req: PhishingScanRequest): RuleVerdict {
  const body = (req.emailBody || '').toLowerCase();
  const url = (req.url || '').toLowerCase();
  let score = 0;
  const reasons: string[] = [];

  const kw = countMatches(body, PHISHING_KEYWORDS);
  if (kw > 0) { score += kw * 2; reasons.push(`${kw} phishing phrase(s) detected`); }

  const brand = countMatches(body, PHISHING_BRANDS);
  if (brand > 0 && body.includes('http')) { score += brand; reasons.push('brand impersonation cues'); }

  if (url) {
    if (SUSPICIOUS_TLDS.some(t => url.endsWith(t) || url.includes(t + '/'))) {
      score += 4; reasons.push('suspicious top-level domain');
    }
    if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url)) {
      score += 4; reasons.push('IP-address URL (no domain)');
    }
    if (/https?:\/\/[^/]{40,}/.test(url)) {
      score += 2; reasons.push('unusually long hostname');
    }
    if (/(paypa1|micros0ft|g00gle|amaz0n|app1e)/.test(url)) {
      score += 5; reasons.push('typosquatted brand domain');
    }
    if (url.includes('@')) { score += 3; reasons.push('embedded credentials in URL'); }
  }

  if (req.imageName) {
    score += 1; reasons.push('screenshot submitted for visual inspection');
  }

  let label: ThreatLabel = 'Safe';
  let confidence = 0.92;
  if (score >= 4) { label = 'Malicious'; confidence = Math.min(0.97, 0.78 + score * 0.025); }
  else if (score >= 1) { label = 'Suspicious'; confidence = 0.7 + Math.min(0.2, score * 0.06); }

  const details = score === 0
    ? 'No phishing indicators detected. Content/URL appear legitimate.'
    : `Detected ${score} risk indicator(s): ${reasons.join('; ')}.`;

  console.log('[detectPhishing]', { score, reasons, label, confidence });

  return {
    label, confidence, details,
    ambiguous: score >= 1 && score < 4 && !!req.emailBody,
    source: 'user@cyberbuddy.local',
    destination: req.url || (req.emailBody ? 'inbox' : 'screenshot'),
  };
}

export function detectDDoS(req: DDoSScanRequest): RuleVerdict {
  const data = req.trafficData || '';
  const lines = data.split(/\n+/).filter(Boolean);
  const ips = data.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || [];
  const uniqueIps = new Set(ips).size;
  const synFloods = (data.match(/SYN/gi) || []).length;
  const reasons: string[] = [];
  let score = 0;

  if (lines.length > 200) { score += 3; reasons.push(`${lines.length} traffic events`); }
  if (uniqueIps > 100) { score += 4; reasons.push(`${uniqueIps} unique source IPs`); }
  else if (uniqueIps > 30) { score += 2; reasons.push(`${uniqueIps} unique source IPs`); }
  if (synFloods > 50) { score += 4; reasons.push(`${synFloods} SYN packets`); }
  if (/UDP.*flood|amplification|reflection/i.test(data)) { score += 3; reasons.push('amplification pattern'); }
  if (/botnet|mirai/i.test(data)) { score += 5; reasons.push('botnet signature'); }

  let label: ThreatLabel = 'Safe';
  let confidence = 0.9;
  if (score >= 5) { label = 'Malicious'; confidence = Math.min(0.98, 0.8 + score * 0.02); }
  else if (score >= 2) { label = 'Suspicious'; confidence = 0.75 + Math.min(0.18, score * 0.05); }

  const details = score === 0
    ? 'Network traffic baseline is normal. No DDoS indicators.'
    : `DDoS indicators (score ${score}): ${reasons.join('; ')}.`;

  console.log('[detectDDoS]', { lines: lines.length, uniqueIps, synFloods, score, reasons, label });

  const firstIp = ips[0];
  return {
    label, confidence, details,
    ambiguous: score >= 2 && score < 5,
    source: firstIp || 'multiple sources',
    destination: 'protected endpoint',
  };
}

const SQLI_PATTERNS: { re: RegExp; weight: number; label: string }[] = [
  { re: /'\s*or\s*'?1'?\s*=\s*'?1/i, weight: 6, label: "tautology ' OR '1'='1" },
  { re: /union\s+select/i,           weight: 6, label: 'UNION SELECT' },
  { re: /;\s*drop\s+table/i,         weight: 7, label: 'DROP TABLE' },
  { re: /information_schema/i,        weight: 5, label: 'information_schema probe' },
  { re: /sleep\s*\(\s*\d+\s*\)/i,     weight: 5, label: 'time-based SLEEP' },
  { re: /benchmark\s*\(/i,            weight: 5, label: 'BENCHMARK' },
  { re: /load_file\s*\(/i,            weight: 6, label: 'LOAD_FILE' },
  { re: /xp_cmdshell/i,               weight: 7, label: 'xp_cmdshell' },
  { re: /--\s|#\s/,                   weight: 2, label: 'SQL comment' },
  { re: /%27|%22/i,                   weight: 1, label: 'URL-encoded quotes' },
];

export function detectSQLi(req: SQLiScanRequest): RuleVerdict {
  const text = `${req.url || ''} ${req.requestString || ''}`;
  const decoded = (() => { try { return decodeURIComponent(text); } catch { return text; } })();
  let score = 0;
  const reasons: string[] = [];
  for (const p of SQLI_PATTERNS) {
    if (p.re.test(decoded)) { score += p.weight; reasons.push(p.label); }
  }

  let label: ThreatLabel = 'Safe';
  let confidence = 0.93;
  if (score >= 5) { label = 'Malicious'; confidence = Math.min(0.99, 0.85 + score * 0.015); }
  else if (score >= 1) { label = 'Suspicious'; confidence = 0.74 + Math.min(0.18, score * 0.05); }

  const details = score === 0
    ? 'No SQL injection patterns detected in the input.'
    : `SQLi patterns (score ${score}): ${reasons.join(', ')}.`;

  console.log('[detectSQLi]', { score, reasons, label, confidence, decoded: decoded.slice(0, 200) });

  const dest = (() => { try { return new URL(req.url || '').host; } catch { return req.url || 'unknown'; } })();

  return {
    label, confidence, details,
    ambiguous: false,
    source: 'client',
    destination: dest,
  };
}

const MALWARE_EXTS = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.ps1', '.dll', '.msi', '.hta'];
const MALWARE_STRINGS = ['eicar', 'TVqQAAMAAAAEAAAA', 'cmd.exe /c', 'powershell -enc', 'CreateRemoteThread', 'VirtualAllocEx', 'WScript.Shell', 'Invoke-Expression', 'mimikatz'];

export function detectMalware(req: MalwareScanRequest): RuleVerdict {
  const name = (req.fileName || '').toLowerCase();
  const text = req.fileText || '';
  let score = 0;
  const reasons: string[] = [];

  if (MALWARE_EXTS.some(e => name.endsWith(e))) { score += 4; reasons.push(`risky extension (${name.split('.').pop()})`); }
  if (/\.(pdf|docx?|xlsx?)\.exe$/.test(name)) { score += 5; reasons.push('double-extension trick'); }
  for (const s of MALWARE_STRINGS) {
    if (text.toLowerCase().includes(s.toLowerCase())) { score += 4; reasons.push(`signature: ${s}`); }
  }
  if (req.fileSize && req.fileSize > 50 * 1024 * 1024) { score += 1; reasons.push('unusually large file'); }
  if (/X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR/.test(text)) { score += 10; reasons.push('EICAR test signature'); }

  let label: ThreatLabel = 'Safe';
  let confidence = 0.94;
  if (score >= 4) { label = 'Malicious'; confidence = Math.min(0.99, 0.84 + score * 0.018); }
  else if (score >= 1) { label = 'Suspicious'; confidence = 0.72 + Math.min(0.2, score * 0.06); }

  const details = score === 0
    ? 'No malware signatures or suspicious behaviors detected.'
    : `Malware indicators (score ${score}): ${reasons.join('; ')}.`;

  console.log('[detectMalware]', { name, size: req.fileSize, score, reasons, label });

  return {
    label, confidence, details,
    ambiguous: score >= 1 && score < 4,
    source: 'uploaded file',
    destination: req.fileName || 'unknown',
  };
}

export function detectByModule(
  module: ThreatModule,
  data: PhishingScanRequest | DDoSScanRequest | SQLiScanRequest | MalwareScanRequest
): RuleVerdict {
  switch (module) {
    case 'phishing': return detectPhishing(data as PhishingScanRequest);
    case 'ddos':     return detectDDoS(data as DDoSScanRequest);
    case 'sqli':     return detectSQLi(data as SQLiScanRequest);
    case 'malware':  return detectMalware(data as MalwareScanRequest);
  }
}
