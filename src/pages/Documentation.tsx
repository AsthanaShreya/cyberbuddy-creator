import { Book, Code, Terminal, Settings, FileCode, Zap } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const sections = [
  {
    id: 'overview', title: 'Overview of CyberBuddy', icon: Book,
    content: `CyberBuddy is an AI-powered cyber threat detection and decentralized incident reporting platform. It combines advanced machine learning models with blockchain technology to provide comprehensive security analysis and immutable incident logging.

The platform supports four main threat detection modules:
• Phishing Detection - Analyzes emails and URLs for phishing attempts
• DDoS/Intrusion Detection - Monitors network traffic for attack patterns
• SQL Injection Detection - Scans URLs and requests for injection vulnerabilities
• Malware Detection - Analyzes files for malicious signatures`,
  },
  {
    id: 'modules', title: 'Threat Modules Explained', icon: Zap,
    content: `Each threat detection module uses specialized machine learning models trained on large datasets:

**Phishing Scanner** - Uses NLP models to analyze email content, URL patterns, and sender information.
**DDoS/Intrusion Scanner** - Analyzes network traffic patterns, packet distributions, and connection behaviors.
**SQL Injection Scanner** - Examines URL parameters and HTTP requests for SQL injection patterns.
**Malware Scanner** - Uses signature-based and behavioral analysis to detect malware.`,
  },
  {
    id: 'usage', title: 'How to Use the Scanner', icon: Terminal,
    content: `1. Sign up or log in to your CyberBuddy account
2. Navigate to Threat Scanner from the navigation menu
3. Select a module by clicking on the appropriate tab
4. Enter your data in the provided input fields
5. Click "Scan" to submit for analysis
6. Review results showing threat label, confidence score, and details
7. Optionally log incidents to IPFS and blockchain for verification`,
  },
  {
    id: 'api-models', title: 'About AI Models', icon: FileCode,
    content: `CyberBuddy integrates with ML services for threat detection:

**Phishing Model** - Based on transformer architecture, trained on phishing email datasets
**DDoS Model** - Uses Random Forest and Deep Learning ensemble, trained on NSL-KDD/CICIDS
**SQL Injection Model** - Rule-based + ML hybrid approach trained on web attack datasets
**Malware Model** - Static and dynamic analysis combined with malware signature databases`,
  },
];

const apiDocs = {
  endpoints: [
    { method: 'POST', path: '/api/scan/phishing', description: 'Scan email/URL for phishing',
      request: `{ "emailBody": "Dear user, your account...", "url": "https://suspicious-link.com" }`,
      response: `{ "label": "Malicious", "confidence": 0.94, "details": "Detected phishing patterns...", "module": "phishing" }` },
    { method: 'POST', path: '/api/scan/ddos', description: 'Analyze network traffic for DDoS',
      request: `{ "trafficData": "192.168.1.1,80,TCP,..." }`,
      response: `{ "label": "Safe", "confidence": 0.87, "details": "No DDoS indicators", "module": "ddos" }` },
    { method: 'POST', path: '/api/scan/sqli', description: 'Check URL for SQL injection',
      request: `{ "url": "https://example.com/page?id=1", "requestString": "GET /page?id=1' OR '1'='1" }`,
      response: `{ "label": "Suspicious", "confidence": 0.72, "details": "SQL injection attempt detected", "module": "sqli" }` },
    { method: 'POST', path: '/api/scan/malware', description: 'Scan file for malware',
      request: `{ "fileName": "suspicious.exe", "fileContent": "base64_encoded_content" }`,
      response: `{ "label": "Malicious", "confidence": 0.98, "details": "Known malware signature detected", "module": "malware" }` },
  ],
};

export default function DocumentationPage() {
  return (
    <div className="container mx-auto px-4 py-12">
      <div className="mb-12">
        <h1 className="text-4xl font-bold mb-4"><span className="text-gradient-primary">Documentation</span></h1>
        <p className="text-muted-foreground max-w-2xl">Learn how to use CyberBuddy, understand our threat detection modules, and explore the API.</p>
      </div>

      <div className="space-y-8 mb-16">
        {sections.map((section) => (
          <Card key={section.id} className="cyber-card" id={section.id}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-foreground">
                <section.icon className="h-5 w-5 text-primary" />{section.title}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="prose prose-invert max-w-none">
                {section.content.split('\n').map((paragraph, idx) => (
                  <p key={idx} className="text-muted-foreground whitespace-pre-wrap mb-2">{paragraph}</p>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="mb-8">
        <h2 className="text-3xl font-bold mb-6 flex items-center gap-2">
          <Code className="h-7 w-7 text-primary" /><span className="text-gradient-secondary">API Reference</span>
        </h2>
      </div>

      <Card className="cyber-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-foreground">
            <Terminal className="h-5 w-5 text-primary" />API Endpoints
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-8">
            {apiDocs.endpoints.map((endpoint) => (
              <div key={endpoint.path} className="border-b border-border/50 pb-6 last:border-0 last:pb-0">
                <div className="flex items-center gap-3 mb-3">
                  <span className="px-2 py-1 rounded bg-cyber-green/20 text-cyber-green text-xs font-mono font-bold">{endpoint.method}</span>
                  <code className="text-primary font-mono">{endpoint.path}</code>
                </div>
                <p className="text-muted-foreground text-sm mb-4">{endpoint.description}</p>
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <span className="text-xs text-muted-foreground font-semibold">Request</span>
                    <pre className="mt-1 p-3 rounded-lg bg-muted/50 text-sm text-foreground overflow-x-auto font-mono border border-border">{endpoint.request}</pre>
                  </div>
                  <div>
                    <span className="text-xs text-muted-foreground font-semibold">Response</span>
                    <pre className="mt-1 p-3 rounded-lg bg-muted/50 text-sm text-foreground overflow-x-auto font-mono border border-border">{endpoint.response}</pre>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
