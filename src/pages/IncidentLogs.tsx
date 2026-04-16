import { useState } from 'react';
import { Database, ExternalLink, Clock, CheckCircle, Loader2, Eye, AlertTriangle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { useToast } from '@/hooks/use-toast';
import { logIncidentToBlockchain } from '@/lib/apiClient';
import { LABEL_COLORS, type ThreatLabel } from '@/lib/config';
import { cn } from '@/lib/utils';
import { useAuth } from '@/hooks/useAuth';

interface Incident {
  id: string;
  created_at: string;
  module: string;
  label: string;
  confidence: number;
  details: string | null;
  ipfsCid: string | null;
  blockchainTxHash: string | null;
  status: 'Confirmed' | 'Pending';
}

const moduleLabels: Record<string, string> = {
  phishing: 'Phishing', ddos: 'DDoS', sqli: 'SQL Injection', malware: 'Malware',
};

const demoIncidents: Incident[] = [
  { id: '1', created_at: new Date(Date.now() - 3600000).toISOString(), module: 'phishing', label: 'Malicious', confidence: 0.94, details: 'Detected phishing patterns.', ipfsCid: null, blockchainTxHash: null, status: 'Pending' },
  { id: '2', created_at: new Date(Date.now() - 7200000).toISOString(), module: 'ddos', label: 'Safe', confidence: 0.87, details: 'No DDoS indicators.', ipfsCid: null, blockchainTxHash: null, status: 'Pending' },
  { id: '3', created_at: new Date(Date.now() - 10800000).toISOString(), module: 'sqli', label: 'Suspicious', confidence: 0.72, details: 'Potential SQL injection pattern.', ipfsCid: null, blockchainTxHash: null, status: 'Pending' },
];

export default function IncidentLogsPage() {
  const [incidents, setIncidents] = useState<Incident[]>(demoIncidents);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [loggingId, setLoggingId] = useState<string | null>(null);
  const { toast } = useToast();
  const { user } = useAuth();

  const handleLogToBlockchain = async (incident: Incident) => {
    setLoggingId(incident.id);
    try {
      const result = await logIncidentToBlockchain({
        scanResult: {
          label: incident.label as ThreatLabel,
          confidence: incident.confidence,
          details: incident.details || '',
          timestamp: incident.created_at,
          module: incident.module as any,
        },
        userId: user?.id || 'unknown',
      });

      if (result.success) {
        setIncidents(prev => prev.map(inc =>
          inc.id === incident.id
            ? { ...inc, ipfsCid: result.ipfsCid!, blockchainTxHash: result.blockchainTxHash!, status: 'Confirmed' as const }
            : inc
        ));
        toast({ title: 'Incident Logged', description: result.message });
      }
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : 'Failed to log incident';
      toast({ variant: 'destructive', title: 'Logging Failed', description: msg });
    } finally {
      setLoggingId(null);
    }
  };

  const getLabelColors = (label: string) => LABEL_COLORS[label as ThreatLabel] || LABEL_COLORS['Suspicious'];

  return (
    <div className="container mx-auto px-4 py-12">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-2"><span className="text-gradient-primary">Incident Logs</span></h1>
        <p className="text-muted-foreground">View and manage security incidents logged to IPFS and blockchain.</p>
        <div className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-accent/10 border border-accent/30 text-accent text-sm">
          <Database className="h-4 w-4" />IPFS + Blockchain integration (Testnet Placeholder)
        </div>
      </div>

      <Card className="cyber-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-foreground">
            <Clock className="h-5 w-5 text-primary" />Logged Incidents ({incidents.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {incidents.length === 0 ? (
            <div className="text-center py-12">
              <AlertTriangle className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">No incidents yet. Run a scan first.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Date/Time</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Module</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Threat</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">IPFS CID</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Blockchain Tx</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Status</th>
                    <th className="text-right py-3 px-4 text-sm font-medium text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((incident) => {
                    const labelColors = getLabelColors(incident.label);
                    return (
                      <tr key={incident.id} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
                        <td className="py-3 px-4">
                          <span className="text-sm text-foreground">{new Date(incident.created_at).toLocaleDateString()}</span><br />
                          <span className="text-xs text-muted-foreground">{new Date(incident.created_at).toLocaleTimeString()}</span>
                        </td>
                        <td className="py-3 px-4 text-sm text-foreground">{moduleLabels[incident.module] || incident.module}</td>
                        <td className="py-3 px-4">
                          <span className={cn('inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border', labelColors.bg, labelColors.text, labelColors.border)}>{incident.label}</span>
                        </td>
                        <td className="py-3 px-4">
                          {incident.ipfsCid ? (
                            <a href={`https://ipfs.io/ipfs/${incident.ipfsCid}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline font-mono">
                              {incident.ipfsCid.slice(0, 10)}...<ExternalLink className="h-3 w-3" />
                            </a>
                          ) : <span className="text-xs text-muted-foreground">Not logged</span>}
                        </td>
                        <td className="py-3 px-4">
                          {incident.blockchainTxHash ? (
                            <a href={`https://etherscan.io/tx/${incident.blockchainTxHash}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-secondary hover:underline font-mono">
                              {incident.blockchainTxHash.slice(0, 10)}...<ExternalLink className="h-3 w-3" />
                            </a>
                          ) : <span className="text-xs text-muted-foreground">Not logged</span>}
                        </td>
                        <td className="py-3 px-4">
                          <span className={cn('inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium',
                            incident.status === 'Confirmed' ? 'bg-cyber-green/10 text-cyber-green border border-cyber-green/30' : 'bg-cyber-amber/10 text-cyber-amber border border-cyber-amber/30'
                          )}>
                            {incident.status === 'Confirmed' && <CheckCircle className="h-3 w-3" />}{incident.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <Button variant="ghost" size="sm" onClick={() => setSelectedIncident(incident)}><Eye className="h-4 w-4" /></Button>
                            {incident.status === 'Pending' && (
                              <Button size="sm" onClick={() => handleLogToBlockchain(incident)} disabled={loggingId === incident.id} className="glow-cyan">
                                {loggingId === incident.id ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Log to Chain'}
                              </Button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={!!selectedIncident} onOpenChange={() => setSelectedIncident(null)}>
        <DialogContent className="cyber-card max-w-lg">
          <DialogHeader><DialogTitle className="text-foreground">Incident Details</DialogTitle></DialogHeader>
          {selectedIncident && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div><span className="text-sm text-muted-foreground">Module</span><p className="font-medium text-foreground">{moduleLabels[selectedIncident.module]}</p></div>
                <div><span className="text-sm text-muted-foreground">Threat</span><p className={cn('font-medium', getLabelColors(selectedIncident.label).text)}>{selectedIncident.label}</p></div>
                <div><span className="text-sm text-muted-foreground">Confidence</span><p className="font-mono text-foreground">{(selectedIncident.confidence * 100).toFixed(1)}%</p></div>
                <div><span className="text-sm text-muted-foreground">Status</span><p className="font-medium text-foreground">{selectedIncident.status}</p></div>
              </div>
              {selectedIncident.ipfsCid && (
                <div className="p-3 rounded-lg bg-muted/50 border border-border">
                  <span className="text-xs text-muted-foreground">IPFS CID</span>
                  <p className="font-mono text-xs text-primary break-all">{selectedIncident.ipfsCid}</p>
                </div>
              )}
              {selectedIncident.blockchainTxHash && (
                <div className="p-3 rounded-lg bg-muted/50 border border-border">
                  <span className="text-xs text-muted-foreground">Blockchain Tx</span>
                  <p className="font-mono text-xs text-secondary break-all">{selectedIncident.blockchainTxHash}</p>
                </div>
              )}
              <div className="p-4 rounded-lg bg-muted/50 border border-border">
                <h5 className="text-sm font-semibold text-foreground mb-2">Details</h5>
                <p className="text-muted-foreground text-sm">{selectedIncident.details}</p>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
