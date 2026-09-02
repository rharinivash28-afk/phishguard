import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import LiveSentinel from './components/LiveSentinel';
import DeepInvestigator from './components/DeepInvestigator';
import IncidentReports from './components/IncidentReports';
import IncidentModal from './components/IncidentModal';
import GmailSettingsModal from './components/GmailSettingsModal';
import EmailSafetyModal from './components/EmailSafetyModal';
import { loadCache, saveCache, clearConnection } from './lib/persist';

// every request carries the session cookie
const api = (path, opts = {}) =>
  fetch(path, { credentials: 'include', ...opts }).then((r) => r);

export default function App() {
  const cache = useRef(loadCache());

  const [activeTab, setActiveTab] = useState('sentinel');
  const [inbox, setInbox] = useState([]);
  // hydrate metrics instantly from the last known good state, then reconcile
  const [stats, setStats] = useState(cache.current.lastStats);
  const [presets, setPresets] = useState([]);
  const [reports, setReports] = useState([]);
  const [config, setConfig] = useState({ durations: [1, 4, 12, 24, null], default_duration_hours: 24 });
  const [sessionReady, setSessionReady] = useState(false);
  const [connection, setConnection] = useState(() => {
    const c = cache.current;
    return c.connected
      ? {
          connected: true,
          email: c.email,
          expires_at: c.expiresAt,
          permanent: c.durationHours === null,
          seconds_remaining: c.expiresAt ? Math.max(0, Math.floor((Date.parse(c.expiresAt) - Date.now()) / 1000)) : null,
        }
      : { connected: false, status: 'AWAITING_CONNECTION' };
  });

  const [selectedEmailForInspection, setSelectedEmailForInspection] = useState(null);
  const [activeReportModal, setActiveReportModal] = useState(null);
  const [activeSafetyModalItem, setActiveSafetyModalItem] = useState(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [notification, setNotification] = useState(null);

  const showNotification = (msg, type = 'info') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 4000);
  };

  const gmailConnected = connection.connected;

  const fetchData = async () => {
    try {
      const [inboxRes, samplesRes, reportsRes] = await Promise.all([
        api('/api/sentinel/inbox').then((r) => r.json()),
        api('/api/samples').then((r) => r.json()),
        api('/api/sentinel/reports').then((r) => r.json()),
      ]);
      setInbox(inboxRes.inbox || []);
      setStats(inboxRes.stats || null);
      setPresets(samplesRes.presets || []);
      setReports(reportsRes.reports || []);
      saveCache({ lastStats: inboxRes.stats || null, lastInboxCount: (inboxRes.inbox || []).length });
    } catch (err) {
      console.error('Error fetching data:', err);
    }
  };

  const fetchConnectionStatus = async () => {
    try {
      const s = await api('/api/gmail/status').then((r) => r.json());
      setConnection(s);
      if (s.connected) {
        saveCache({
          connected: true,
          email: s.email || '',
          durationHours: s.duration_hours ?? (s.permanent ? null : cache.current.durationHours),
          connectedAt: s.connected_at || null,
          expiresAt: s.expires_at || null,
        });
      } else {
        if (s.status === 'EXPIRED' && cache.current.connected) {
          showNotification('Gmail session expired — connection closed and synced mail cleared', 'info');
          setInbox([]);
          setReports([]);
        }
        clearConnection();
        cache.current = loadCache();
      }
      cache.current = loadCache();
    } catch (err) {
      console.error(err);
    }
  };

  // establish the session cookie + load config first
  useEffect(() => {
    Promise.all([
      api('/api/session').then((r) => r.json()).catch(() => null),
      api('/api/config').then((r) => r.json()).catch(() => null),
    ]).then(([, cfg]) => {
      if (cfg) setConfig(cfg);
      setSessionReady(true);
    });
  }, []);

  useEffect(() => {
    if (!sessionReady) return undefined;
    fetchData();
    fetchConnectionStatus();
    const dataIv = setInterval(fetchData, 6000);
    const connIv = setInterval(fetchConnectionStatus, 10000);
    return () => {
      clearInterval(dataIv);
      clearInterval(connIv);
    };
  }, [sessionReady]);

  const handleQuarantineToggle = async (emailId, action) => {
    try {
      const res = await api('/api/sentinel/quarantine-action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_id: emailId, action }),
      });
      const data = await res.json();
      if (data.status === 'SUCCESS') {
        showNotification(
          action === 'quarantine' ? 'Email quarantined & blocked from inbox' : 'Email released from quarantine',
          action === 'quarantine' ? 'danger' : 'success'
        );
        fetchData();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleSimulateAttack = async () => {
    try {
      const res = await api('/api/sentinel/simulate-incoming', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      showNotification('Simulated phishing threat injected & auto-quarantined', 'danger');
      fetchData();
      if (data.item) setActiveSafetyModalItem(data.item);
    } catch (err) {
      console.error(err);
    }
  };

  const handleIngestCustomEmail = async (emailPayload) => {
    try {
      const res = await api('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(emailPayload),
      });
      const data = await res.json();
      showNotification(
        data.analysis.risk_score >= 50
          ? `Phishing threat detected (${data.analysis.risk_score}%) — quarantined`
          : `Email verified safe (${data.analysis.risk_score}%)`,
        data.analysis.risk_score >= 50 ? 'danger' : 'success'
      );
      fetchData();
      if (data.item) setActiveSafetyModalItem(data.item);
    } catch (err) {
      console.error(err);
    }
  };

  const handleUploadEml = async (file) => {
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await api('/api/upload-eml', { method: 'POST', body: formData });
      if (!res.ok) {
        const err = await res.json();
        showNotification(`Upload error: ${err.detail}`, 'danger');
        return;
      }
      const data = await res.json();
      showNotification(`Loaded message: "${data.item.subject}"`, 'success');
      fetchData();
      if (data.item) setActiveSafetyModalItem(data.item);
    } catch (err) {
      console.error(err);
      showNotification('Failed to process .eml file', 'danger');
    }
  };

  const handleInspectEmail = (emailItem) => {
    setSelectedEmailForInspection(emailItem);
    setActiveTab('investigator');
  };

  const handleViewReport = async (incidentId) => {
    try {
      const res = await api(`/api/sentinel/report/${incidentId}`);
      if (res.ok) {
        const data = await res.json();
        setActiveReportModal(data.report);
      } else {
        const found = reports.find((r) => r.incident_id === incidentId);
        if (found) setActiveReportModal(found);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleGenerateReportFromInvestigator = async (analysis, formData) => {
    try {
      const res = await api('/api/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sender_address: formData.sender_address,
          display_name: formData.display_name,
          subject: formData.subject,
          body: formData.body,
          recipient: formData.recipient || '',
          urls: (formData.urls || '').split('\n').filter(Boolean).map((u) => ({ url: u.trim(), anchor: '' })),
          attachments: [],
          spf_status: formData.spf_status,
          dkim_status: formData.dkim_status,
          dmarc_status: formData.dmarc_status,
        }),
      });
      const data = await res.json();
      if (data.report) {
        setActiveReportModal(data.report);
        fetchData();
      }
    } catch (err) {
      console.error(err);
    }
  };

  // returns the raw response so the modal can drive its progress bar
  const handleConnectGmail = async (email, appPassword, durationHours) => {
    saveCache({ durationHours: durationHours ?? null });
    cache.current = loadCache();
    try {
      const res = await api('/api/gmail/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, app_password: appPassword, duration_hours: durationHours }),
      });
      const data = await res.json();
      if (data.connected) {
        showNotification(
          `Gmail connected — monitoring ${email} (${data.new_emails_found ?? 0} messages pulled)`,
          'success'
        );
        setInbox([]); // purge any stale view immediately
        await fetchConnectionStatus();
        await fetchData();
      } else {
        showNotification(data.error || 'Gmail rejected the login.', 'danger');
      }
      return data;
    } catch (err) {
      console.error(err);
      return { connected: false, error: 'Network error reaching the backend.', phases: [] };
    }
  };

  const handleDisconnectGmail = async () => {
    try {
      await api('/api/gmail/disconnect', { method: 'POST' });
      showNotification('Gmail disconnected — your synced mail was cleared', 'info');
      clearConnection();
      cache.current = loadCache();
      setConnection({ connected: false, status: 'AWAITING_CONNECTION' });
      setInbox([]);
      setReports([]);
      fetchData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleToggleMonitoring = async (active) => {
    try {
      await api('/api/sentinel/toggle-active', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active }),
      });
      fetchData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleTriggerManualScan = async () => {
    try {
      showNotification('Scanning your Gmail inbox…', 'info');
      const res = await api('/api/sentinel/scan-now', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      const r = data.result || {};
      if (r.status === 'TRANSIENT') {
        showNotification('Temporary network issue — connection kept, will retry', 'info');
      } else if (r.status === 'EXPIRED') {
        showNotification('Gmail session expired', 'info');
        await fetchConnectionStatus();
      } else {
        showNotification(`Scan complete — ${r.new_emails_found ?? 0} new emails processed`, 'success');
      }
      fetchData();
    } catch (err) {
      console.error(err);
    }
  };

  // Refresh button: when Gmail is connected, actually poll it for new mail;
  // otherwise just re-sync workspace state. Returns { newCount } so the button
  // can animate a result.
  const handleSmartRefresh = async () => {
    try {
      if (gmailConnected) {
        const res = await api('/api/sentinel/scan-now', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        });
        const data = await res.json().catch(() => ({}));
        const r = data.result || {};
        if (r.status === 'EXPIRED') {
          showNotification('Gmail session expired', 'info');
          await fetchConnectionStatus();
          await fetchData();
          return { newCount: 0, expired: true };
        }
        if (r.status === 'TRANSIENT') {
          showNotification('Temporary network issue — connection kept, retrying', 'info');
          await fetchData();
          return { newCount: 0, transient: true };
        }
        const n = r.new_emails_found ?? 0;
        await fetchData();
        return { newCount: n };
      }
      await fetchData();
      return { newCount: 0 };
    } catch (err) {
      console.error(err);
      return { newCount: 0, error: true };
    }
  };

  const handleWipeWorkspace = async () => {
    try {
      await api('/api/session/wipe', { method: 'POST' });
      showNotification('Your workspace and all data were wiped', 'info');
      clearConnection();
      cache.current = loadCache();
      setInbox([]);
      setReports([]);
      setConnection({ connected: false, status: 'AWAITING_CONNECTION' });
      setActiveSafetyModalItem(null);
      setSelectedEmailForInspection(null);
      await api('/api/session');
      fetchData();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="min-h-screen flex flex-col text-white/90">
      {notification && (
        <div className={`fixed top-20 right-6 z-[60] px-4 py-2.5 rounded-xl text-xs font-semibold flex items-center gap-2 animate-slide-in glass-hi ${
          notification.type === 'danger' ? 'text-white' : notification.type === 'success' ? 'text-white/90' : 'text-white/70'
        }`}>
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${notification.type === 'danger' ? 'bg-white animate-pulse' : 'bg-white/50'}`} />
          <span>{notification.msg}</span>
        </div>
      )}

      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        stats={stats}
        connection={connection}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onConnectGmail={() => setIsSettingsOpen(true)}
        onSimulateAttack={handleSimulateAttack}
      />

      <div className="bg-white/[0.04] border-b border-white/10 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2 flex items-center gap-2 sm:gap-3 text-[11px]">
          <span className="pill-muted shrink-0">Private workspace</span>
          <p className="text-white/50 flex-1 leading-relaxed truncate sm:whitespace-normal sm:overflow-visible">
            <span className="hidden sm:inline">Zero-PII offline forensics. This browser has its own isolated inbox — nobody else can see it. Your Gmail app password is stored encrypted and only used to read your mail.</span>
            <span className="sm:hidden">Isolated to this browser · app password encrypted · zero-PII.</span>
          </p>
          <button onClick={handleWipeWorkspace} className="text-white/40 hover:text-white/80 transition shrink-0 font-mono whitespace-nowrap" title="Delete everything in this workspace">
            Wipe my data
          </button>
        </div>
      </div>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'sentinel' && (
          <LiveSentinel
            inbox={inbox}
            stats={stats}
            gmailConnected={gmailConnected}
            onRefresh={handleSmartRefresh}
            onQuarantineToggle={handleQuarantineToggle}
            onInspectEmail={handleInspectEmail}
            onViewReport={handleViewReport}
            onSimulateAttack={handleSimulateAttack}
            onOpenSafetyModal={(item) => setActiveSafetyModalItem(item)}
            onIngestCustomEmail={handleIngestCustomEmail}
            onUploadEml={handleUploadEml}
            onConnectGmail={() => setIsSettingsOpen(true)}
          />
        )}

        {activeTab === 'investigator' && (
          <DeepInvestigator
            initialEmail={selectedEmailForInspection}
            presets={presets}
            onGenerateReport={handleGenerateReportFromInvestigator}
            onViewReport={handleViewReport}
          />
        )}

        {activeTab === 'reports' && (
          <IncidentReports reports={reports} onViewReport={handleViewReport} />
        )}
      </main>

      <footer className="border-t border-white/10 py-4 text-center text-xs text-white/35 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row justify-between items-center gap-2">
          <span>PhishGuard AI • Enterprise Inbox Sentinel</span>
          <span>App-password IMAP • 4-tier deterministic engine • STIX 2.1</span>
        </div>
      </footer>

      {activeSafetyModalItem && (
        <EmailSafetyModal
          emailItem={activeSafetyModalItem}
          onClose={() => setActiveSafetyModalItem(null)}
          onInspect={handleInspectEmail}
          onViewReport={handleViewReport}
          onQuarantineToggle={handleQuarantineToggle}
        />
      )}

      {activeReportModal && (
        <IncidentModal report={activeReportModal} onClose={() => setActiveReportModal(null)} />
      )}

      {isSettingsOpen && (
        <GmailSettingsModal
          stats={stats}
          connection={connection}
          config={config}
          defaultDuration={cache.current.durationHours}
          onClose={() => setIsSettingsOpen(false)}
          onConnectGmail={handleConnectGmail}
          onDisconnectGmail={handleDisconnectGmail}
          onToggleMonitoring={handleToggleMonitoring}
          onTriggerScan={handleTriggerManualScan}
        />
      )}
    </div>
  );
}
