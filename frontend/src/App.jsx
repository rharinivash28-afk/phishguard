import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import LiveSentinel from './components/LiveSentinel';
import DeepInvestigator from './components/DeepInvestigator';
import IncidentReports from './components/IncidentReports';
import IncidentModal from './components/IncidentModal';
import GmailSettingsModal from './components/GmailSettingsModal';
import EmailSafetyModal from './components/EmailSafetyModal';
import GoogleOAuthModal from './components/GoogleOAuthModal';

export default function App() {
  const [activeTab, setActiveTab] = useState('sentinel');
  const [inbox, setInbox] = useState([]);
  const [stats, setStats] = useState(null);
  const [samples, setSamples] = useState([]);
  const [reports, setReports] = useState([]);
  const [config, setConfig] = useState({ demo_mode: false, allow_live_gmail: true });
  const [bannerDismissed, setBannerDismissed] = useState(false);

  const liveGmailAllowed = !config.demo_mode || config.allow_live_gmail;

  const [selectedEmailForInspection, setSelectedEmailForInspection] = useState(null);
  const [activeReportModal, setActiveReportModal] = useState(null);
  const [activeSafetyModalItem, setActiveSafetyModalItem] = useState(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isOAuthModalOpen, setIsOAuthModalOpen] = useState(false);
  const [notification, setNotification] = useState(null);

  const showNotification = (msg, type = 'info') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 4000);
  };

  // Fetch initial data
  const fetchData = async () => {
    try {
      const [inboxRes, samplesRes, reportsRes] = await Promise.all([
        fetch('/api/sentinel/inbox').then(r => r.json()),
        fetch('/api/samples').then(r => r.json()),
        fetch('/api/sentinel/reports').then(r => r.json())
      ]);

      setInbox(inboxRes.inbox || []);
      setStats(inboxRes.stats || null);
      setSamples(samplesRes.samples || []);
      setReports(reportsRes.reports || []);
    } catch (err) {
      console.error('Error fetching data:', err);
    }
  };

  useEffect(() => {
    fetchData();
    fetch('/api/config')
      .then(r => r.json())
      .then(cfg => setConfig(cfg))
      .catch(() => {});
    const interval = setInterval(fetchData, 6000);
    return () => clearInterval(interval);
  }, []);

  // Handle the Google OAuth redirect back from the backend callback
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const gmail = params.get('gmail');
    if (!gmail) return;
    if (gmail === 'connected') {
      showNotification(`Gmail connected${params.get('email') ? ` — ${params.get('email')}` : ''}. Loading your inbox…`, 'success');
      // wipe whatever was on screen from a previous account, then re-pull
      setInbox([]);
      setReports([]);
      setActiveSafetyModalItem(null);
      setSelectedEmailForInspection(null);
      fetchData();
      setTimeout(fetchData, 1500);
      setTimeout(fetchData, 4000);
    } else if (gmail === 'error') {
      showNotification(`Gmail connection failed: ${params.get('reason') || 'unknown error'}`, 'danger');
      setIsOAuthModalOpen(true);
    }
    window.history.replaceState({}, '', window.location.pathname);
  }, []);

  const handleQuarantineToggle = async (emailId, action) => {
    try {
      const res = await fetch('/api/sentinel/quarantine-action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_id: emailId, action })
      });
      const data = await res.json();
      if (data.status === 'SUCCESS') {
        showNotification(
          action === 'quarantine' ? 'Email Quarantined & Blocked from Inbox' : 'Email Released from Quarantine',
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
      const res = await fetch('/api/sentinel/simulate-incoming', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      showNotification('New Phishing Threat Injected & Auto-Quarantined!', 'danger');
      fetchData();
      if (data.item) {
        setActiveSafetyModalItem(data.item);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleIngestCustomEmail = async (emailPayload) => {
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(emailPayload)
      });
      const data = await res.json();

      showNotification(
        data.analysis.risk_score >= 50
          ? `Phishing Threat Detected (${data.analysis.risk_score}%) — Quarantined`
          : `Email Verified Safe (${data.analysis.risk_score}%)`,
        data.analysis.risk_score >= 50 ? 'danger' : 'success'
      );
      fetchData();

      if (data.item) {
        setActiveSafetyModalItem(data.item);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleUploadEml = async (file) => {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const res = await fetch('/api/upload-eml', {
        method: 'POST',
        body: formData
      });

      if (!res.ok) {
        const err = await res.json();
        showNotification(`Upload error: ${err.detail}`, 'danger');
        return;
      }

      const data = await res.json();
      showNotification(`Loaded real Gmail message: "${data.item.subject}"`, 'success');
      fetchData();

      if (data.item) {
        setActiveSafetyModalItem(data.item);
      }
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
      const res = await fetch(`/api/sentinel/report/${incidentId}`);
      if (res.ok) {
        const data = await res.json();
        setActiveReportModal(data.report);
      } else {
        const found = reports.find(r => r.incident_id === incidentId);
        if (found) setActiveReportModal(found);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleGenerateReportFromInvestigator = async (analysis, formData) => {
    try {
      const res = await fetch('/api/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sender_address: formData.sender_address,
          display_name: formData.display_name,
          subject: formData.subject,
          body: formData.body,
          recipient: formData.recipient || 'harinivash28082007@gmail.com',
          urls: (formData.urls || '').split('\n').filter(Boolean).map(u => ({ url: u.trim(), anchor: '' })),
          attachments: [],
          spf_status: formData.spf_status,
          dkim_status: formData.dkim_status,
          dmarc_status: formData.dmarc_status
        })
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

  const handleSaveGmailConfig = async (email, appPassword) => {
    try {
      const res = await fetch('/api/sentinel/connect-gmail', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, app_password: appPassword })
      });
      const data = await res.json();
      if (data.connected) {
        showNotification(`Gmail connected — 24/7 guard active for ${email}`, 'success');
      } else if (appPassword) {
        showNotification(`Gmail rejected the app password. ${data.error || 'Check IMAP + App Password steps.'}`, 'danger');
      }
      fetchData();
      return data;
    } catch (err) {
      console.error(err);
      return { connected: false, error: 'Network error reaching the backend.' };
    }
  };

  // ---- Google OAuth (one-click) --------------------------------------
  const handleSaveOAuthCreds = async (clientId, clientSecret) => {
    try {
      const res = await fetch('/api/auth/google/save-credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: clientId, client_secret: clientSecret })
      });
      const data = await res.json();
      if (data.status === 'SUCCESS') {
        showNotification('Google credentials saved. Click "Sign in with Google" to connect.', 'success');
        fetchData();
        return { ok: true };
      }
      const msg = data.error || data.detail || 'Could not save credentials';
      showNotification(msg, 'danger');
      return { ok: false, error: msg };
    } catch (err) {
      console.error(err);
      return { ok: false, error: 'Network error reaching the backend.' };
    }
  };

  const handleStartOAuthLogin = async () => {
    if (!liveGmailAllowed) {
      showNotification(
        'This is a shared public demo — connecting a mailbox is disabled. Try the analyzer, paste an email, or upload a .eml instead.',
        'info'
      );
      return;
    }
    try {
      const res = await fetch('/api/auth/google/login');
      if (!res.ok) {
        if (res.status === 403) {
          showNotification('Live Gmail is disabled on this shared demo instance.', 'info');
          return;
        }
        // No OAuth client configured yet — open the modal so the user can set one up
        setIsOAuthModalOpen(true);
        showNotification('Google sign-in needs an OAuth client. See "Google sign-in" tab.', 'info');
        return;
      }
      const data = await res.json();
      if (data.auth_url) {
        window.location.assign(data.auth_url);
      }
    } catch (err) {
      console.error(err);
      showNotification('Could not start Google sign-in', 'danger');
    }
  };

  const handleDirectTokenConnect = async (email, token) => {
    try {
      const res = await fetch('/api/auth/google/direct-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, access_token: token })
      });
      const data = await res.json();
      if (data.status === 'SUCCESS') {
        showNotification(`Connected with Google Gmail API for ${email}!`, 'success');
        setIsOAuthModalOpen(false);
        fetchData();
      } else {
        showNotification(`API Error: ${data.error || 'Failed to authenticate'}`, 'danger');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleOAuthDisconnect = async () => {
    try {
      await fetch('/api/auth/google/disconnect', { method: 'POST' });
      showNotification('Google API disconnected', 'info');
      fetchData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleTriggerOAuthSync = async () => {
    try {
      showNotification('Syncing with Gmail REST API...', 'info');
      const res = await fetch('/api/auth/google/sync-now', { method: 'POST' });
      const data = await res.json();
      showNotification(`Gmail API Sync Complete! Found ${data.result?.new_emails_count ?? 0} new messages.`, 'success');
      fetchData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleToggleMonitoring = async (active) => {
    try {
      await fetch('/api/sentinel/toggle-active', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active })
      });
      fetchData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleTriggerManualScan = async () => {
    try {
      showNotification('Scanning live inbox...', 'info');
      const res = await fetch('/api/sentinel/scan-now', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      showNotification(`Scan complete! ${data.result?.new_emails_found ?? data.result?.new_emails_count ?? 0} new emails processed.`, 'success');
      fetchData();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="min-h-screen flex flex-col text-white/90">
      {/* Top Notification Toast */}
      {notification && (
        <div className={`fixed top-20 right-6 z-[60] px-4 py-2.5 rounded-xl text-xs font-semibold flex items-center gap-2 animate-slide-in glass-hi ${
          notification.type === 'danger'
            ? 'text-white'
            : notification.type === 'success'
            ? 'text-white/90'
            : 'text-white/70'
        }`}>
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${notification.type === 'danger' ? 'bg-white animate-pulse' : 'bg-white/50'}`} />
          <span>{notification.msg}</span>
        </div>
      )}

      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        stats={stats}
        onToggleMonitoring={handleToggleMonitoring}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onOpenOAuthModal={() => setIsOAuthModalOpen(true)}
        onStartOAuthLogin={handleStartOAuthLogin}
        onSimulateAttack={handleSimulateAttack}
      />

      {config.demo_mode && !bannerDismissed && (
        <div className="bg-white/[0.06] border-b border-white/10 backdrop-blur-xl">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2.5 flex items-start sm:items-center gap-3 text-xs">
            <span className="pill-muted shrink-0 mt-0.5 sm:mt-0">Shared demo</span>
            <p className="text-white/60 flex-1 leading-relaxed">
              This is a public instance — the inbox, quarantine and stats are{' '}
              <span className="text-white/80 font-semibold">shared by everyone here</span> and reset on redeploy.
              {liveGmailAllowed
                ? ' Connecting a real mailbox works but exposes it to other visitors.'
                : ' Live Gmail connection is disabled. Use the analyzer, "Paste email", ".eml upload" and "Simulate" — all fully working.'}
            </p>
            <button
              onClick={() => setBannerDismissed(true)}
              className="text-white/40 hover:text-white/80 transition shrink-0 font-mono"
              title="Dismiss"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'sentinel' && (
          <LiveSentinel
            inbox={inbox}
            stats={stats}
            liveGmailAllowed={liveGmailAllowed}
            onRefresh={fetchData}
            onQuarantineToggle={handleQuarantineToggle}
            onInspectEmail={handleInspectEmail}
            onViewReport={handleViewReport}
            onSimulateAttack={handleSimulateAttack}
            onOpenSafetyModal={(item) => setActiveSafetyModalItem(item)}
            onIngestCustomEmail={handleIngestCustomEmail}
            onUploadEml={handleUploadEml}
            onOpenOAuthModal={() => setIsOAuthModalOpen(true)}
            onStartOAuthLogin={handleStartOAuthLogin}
          />
        )}

        {activeTab === 'investigator' && (
          <DeepInvestigator
            initialEmail={selectedEmailForInspection}
            samples={samples}
            onGenerateReport={handleGenerateReportFromInvestigator}
            onViewReport={handleViewReport}
          />
        )}

        {activeTab === 'reports' && (
          <IncidentReports
            reports={reports}
            onViewReport={handleViewReport}
          />
        )}
      </main>

      <footer className="border-t border-white/10 py-4 text-center text-xs text-white/35 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row justify-between items-center gap-2">
          <span>PhishGuard AI Platform • PS-02 Cybersecurity Sentinel</span>
          <span>Gmail Connect • Real-Time Classification • Auto-Quarantine</span>
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
        <IncidentModal
          report={activeReportModal}
          onClose={() => setActiveReportModal(null)}
        />
      )}

      {isOAuthModalOpen && (
        <GoogleOAuthModal
          stats={stats}
          onClose={() => setIsOAuthModalOpen(false)}
          onSaveOAuthCreds={handleSaveOAuthCreds}
          onStartOAuthLogin={handleStartOAuthLogin}
          onDirectTokenConnect={handleDirectTokenConnect}
          onOAuthDisconnect={handleOAuthDisconnect}
          onTriggerOAuthSync={handleTriggerOAuthSync}
          onSaveGmailConfig={handleSaveGmailConfig}
          onTriggerScan={handleTriggerManualScan}
        />
      )}

      {isSettingsOpen && (
        <GmailSettingsModal
          stats={stats}
          onClose={() => setIsSettingsOpen(false)}
          onSaveConfig={handleSaveGmailConfig}
          onToggleMonitoring={handleToggleMonitoring}
          onTriggerScan={handleTriggerManualScan}
        />
      )}
    </div>
  );
}
