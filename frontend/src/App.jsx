import { useState, useEffect, useRef } from 'react';
import Sidebar from './components/layout/Sidebar.jsx';
import TopBar from './components/layout/TopBar.jsx';
import StatCard from './components/shared/StatCard.jsx';
import RecentScansTable from './components/shared/RecentScansTable.jsx';
import UploadZone from './components/upload/UploadZone.jsx';
import ActiveJobPage from './components/active/ActiveJobPage.jsx';
import ReportPage from './components/reports/ReportPage.jsx';
import { IconList, IconArrowRight } from './components/icons/index.jsx';
import api from './api.js';

const bytesToLabel = (bytes) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const detectType = (filename) => {
  const ext = filename.split('.').pop().toLowerCase();
  const types = {
    exe: 'PE32+', dll: 'PE32+', py: 'Python', sh: 'Bash', bash: 'Bash',
    pdf: 'PDF', zip: 'Archive',
  };
  return types[ext] || 'Unknown';
};

const formatTime = (isoStr) => {
  if (!isoStr) return 'Unknown';
  const date = new Date(isoStr);
  const now = new Date();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
};

const transformReportForTable = (item) => ({
  name: item.filename,
  kind: detectType(item.filename),
  verdict: item.verdict ? item.verdict.toLowerCase() : 'unknown',
  time: formatTime(item.created_at),
  mode: item.mode === 'deep_scan' ? 'Deep' : 'Std',
  job_id: item.job_id,
  ...item,
});

export default function App() {
  const [route, setRoute] = useState('upload');       // 'upload' | 'active' | 'reports' | 'intel'
  const [jobState, setJobState] = useState('idle');   // idle | scanning | done
  const [droppedFile, setDroppedFile] = useState(null);
  const [currentJobId, setCurrentJobId] = useState(null);
  const [mode, setMode] = useState('standard');
  const [progress, setProgress] = useState(0);
  const [completedSteps, setCompletedSteps] = useState(0);
  const [liveText, setLiveText] = useState('');
  const [usedTools, setUsedTools] = useState(0);
  const [recent, setRecent] = useState([]);
  const [currentReport, setCurrentReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Fetch recent reports on mount
  useEffect(() => {
    const fetchReports = async () => {
      try {
        const response = await api.get('/reports', { params: { page: 1, page_size: 20 } });
        const items = response.data.items || [];
        setRecent(items.map(transformReportForTable));
      } catch (err) {
        console.error('Failed to fetch reports:', err);
      }
    };
    fetchReports();
  }, []);

  // Poll for job status while scanning
  useEffect(() => {
    if (jobState !== 'scanning' || !currentJobId) return;
    let cancelled = false;

    const pollStatus = async () => {
      while (!cancelled) {
        try {
          const response = await api.get(`/report/${currentJobId}`);
          const data = response.data;

          if (data.status === 'running') {
            setProgress(Math.min(95, 20 + (data.elapsed_seconds || 0) * 2));
            setLiveText(data.current_action || 'Processing...');
          } else if (data.status === 'complete') {
            setProgress(100);
            // The backend returns report_json which contains all the report data
            // We need to merge it with filename and sha256 from the jobs table
            const reportData = {
              ...data.report,
              filename: data.filename,
              sha256: data.sha256,
            };
            setCurrentReport(reportData);
            setJobState('done');
            setRoute('reports');
            // Refresh recent reports
            try {
              const reportsList = await api.get('/reports', { params: { page: 1, page_size: 20 } });
              setRecent((reportsList.data.items || []).map(transformReportForTable));
            } catch (err) {
              console.error('Failed to refresh reports:', err);
            }
          } else if (data.status === 'failed') {
            setError(data.error || 'Analysis failed');
            setJobState('idle');
            setCurrentJobId(null);
          } else if (data.status === 'queued') {
            setProgress(Math.min(10, progress + 1));
            setLiveText('Queued for analysis...');
          }
        } catch (err) {
          console.error('Poll status error:', err);
        }

        await new Promise((r) => setTimeout(r, 2000));
      }
    };

    pollStatus();
    return () => { cancelled = true; };
  }, [jobState, currentJobId]);

  const job = currentReport;

  const handleFile = (f) => {
    if (!f) { setDroppedFile(null); return; }
    setDroppedFile({
      name: f.name,
      sizeLabel: f.size ? bytesToLabel(f.size) : '0 B',
      detectedType: detectType(f.name),
      file: f,
    });
    setError(null);
  };

  const handleStart = async () => {
    if (!droppedFile || !droppedFile.file || loading) return;
    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', droppedFile.file);
      formData.append('mode', mode);

      const response = await api.post('/analyze', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });

      const { job_id } = response.data;
      setCurrentJobId(job_id);
      setJobState('scanning');
      setRoute('active');
      setProgress(0);
      setCompletedSteps(0);
      setLiveText('Queued for analysis...');
      setUsedTools(0);

      // Add to recent list
      setRecent((prev) => [
        {
          name: droppedFile.name,
          kind: droppedFile.detectedType,
          verdict: 'scanning',
          job_id,
          created_at: new Date().toISOString(),
          time: 'Just now',
          mode: mode === 'deep_scan' ? 'Deep' : 'Std',
        },
        ...prev.slice(0, 19),
      ]);
    } catch (err) {
      const detail = err.response?.data?.detail;
      const msg = typeof detail === 'string' ? detail : err.message || 'Upload failed';
      setError(msg);
      setLoading(false);
    }
  };


  const etaSec = Math.max(0, Math.round(((100 - progress) / 100) * 300));
  const activeTools = [];
  const sidebarRecent = recent.slice(0, 5).map((r) => ({ name: r.name, verdict: r.verdict }));

  let main = null;

  if (route === 'upload' || (route === 'reports' && jobState === 'idle')) {
    main = (
      <div style={{ padding: '24px 28px', maxWidth: 1280, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 22 }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 600, letterSpacing: '-0.01em' }}>Submit a file for analysis</div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
            Drop a binary, archive, or document. The agent will detonate, reason, and compile a verdict in under five minutes.
          </div>
        </div>
        <UploadZone
          onFile={handleFile}
          onPasteHash={() => handleFile({ name: 'hash_lookup.bin', size: 0 })}
          droppedFile={droppedFile}
          mode={mode}
          setMode={setMode}
          onStart={handleStart}
          loading={loading}
          error={error}
        />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
          <StatCard value="12,847" label="Files scanned"      sub="last 30 days" />
          <StatCard value="94.2%"  label="Detection accuracy" sub="vs ground truth" />
          <StatCard value="0.8s"   label="Avg hash lookup"    sub="median round-trip" />
          <StatCard value="3.2"    label="Avg ATT&CK TTPs"    sub="per malicious sample" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 10 }}>
            <div className="eyebrow">Recent scans</div>
            <button className="btn btn-ghost" style={{ height: 28, fontSize: 12 }}>
              View all <IconArrowRight size={12} />
            </button>
          </div>
          <RecentScansTable
            rows={recent}
            onOpen={(r) => { if (r.verdict === 'malicious') setRoute('reports'); }}
          />
        </div>
      </div>
    );
  } else if (route === 'active' && jobState === 'scanning') {
    main = (
      <ActiveJobPage
        job={currentReport}
        progress={progress}
        etaSec={etaSec}
        completedSteps={completedSteps}
        liveText={liveText}
        usedTools={usedTools}
        totalTools={mode === 'deep_scan' ? 20 : 8}
        activeTools={activeTools}
        isLive={true}
      />
    );
  } else if (route === 'reports' && jobState === 'done') {
    main = currentReport ? <ReportPage job={currentReport} /> : (
      <div style={{ padding: '24px 28px', maxWidth: 1280, margin: '0 auto' }}>
        <div className="surface" style={{ padding: 32, borderRadius: 10, textAlign: 'center' }}>
          <IconList size={28} />
          <div style={{ marginTop: 12, fontSize: 15, fontWeight: 600 }}>Loading report...</div>
        </div>
      </div>
    );
  } else if (route === 'reports' && jobState !== 'done') {
    main = (
      <div style={{ padding: '24px 28px', maxWidth: 1280, margin: '0 auto' }}>
        <div className="surface" style={{ padding: 32, borderRadius: 10, textAlign: 'center' }}>
          <IconList size={28} />
          <div style={{ marginTop: 12, fontSize: 15, fontWeight: 600 }}>No active report</div>
          <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginTop: 4 }}>
            Run a scan from the Upload page to generate a report.
          </div>
        </div>
      </div>
    );
  } else if (route === 'intel') {
    main = (
      <div style={{ padding: '24px 28px', maxWidth: 1280, margin: '0 auto' }}>
        <div className="surface" style={{ padding: 32, borderRadius: 10 }}>
          <div className="eyebrow" style={{ marginBottom: 8 }}>Threat intelligence</div>
          <div style={{ fontSize: 14, color: 'var(--text-secondary)' }}>Live feeds from MalwareBazaar, AbuseIPDB and internal corpus.</div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-grid">
      <Sidebar route={route} setRoute={setRoute} recent={sidebarRecent} jobState={jobState} />
      <main style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', height: '100vh' }}>
        <TopBar route={route} currentJob={droppedFile} />
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {main}
        </div>
      </main>
    </div>
  );
}
