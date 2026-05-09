import { useState, useEffect } from 'react';
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

const formatAnalysisDuration = (seconds) => {
  if (!seconds && seconds !== 0) return 'Unknown';
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
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

const buildReportData = (apiData, fallbackName = 'unknown', capturedSteps = []) => {
  const report = apiData.report || {};
  const fileMeta = report.file_meta || {};
  const rawIocs = report.iocs || {};
  const flatIocs = [
    ...(rawIocs.ips || []).map((v) => ({ type: 'IP', value: v, source: 'Analysis' })),
    ...(rawIocs.urls || []).map((v) => ({ type: 'URL', value: v, source: 'Analysis' })),
    ...(rawIocs.domains || []).map((v) => ({ type: 'Domain', value: v, source: 'Analysis' })),
  ];
  return {
    ...report,
    filename: fileMeta.filename || fallbackName,
    sha256: fileMeta.sha256 || '',
    family: report.threat_category,
    toolCalls: report.tools_called,
    duration: formatAnalysisDuration(report.analysis_time_seconds),
    iocs: flatIocs,
    mitre: report.mitre_techniques || [],
    reasoningSteps: capturedSteps,
  };
};

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
  const [sseSteps, setSseSteps] = useState([]);
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

  // Connect to SSE stream while scanning
  useEffect(() => {
    if (jobState !== 'scanning' || !currentJobId) return;

    const apiBase = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
    const apiKey = import.meta.env.VITE_API_KEY || 'dev-key';

    // Capture file name at effect start to avoid stale closure
    const fallbackName = droppedFile?.name || 'unknown';

    const stepsRef = { current: [] };
    let finished = false;

    const finishJob = async () => {
      if (finished) return;
      finished = true;
      setProgress(100);
      try {
        const response = await api.get(`/report/${currentJobId}`);
        const data = response.data;
        if (data.status === 'failed') {
          setError(data.error || 'Analysis failed');
          setJobState('idle');
          setCurrentJobId(null);
          return;
        }
        setCurrentReport(buildReportData(data, fallbackName, stepsRef.current));
        setSseSteps([]);
        setJobState('done');
        setRoute('reports');
        try {
          const list = await api.get('/reports', { params: { page: 1, page_size: 20 } });
          setRecent((list.data.items || []).map(transformReportForTable));
        } catch (err) {
          console.error('Failed to refresh reports:', err);
        }
      } catch (err) {
        setError('Failed to load report: ' + err.message);
        setJobState('idle');
      }
    };

    const es = new EventSource(
      `${apiBase}/stream/${currentJobId}?api_key=${encodeURIComponent(apiKey)}`
    );

    es.addEventListener('thought', (e) => {
      const data = JSON.parse(e.data);
      const step = {
        step: stepsRef.current.length + 1,
        time: new Date().toLocaleTimeString('en-US', { hour12: false }),
        thought: data.text || data.content || '',
        tool: '',
        result: '',
      };
      stepsRef.current = [...stepsRef.current, step];
      setSseSteps([...stepsRef.current]);
      setLiveText(step.thought);
      setCompletedSteps(Math.max(0, stepsRef.current.length - 1));
      setProgress(Math.min(90, 10 + stepsRef.current.length * 8));
    });

    es.addEventListener('tool_call', (e) => {
      const data = JSON.parse(e.data);
      const steps = stepsRef.current;
      if (steps.length > 0) {
        const last = { ...steps[steps.length - 1], tool: data.tool || data.name || '' };
        stepsRef.current = [...steps.slice(0, -1), last];
        setSseSteps([...stepsRef.current]);
        setUsedTools(stepsRef.current.filter((s) => s.tool).length);
      }
    });

    es.addEventListener('tool_result', (e) => {
      const data = JSON.parse(e.data);
      const steps = stepsRef.current;
      if (steps.length > 0) {
        const last = { ...steps[steps.length - 1], result: data.result || data.content || '' };
        stepsRef.current = [...steps.slice(0, -1), last];
        setSseSteps([...stepsRef.current]);
      }
    });

    es.addEventListener('complete', () => {
      es.close();
      finishJob();
    });

    es.onerror = () => {
      es.close();
      finishJob();
    };

    return () => { es.close(); };
  }, [jobState, currentJobId]);

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
      setSseSteps([]);
      setCurrentReport(null);
      setLoading(false);

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

  const scanningJobMeta = droppedFile ? {
    filename: droppedFile.name,
    sha256: '',
    size: droppedFile.sizeLabel,
    type: droppedFile.detectedType,
    mode,
    reasoningSteps: sseSteps,
  } : null;

  const handleOpenReport = async (r) => {
    try {
      const response = await api.get(`/report/${r.job_id}`);
      const data = response.data;
      if (data.status !== 'complete') return;
      setCurrentReport(buildReportData(data, r.name));
      setJobState('done');
      setRoute('reports');
    } catch (err) {
      console.error('Failed to load report:', err);
    }
  };

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
            onOpen={handleOpenReport}
          />
        </div>
      </div>
    );
  } else if (route === 'active' && jobState === 'scanning') {
    main = (
      <ActiveJobPage
        job={scanningJobMeta}
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
