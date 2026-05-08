import { useState, useEffect, useRef } from 'react';
import Sidebar from './components/layout/Sidebar.jsx';
import TopBar from './components/layout/TopBar.jsx';
import StatCard from './components/shared/StatCard.jsx';
import RecentScansTable from './components/shared/RecentScansTable.jsx';
import UploadZone from './components/upload/UploadZone.jsx';
import ActiveJobPage from './components/active/ActiveJobPage.jsx';
import ReportPage from './components/reports/ReportPage.jsx';
import { IconList, IconArrowRight } from './components/icons/index.jsx';
import { demoJob, recentScansSeed, bytesToLabel, detectType } from './data/demoData.js';

export default function App() {
  const [route, setRoute] = useState('upload');       // 'upload' | 'active' | 'reports' | 'intel'
  const [jobState, setJobState] = useState('idle');   // idle | scanning | done
  const [droppedFile, setDroppedFile] = useState(null);
  const [mode, setMode] = useState('deep');
  const [progress, setProgress] = useState(0);
  const [completedSteps, setCompletedSteps] = useState(0);
  const [liveText, setLiveText] = useState('');
  const [usedTools, setUsedTools] = useState(0);
  const [recent, setRecent] = useState(recentScansSeed);

  const job = demoJob;

  const handleFile = (f) => {
    if (!f) { setDroppedFile(null); return; }
    setDroppedFile({
      name: f.name,
      sizeLabel: bytesToLabel(f.size),
      detectedType: detectType(f.name),
    });
  };

  const handleStart = () => {
    setJobState('scanning');
    setRoute('active');
    setProgress(0);
    setCompletedSteps(0);
    setLiveText('');
    setUsedTools(0);
    setRecent((prev) => [
      { name: droppedFile.name, kind: droppedFile.detectedType, verdict: 'unknown', time: 'Just now', mode: mode === 'deep' ? 'Deep' : 'Std' },
      ...prev.slice(0, 5),
    ]);
  };

  // Stream simulation
  useEffect(() => {
    if (jobState !== 'scanning') return;
    let cancelled = false;

    const startedAt = Date.now();
    const totalMs = 22000;
    const tick = setInterval(() => {
      const pct = Math.min(99, Math.floor(((Date.now() - startedAt) / totalMs) * 100));
      setProgress(pct);
    }, 200);

    const run = async () => {
      const stepDurations = [3000, 4000, 4500, 5000, 4500];
      for (let i = 0; i < job.reasoningSteps.length; i++) {
        if (cancelled) return;
        const s = job.reasoningSteps[i];
        const txt = s.thought;
        const dur = stepDurations[i];
        const chars = txt.length;
        const perChar = Math.max(8, Math.floor((dur * 0.55) / chars));
        for (let c = 0; c <= chars; c++) {
          if (cancelled) return;
          setLiveText(txt.slice(0, c));
          await new Promise((r) => setTimeout(r, perChar));
        }
        setUsedTools((u) => u + (s.tool.includes(',') ? 2 : Math.max(2, 3 - (i % 2))));
        await new Promise((r) => setTimeout(r, dur * 0.45));
        if (cancelled) return;
        setCompletedSteps(i + 1);
        setLiveText('');
      }
      clearInterval(tick);
      if (cancelled) return;
      setProgress(100);
      setUsedTools(14);
      await new Promise((r) => setTimeout(r, 500));
      if (cancelled) return;
      setJobState('done');
      setRoute('reports');
      setRecent((prev) => {
        const copy = [...prev];
        if (copy[0]) copy[0] = { ...copy[0], verdict: 'malicious', time: 'Just now' };
        return copy;
      });
    };
    run();

    return () => { cancelled = true; clearInterval(tick); };
  }, [jobState]);

  const etaSec = Math.max(0, Math.round(((100 - progress) / 100) * 22));
  const currentStep = job.reasoningSteps[completedSteps];
  const activeTools = currentStep ? currentStep.tool.split(',').map((t) => t.trim()) : [];
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
        job={job}
        progress={progress}
        etaSec={etaSec}
        completedSteps={completedSteps}
        liveText={liveText}
        usedTools={usedTools}
        totalTools={mode === 'deep' ? 20 : 8}
        activeTools={activeTools}
        isLive={true}
      />
    );
  } else if (route === 'reports' && jobState === 'done') {
    main = <ReportPage job={job} />;
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
