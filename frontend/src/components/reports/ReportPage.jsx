import { IconFile } from '../icons/index.jsx';
import VerdictBanner from './VerdictBanner.jsx';
import ExecutiveSummary from './ExecutiveSummary.jsx';
import IOCTable from './IOCTable.jsx';
import MitreList from './MitreList.jsx';
import ReasoningChain from '../active/ReasoningChain.jsx';

export default function ReportPage({ job }) {
  return (
    <div style={{ padding: '24px 28px', maxWidth: 1280, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <IconFile size={16} />
        <span className="mono" style={{ fontSize: 14 }}>{job.filename}</span>
        {job.sha256 && (
          <span className="hashpill mono">SHA-256 {job.sha256.slice(0, 8)}…{job.sha256.slice(-4)}</span>
        )}
        <span style={{ marginLeft: 'auto', fontSize: 11.5, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
          report ID · MS-2026-0508-A3F9
        </span>
      </div>
      <VerdictBanner job={job} />
      <ExecutiveSummary job={job} />
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <IOCTable iocs={job.iocs} />
        <MitreList mitre={job.mitre} />
      </div>
      <ReasoningChain
        steps={job.reasoningSteps || []}
        completedCount={(job.reasoningSteps || []).length}
        liveStreamText=""
        isLive={false}
      />
    </div>
  );
}
