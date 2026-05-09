import JobHeader from './JobHeader.jsx';
import ToolStatusStrip from './ToolStatusStrip.jsx';
import ReasoningChain from './ReasoningChain.jsx';
import SandboxView from './SandboxView.jsx';

export default function ActiveJobPage({ job, progress, etaSec, completedSteps, liveText, totalTools, usedTools, activeTools, isLive }) {
  return (
    <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 1280, margin: '0 auto' }}>
      <JobHeader job={job} progress={progress} etaSec={etaSec} />
      <ToolStatusStrip activeTools={activeTools} used={usedTools} total={totalTools} />
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 16 }}>
        <ReasoningChain
          steps={job.reasoningSteps}
          completedCount={completedSteps}
          liveStreamText={liveText}
          isLive={isLive}
        />
        <SandboxView
          active={isLive}
          used={completedSteps}
          capturedDump={completedSteps >= 2}
          blockedNet={completedSteps >= 2 ? 7 : 0}
          schtasks={completedSteps >= 2 ? 1 : 0}
        />
      </div>
    </div>
  );
}
