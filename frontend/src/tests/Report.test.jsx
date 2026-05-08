import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useParams: () => ({ job_id: 'test-job-id' }),
  };
});

vi.mock('../api', () => ({
  default: { get: vi.fn() },
}));

import api from '../api';
import Report from '../pages/Report';

const MOCK_REPORT = {
  job_id: 'test-job-id',
  mode: 'standard',
  verdict: 'malicious',
  confidence: 97,
  threat_category: 'trojan',
  severity: 'critical',
  summary: 'This file is a UPX-packed trojan dropper.',
  key_indicators: [
    'UPX packing confirmed — real payload only visible in memory dump',
    'Injected PE image at offset 0x3f2000',
    'Known C2 IP: 185.220.101.45 (abuse score 97/100)',
  ],
  mitre_techniques: [
    { id: 'T1027.002', name: 'Software Packing', tactic: 'Defense Evasion', evidence: 'UPX sections' },
    { id: 'T1055.001', name: 'DLL Injection', tactic: 'Defense Evasion', evidence: 'Injected PE' },
    { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', evidence: 'Known C2' },
  ],
  recommended_action: 'Quarantine',
  iocs: {
    ips: ['185.220.101.45'],
    urls: ['http://185.220.101.45/gate.php'],
    domains: [],
    mutexes: ['Global\\MicrosoftUpdateMutex_v2'],
  },
  tools_called: 5,
  analysis_time_seconds: 48,
  reasoning_chain: {
    steps: [
      {
        step_number: 1,
        reasoning: 'High entropy suggests packing.',
        tool_called: 'get_pe_sections()',
        result_summary: 'UPX confirmed.',
      },
      {
        step_number: 2,
        reasoning: 'UPX confirmed — dumping memory.',
        tool_called: 'run_sandbox(duration=15)',
        result_summary: '7 blocked network calls.',
      },
    ],
  },
};

function renderReport() {
  return render(
    <MemoryRouter>
      <Report />
    </MemoryRouter>
  );
}

describe('Report page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.get.mockResolvedValue({ data: { status: 'complete', report: MOCK_REPORT } });
  });

  it('shows a loading indicator while fetching', () => {
    api.get.mockReturnValue(new Promise(() => {})); // never resolves
    renderReport();
    expect(screen.getByText(/Loading report/i)).toBeInTheDocument();
  });

  it('renders the verdict badge with correct label and confidence', async () => {
    renderReport();
    await waitFor(() => {
      expect(screen.getByTestId('verdict-badge')).toBeInTheDocument();
    });
    expect(screen.getByTestId('verdict-badge')).toHaveTextContent(/Malicious/i);
    expect(screen.getByTestId('verdict-badge')).toHaveTextContent(/97%/);
  });

  it('renders the severity chip', async () => {
    renderReport();
    await waitFor(() => {
      expect(screen.getByTestId('severity-chip')).toHaveTextContent(/Critical/i);
    });
  });

  it('renders MITRE ATT&CK technique tags', async () => {
    renderReport();
    await waitFor(() => {
      expect(screen.getByTestId('mitre-section')).toBeInTheDocument();
    });
    const tags = screen.getAllByTestId('mitre-tag');
    expect(tags).toHaveLength(3);
    expect(tags[0]).toHaveTextContent('T1027.002');
    expect(tags[0]).toHaveTextContent('Software Packing');
  });

  it('MITRE tags link to attack.mitre.org with slashed sub-technique IDs', async () => {
    renderReport();
    await waitFor(() => screen.getAllByTestId('mitre-tag'));
    const firstTag = screen.getAllByTestId('mitre-tag')[0];
    expect(firstTag).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1027/002');
    expect(firstTag).toHaveAttribute('target', '_blank');
  });

  it('reasoning chain is collapsed by default', async () => {
    renderReport();
    await waitFor(() => {
      expect(screen.getByTestId('reasoning-chain-toggle')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('reasoning-chain-body')).not.toBeInTheDocument();
  });

  it('reasoning chain expands when the toggle is clicked', async () => {
    renderReport();
    await waitFor(() => screen.getByTestId('reasoning-chain-toggle'));
    fireEvent.click(screen.getByTestId('reasoning-chain-toggle'));
    expect(screen.getByTestId('reasoning-chain-body')).toBeInTheDocument();
    expect(screen.getByText(/High entropy suggests packing/i)).toBeInTheDocument();
  });

  it('renders the summary card', async () => {
    renderReport();
    await waitFor(() => {
      expect(screen.getByText(/UPX-packed trojan dropper/i)).toBeInTheDocument();
    });
  });

  it('renders key indicators as a numbered list', async () => {
    renderReport();
    await waitFor(() => {
      expect(screen.getByText(/UPX packing confirmed/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/Injected PE image/i)).toBeInTheDocument();
  });

  it('renders the recommended action banner', async () => {
    renderReport();
    await waitFor(() => {
      expect(screen.getByTestId('action-banner')).toHaveTextContent(/Quarantine/i);
    });
  });

  it('shows an error message when the API call fails', async () => {
    api.get.mockRejectedValue({ message: 'Network error' });
    renderReport();
    await waitFor(() => {
      expect(screen.getByText(/Network error/i)).toBeInTheDocument();
    });
  });
});
