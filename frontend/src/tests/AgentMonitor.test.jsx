import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

const mockNavigate = vi.hoisted(() => vi.fn());

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: () => ({ job_id: 'test-job-id' }),
    useLocation: () => ({ state: { filename: 'trojan.exe', mode: 'standard' } }),
  };
});

vi.mock('../api', () => ({
  default: { get: vi.fn() },
}));

import api from '../api';
import AgentMonitor from '../pages/AgentMonitor';

function renderMonitor() {
  return render(
    <MemoryRouter>
      <AgentMonitor />
    </MemoryRouter>
  );
}

describe('AgentMonitor page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Stop intervals immediately after the initial poll to prevent repeated calls
    vi.spyOn(global, 'setInterval').mockImplementation(() => 0);
  });

  it('shows queued panel while status is queued', async () => {
    api.get.mockResolvedValue({ data: { status: 'queued', elapsed_seconds: 0 } });
    renderMonitor();
    await waitFor(() => {
      expect(screen.getByTestId('queued-panel')).toBeInTheDocument();
    });
    expect(screen.getByText(/Queued — waiting for worker/i)).toBeInTheDocument();
  });

  it('displays filename and mode at the top', async () => {
    api.get.mockResolvedValue({ data: { status: 'queued', elapsed_seconds: 0 } });
    renderMonitor();
    await waitFor(() => {
      expect(screen.getByText('trojan.exe')).toBeInTheDocument();
    });
    expect(screen.getByText(/Standard mode/i)).toBeInTheDocument();
  });

  it('shows running step with current action text', async () => {
    api.get.mockResolvedValue({
      data: {
        status: 'running',
        current_step: 3,
        current_action: 'Scanning memory dump for injected PE images',
        elapsed_seconds: 34,
      },
    });
    renderMonitor();
    await waitFor(() => {
      expect(screen.getByTestId('current-step')).toBeInTheDocument();
    });
    expect(screen.getByText(/Scanning memory dump for injected PE images/i)).toBeInTheDocument();
    expect(screen.getByText(/Step 3 of 8/i)).toBeInTheDocument();
  });

  it('accumulates the current step in local state', async () => {
    api.get.mockResolvedValue({
      data: {
        status: 'running',
        current_step: 2,
        current_action: 'Running sandbox',
        elapsed_seconds: 20,
      },
    });
    renderMonitor();
    await waitFor(() => {
      expect(screen.getByText(/Running sandbox/i)).toBeInTheDocument();
    });
    // Step 2 of 8 displayed in the live step header
    expect(screen.getByText(/Step 2 of 8/i)).toBeInTheDocument();
  });

  it('navigates to the report page when status becomes complete', async () => {
    api.get.mockResolvedValue({ data: { status: 'complete' } });
    renderMonitor();
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/job/test-job-id/report', { replace: true });
    });
  });

  it('shows an error panel when status is failed', async () => {
    api.get.mockResolvedValue({
      data: { status: 'failed', error: 'Worker crashed unexpectedly' },
    });
    renderMonitor();
    await waitFor(() => {
      expect(screen.getByTestId('error-panel')).toBeInTheDocument();
    });
    expect(screen.getByText(/Worker crashed unexpectedly/i)).toBeInTheDocument();
  });
});
