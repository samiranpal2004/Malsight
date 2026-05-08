import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

const mockNavigate = vi.hoisted(() => vi.fn());

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../api', () => ({
  default: { get: vi.fn() },
}));

import api from '../api';
import History from '../pages/History';

const MOCK_ITEMS = [
  {
    job_id: 'job-001',
    filename: 'malware.exe',
    mode: 'standard',
    verdict: 'malicious',
    threat_category: 'trojan',
    confidence: 97,
    tools_called: 5,
    analysis_time_seconds: 48,
    completed_at: '2026-05-01T10:30:00Z',
  },
  {
    job_id: 'job-002',
    filename: 'script.py',
    mode: 'deep_scan',
    verdict: 'suspicious',
    threat_category: 'dropper',
    confidence: 72,
    tools_called: 12,
    analysis_time_seconds: 180,
    completed_at: '2026-05-02T14:00:00Z',
  },
];

function renderHistory() {
  return render(
    <MemoryRouter>
      <History />
    </MemoryRouter>
  );
}

describe('History page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.get.mockResolvedValue({ data: { items: MOCK_ITEMS, total: 2 } });
  });

  it('renders a loading skeleton initially', () => {
    api.get.mockReturnValue(new Promise(() => {})); // never resolves
    renderHistory();
    expect(screen.getByTestId('loading-skeleton')).toBeInTheDocument();
  });

  it('renders table rows for each report', async () => {
    renderHistory();
    await waitFor(() => {
      expect(screen.getAllByTestId('history-row')).toHaveLength(2);
    });
    expect(screen.getByText('malware.exe')).toBeInTheDocument();
    expect(screen.getByText('script.py')).toBeInTheDocument();
  });

  it('shows empty state when there are no reports', async () => {
    api.get.mockResolvedValue({ data: { items: [], total: 0 } });
    renderHistory();
    await waitFor(() => {
      expect(screen.getByTestId('empty-state')).toBeInTheDocument();
    });
    expect(screen.getByText(/No analyses yet/i)).toBeInTheDocument();
  });

  it('renders VerdictBadge for each row', async () => {
    renderHistory();
    await waitFor(() => screen.getAllByTestId('history-row'));
    const badges = screen.getAllByTestId('verdict-badge');
    expect(badges).toHaveLength(2);
    expect(badges[0]).toHaveTextContent(/Malicious/i);
    expect(badges[1]).toHaveTextContent(/Suspicious/i);
  });

  it('clicking a row navigates to the report page', async () => {
    renderHistory();
    await waitFor(() => screen.getAllByTestId('history-row'));
    fireEvent.click(screen.getAllByTestId('history-row')[0]);
    expect(mockNavigate).toHaveBeenCalledWith('/job/job-001/report');
  });

  it('changing the verdict filter triggers a new API fetch with filter param', async () => {
    renderHistory();
    await waitFor(() => screen.getAllByTestId('history-row'));

    api.get.mockResolvedValue({ data: { items: [MOCK_ITEMS[0]], total: 1 } });

    fireEvent.change(screen.getByTestId('verdict-filter'), {
      target: { value: 'malicious' },
    });

    await waitFor(() => {
      expect(api.get).toHaveBeenCalledWith(
        '/reports',
        expect.objectContaining({
          params: expect.objectContaining({ verdict: 'malicious' }),
        })
      );
    });
  });

  it('changing the mode filter triggers a new API fetch with mode param', async () => {
    renderHistory();
    await waitFor(() => screen.getAllByTestId('history-row'));

    api.get.mockResolvedValue({ data: { items: [MOCK_ITEMS[1]], total: 1 } });

    fireEvent.change(screen.getByTestId('mode-filter'), {
      target: { value: 'deep_scan' },
    });

    await waitFor(() => {
      expect(api.get).toHaveBeenCalledWith(
        '/reports',
        expect.objectContaining({
          params: expect.objectContaining({ mode: 'deep_scan' }),
        })
      );
    });
  });

  it('shows an error message when the API fails', async () => {
    api.get.mockRejectedValue({ message: 'Server error' });
    renderHistory();
    await waitFor(() => {
      expect(screen.getByText(/Server error/i)).toBeInTheDocument();
    });
  });
});
