import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

// Must be hoisted so the factory can reference it before imports resolve
const mockNavigate = vi.hoisted(() => vi.fn());

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../api', () => ({
  default: { post: vi.fn() },
}));

import api from '../api';
import Upload from '../pages/Upload';

function renderUpload() {
  return render(
    <MemoryRouter>
      <Upload />
    </MemoryRouter>
  );
}

describe('Upload page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the drop zone with instruction text', () => {
    renderUpload();
    expect(screen.getByText(/Drop a file here/i)).toBeInTheDocument();
    expect(screen.getByTestId('submit-button')).toBeDisabled();
  });

  it('accepts a file with a valid extension and shows its name', async () => {
    renderUpload();
    const input = screen.getByTestId('file-input');
    const file = new File(['content'], 'malware.exe', { type: 'application/octet-stream' });
    fireEvent.change(input, { target: { files: [file] } });
    await waitFor(() => {
      expect(screen.getByText('malware.exe')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('error-message')).not.toBeInTheDocument();
  });

  it('rejects a file with an unsupported extension and shows an error', async () => {
    renderUpload();
    const input = screen.getByTestId('file-input');
    const file = new File(['content'], 'document.docx', { type: 'application/vnd.openxmlformats' });
    fireEvent.change(input, { target: { files: [file] } });
    await waitFor(() => {
      expect(screen.getByTestId('error-message')).toBeInTheDocument();
    });
    expect(screen.getByTestId('error-message')).toHaveTextContent(/not supported/i);
  });

  it('submit button stays disabled when no file is selected', () => {
    renderUpload();
    expect(screen.getByTestId('submit-button')).toBeDisabled();
  });

  it('submit button becomes enabled after a valid file is selected', async () => {
    renderUpload();
    const input = screen.getByTestId('file-input');
    const file = new File(['content'], 'sample.py', { type: 'text/x-python' });
    fireEvent.change(input, { target: { files: [file] } });
    await waitFor(() => {
      expect(screen.getByTestId('submit-button')).not.toBeDisabled();
    });
  });

  it('mode selection highlights the clicked card', () => {
    renderUpload();
    const deepScanBtn = screen.getByTestId('mode-deep_scan');
    fireEvent.click(deepScanBtn);
    expect(deepScanBtn.className).toMatch(/border-indigo-500/);
  });

  it('submits the form and navigates to /job/:id on success', async () => {
    api.post.mockResolvedValue({ data: { job_id: 'abc-123', mode: 'standard' } });
    renderUpload();

    const input = screen.getByTestId('file-input');
    const file = new File(['content'], 'sample.exe', { type: 'application/octet-stream' });
    fireEvent.change(input, { target: { files: [file] } });
    await waitFor(() => screen.getByText('sample.exe'));

    fireEvent.click(screen.getByTestId('submit-button'));

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/analyze', expect.any(FormData));
      expect(mockNavigate).toHaveBeenCalledWith('/job/abc-123', expect.objectContaining({
        state: expect.objectContaining({ filename: 'sample.exe' }),
      }));
    });
  });

  it('shows an inline error when the API call fails', async () => {
    api.post.mockRejectedValue({
      response: { data: { detail: 'Unsupported file type' } },
    });
    renderUpload();

    const input = screen.getByTestId('file-input');
    const file = new File(['content'], 'sample.exe', { type: 'application/octet-stream' });
    fireEvent.change(input, { target: { files: [file] } });
    await waitFor(() => screen.getByText('sample.exe'));

    fireEvent.click(screen.getByTestId('submit-button'));

    await waitFor(() => {
      expect(screen.getByTestId('error-message')).toHaveTextContent(/Unsupported file type/i);
    });
  });
});
