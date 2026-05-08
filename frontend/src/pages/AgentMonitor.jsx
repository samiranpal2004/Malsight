import { useEffect, useRef, useState } from 'react';
import { useParams, useLocation, useNavigate } from 'react-router-dom';
import { Loader2, Clock, AlertCircle } from 'lucide-react';
import api from '../api';

const MAX_STEPS = { standard: 8, deep_scan: 20 };

export default function AgentMonitor() {
  const { job_id } = useParams();
  const { state } = useLocation();
  const navigate = useNavigate();

  const filename = state?.filename ?? 'Analyzing…';
  const mode = state?.mode ?? 'standard';
  const modeLabel = mode === 'deep_scan' ? 'Deep Scan' : 'Standard';
  const maxSteps = MAX_STEPS[mode] ?? 8;

  const [status, setStatus] = useState('queued');
  const [currentStep, setCurrentStep] = useState(0);
  const [currentAction, setCurrentAction] = useState('');
  const [steps, setSteps] = useState([]);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState('');

  const pollRef = useRef(null);
  const timerRef = useRef(null);
  const elapsedRef = useRef(0);
  const stepsEndRef = useRef(null);

  useEffect(() => {
    const poll = async () => {
      try {
        const { data } = await api.get(`/report/${job_id}`);
        setStatus(data.status);

        if (data.elapsed_seconds != null) {
          elapsedRef.current = data.elapsed_seconds;
          setElapsed(data.elapsed_seconds);
        }

        if (data.status === 'running') {
          const step = data.current_step ?? 0;
          const action = data.current_action ?? '';
          setCurrentStep(step);
          setCurrentAction(action);
          setSteps((prev) => {
            if (step > 0 && !prev.find((s) => s.step === step)) {
              return [...prev, { step, action }];
            }
            return prev;
          });
        }

        if (data.status === 'complete') {
          clearInterval(pollRef.current);
          clearInterval(timerRef.current);
          navigate(`/job/${job_id}/report`, { replace: true });
        }

        if (data.status === 'failed') {
          clearInterval(pollRef.current);
          clearInterval(timerRef.current);
          setError(data.error || 'Analysis failed with an unknown error.');
        }
      } catch (err) {
        setError(err.response?.data?.detail || err.message || 'Failed to reach server.');
      }
    };

    poll();
    pollRef.current = setInterval(poll, 2000);
    timerRef.current = setInterval(() => {
      elapsedRef.current += 1;
      setElapsed(elapsedRef.current);
    }, 1000);

    return () => {
      clearInterval(pollRef.current);
      clearInterval(timerRef.current);
    };
  }, [job_id, navigate]);

  useEffect(() => {
    stepsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [steps]);

  return (
    <div className="max-w-3xl mx-auto px-6 py-12">
      {/* Job header */}
      <div className="flex items-start justify-between mb-8 gap-4">
        <div>
          <h1 className="text-xl font-semibold text-gray-100 break-all">{filename}</h1>
          <p className="text-sm text-gray-400 mt-1">{modeLabel} mode</p>
        </div>
        <div className="flex items-center gap-1.5 text-gray-400 text-sm shrink-0">
          <Clock className="w-4 h-4" />
          <span data-testid="elapsed">{elapsed}s</span>
        </div>
      </div>

      {/* Status area */}
      {error ? (
        <div
          className="flex items-start gap-3 bg-red-900/30 border border-red-700 rounded-xl p-6"
          data-testid="error-panel"
        >
          <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 shrink-0" />
          <div>
            <p className="font-medium text-red-300">Analysis Failed</p>
            <p className="text-sm text-red-400 mt-1">{error}</p>
          </div>
        </div>
      ) : status === 'queued' ? (
        <div
          className="flex items-center gap-3 bg-gray-800 border border-gray-700 rounded-xl p-6 text-gray-300"
          data-testid="queued-panel"
        >
          <Loader2 className="w-5 h-5 animate-spin text-indigo-400 shrink-0" />
          <span>Queued — waiting for worker…</span>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Current live step */}
          {currentAction && (
            <div
              className="bg-indigo-900/20 border border-indigo-700 rounded-xl p-5"
              data-testid="current-step"
            >
              <div className="flex items-center gap-2 mb-3">
                <Loader2 className="w-4 h-4 animate-spin text-indigo-400 shrink-0" />
                <span className="text-indigo-300 font-semibold text-sm">
                  🔍 Step {currentStep} of {maxSteps} — Running
                </span>
              </div>
              <p className="text-gray-300 text-sm italic">&ldquo;{currentAction}&rdquo;</p>
            </div>
          )}

          {/* Previous steps log */}
          {steps.length > 1 && (
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-4 max-h-72 overflow-y-auto">
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">Previous steps</p>
              <div className="space-y-3">
                {steps.slice(0, -1).map((s) => (
                  <div key={s.step} className="border-l-2 border-gray-600 pl-3">
                    <p className="text-xs text-gray-500 mb-0.5">Step {s.step}</p>
                    <p className="text-sm text-gray-400 italic">&ldquo;{s.action}&rdquo;</p>
                  </div>
                ))}
              </div>
              <div ref={stepsEndRef} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
