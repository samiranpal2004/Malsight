import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';

export default function ReasoningChain({ steps = [] }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="border border-gray-700 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="w-full flex items-center justify-between px-5 py-4 bg-gray-800 hover:bg-gray-700 text-left transition-colors"
        data-testid="reasoning-chain-toggle"
      >
        <span className="font-semibold text-gray-100">Analysis Reasoning Chain</span>
        <div className="flex items-center gap-2 text-gray-400 text-sm">
          <span>{steps.length} step{steps.length !== 1 ? 's' : ''}</span>
          {open ? (
            <ChevronDown className="w-4 h-4" />
          ) : (
            <ChevronRight className="w-4 h-4" />
          )}
        </div>
      </button>

      {open && (
        <div className="divide-y divide-gray-700" data-testid="reasoning-chain-body">
          {steps.map((step) => (
            <div key={step.step_number} className="p-5 bg-gray-800/50">
              <div className="flex items-center gap-2 mb-3">
                <span className="text-xs bg-gray-700 text-gray-300 rounded px-2 py-0.5 font-mono">
                  Step {step.step_number}
                </span>
              </div>
              {step.reasoning && (
                <p className="text-sm text-gray-300 italic mb-3">
                  &ldquo;{step.reasoning}&rdquo;
                </p>
              )}
              {step.tool_called && (
                <p className="text-xs font-mono text-indigo-400 bg-gray-900 rounded px-3 py-2 mb-3">
                  {step.tool_called}
                </p>
              )}
              {step.result_summary && (
                <p className="text-sm text-gray-400">{step.result_summary}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
