import { useEffect, useState, useRef } from "react";
import { useParams } from "react-router-dom";
import { ReportContent } from "./Report";

const EVENT_COLORS = {
  thought:     { bg: "bg-blue-900/40",   border: "border-blue-500",  label: "AGENT_THOUGHT", labelColor: "text-blue-400"   },
  tool_call:   { bg: "bg-yellow-900/40", border: "border-yellow-500",label: "TOOL_CALL",      labelColor: "text-yellow-400" },
  tool_result: { bg: "bg-green-900/40",  border: "border-green-500", label: "TOOL_RESULT",    labelColor: "text-green-400"  },
};

function StatusBadge({ status }) {
  const styles = {
    running:    "bg-blue-500/20 text-blue-400 animate-pulse",
    complete:   "bg-green-500/20 text-green-400",
    failed:     "bg-red-500/20 text-red-400",
    connecting: "bg-gray-500/20 text-gray-400",
    error:      "bg-red-500/20 text-red-400",
  };
  const labels = {
    running:    "● ANALYZING",
    complete:   "✓ COMPLETE",
    failed:     "✗ FAILED",
    connecting: "● CONNECTING",
    error:      "✗ ERROR",
  };
  return (
    <span className={`px-3 py-1 rounded-full text-xs font-medium ${styles[status] ?? styles.connecting}`}>
      {labels[status] ?? "● CONNECTING"}
    </span>
  );
}

function EventCard({ event }) {
  const style = EVENT_COLORS[event.type] || EVENT_COLORS.thought;
  return (
    <div className={`rounded-lg border-l-4 p-3 ${style.bg} ${style.border}`}>
      <div className="flex items-center justify-between mb-1">
        <span className={`text-xs font-mono font-bold ${style.labelColor}`}>
          {style.label}
        </span>
        <span className="text-xs text-gray-500 font-mono">{event.timestamp}</span>
      </div>
      <p className={`text-sm ${
        event.type === "tool_call"
          ? "text-yellow-200 font-mono"
          : event.type === "tool_result"
          ? "text-green-200"
          : "text-gray-200 italic"
      }`}>
        {event.type === "tool_call" ? `→ ${event.content}` : event.content}
      </p>
    </div>
  );
}

export default function AgentMonitor() {
  const { job_id } = useParams();
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState("connecting");
  const [report, setReport] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const bottomRef = useRef(null);
  const startTime = useRef(Date.now());

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTime.current) / 1000));
    }, 1000);

    const apiKey = import.meta.env.VITE_API_KEY || "";
    const baseUrl = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
    const url = `${baseUrl}/stream/${job_id}`;

    let active = true;
    const controller = new AbortController();

    async function fetchReport() {
      const r = await fetch(`${baseUrl}/report/${job_id}`, {
        headers: { "X-API-Key": apiKey },
      });
      const data = await r.json();
      if (data.report) setReport(data.report);
      return data;
    }

    async function startStream() {
      try {
        const resp = await fetch(url, {
          headers: { "X-API-Key": apiKey },
          signal: controller.signal,
        });

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (active) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n\n");
          buffer = lines.pop();

          for (const line of lines) {
            if (line.startsWith("data: ")) {
              try {
                const event = JSON.parse(line.slice(6));
                if (event.type === "done") {
                  setStatus(event.status);
                  clearInterval(timer);
                  if (event.status === "complete") {
                    try {
                      await fetchReport();
                    } catch (e) {
                      console.error("Failed to fetch report", e);
                    }
                  }
                  return;
                } else {
                  setEvents((prev) => [...prev, event]);
                  setStatus("running");
                }
              } catch {}
            }
          }
        }
      } catch (err) {
        if (!active) return;
        // Stream dropped — fall back to polling
        const poll = setInterval(async () => {
          try {
            const data = await fetchReport();
            if (data.status === "complete") {
              clearInterval(poll);
              clearInterval(timer);
              setStatus("complete");
            } else if (data.status === "failed") {
              clearInterval(poll);
              clearInterval(timer);
              setStatus("failed");
            }
          } catch {}
        }, 2000);
        return () => clearInterval(poll);
      }
    }

    startStream();

    return () => {
      active = false;
      controller.abort();
      clearInterval(timer);
    };
  }, [job_id]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events]);

  return (
    <div className="flex-1 bg-gray-900 text-gray-100 flex flex-col overflow-hidden">
      {/* Top bar */}
      <div className="flex items-center justify-between px-6 py-3 border-b border-gray-800 shrink-0">
        <span className="text-gray-400 text-sm" data-testid="elapsed">{elapsed}s</span>
        <StatusBadge status={status} />
      </div>

      {/* Split view */}
      <div className="flex flex-1 overflow-hidden">

        {/* LEFT — Agent Reasoning (40%) */}
        <div className="w-2/5 border-r border-gray-800 flex flex-col overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-800 shrink-0">
            <h2 className="text-white font-semibold">Agent Reasoning</h2>
            <p className="text-gray-500 text-xs mt-0.5">Job {job_id}</p>
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-2">
            {events.length === 0 && (
              <div className="text-gray-500 text-sm animate-pulse">
                Waiting for agent to start...
              </div>
            )}
            {events.map((event, i) => (
              <EventCard key={i} event={event} />
            ))}
            <div ref={bottomRef} />
          </div>
        </div>

        {/* RIGHT — Threat Report (60%) */}
        <div className="w-3/5 flex flex-col overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-800 shrink-0">
            <h2 className="text-white font-semibold">Threat Report</h2>
          </div>
          <div className="flex-1 overflow-y-auto p-6">
            {!report && status !== "failed" && (
              <div className="flex flex-col items-center justify-center h-full gap-4">
                <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-gray-400 text-sm animate-pulse">
                  Analyzing — report will appear here when complete
                </p>
                {events.length > 0 && (
                  <p className="text-gray-600 text-xs">
                    Step {events[events.length - 1]?.step} in progress...
                  </p>
                )}
              </div>
            )}
            {status === "failed" && !report && (
              <div className="flex items-center justify-center h-full">
                <p className="text-red-400">Analysis failed. Check logs on the left.</p>
              </div>
            )}
            {report && <ReportContent report={report} showReasoningChain={false} />}
          </div>
        </div>

      </div>
    </div>
  );
}
