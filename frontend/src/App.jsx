import { BrowserRouter, Routes, Route, Link, NavLink } from 'react-router-dom';
import Upload from './pages/Upload';
import AgentMonitor from './pages/AgentMonitor';
import Report from './pages/Report';
import History from './pages/History';

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex flex-col h-screen bg-gray-900 text-gray-100">
        <nav className="border-b border-gray-800 bg-gray-900/95 backdrop-blur shrink-0 z-10 px-6 py-4 flex items-center justify-between">
          <Link to="/" className="text-xl font-bold tracking-tight text-white">
            <span className="text-indigo-400">Mal</span>Sight
          </Link>
          <NavLink
            to="/reports"
            className={({ isActive }) =>
              `text-sm transition-colors ${isActive ? 'text-indigo-400' : 'text-gray-400 hover:text-gray-200'}`
            }
          >
            Report History
          </NavLink>
        </nav>
        <main className="flex-1 overflow-auto flex flex-col">
          <Routes>
            <Route path="/" element={<Upload />} />
            <Route path="/job/:job_id" element={<AgentMonitor />} />
            <Route path="/job/:job_id/report" element={<Report />} />
            <Route path="/reports" element={<History />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
