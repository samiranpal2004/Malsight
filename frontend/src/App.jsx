import { BrowserRouter, Routes, Route, Link, NavLink } from 'react-router-dom';
import Upload from './pages/Upload';
import AgentMonitor from './pages/AgentMonitor';
import Report from './pages/Report';
import History from './pages/History';
import Inbox from './pages/Inbox';
import EmailDetail from './pages/EmailDetail';
import AttachmentReport from './pages/AttachmentReport';
import Quarantine from './pages/Quarantine';
import ConnectGmail from './pages/ConnectGmail';

const NAV_LINKS = [
  { to: '/reports',         label: 'Report History' },
  { to: '/mail',            label: 'Inbox' },
  { to: '/mail/quarantine', label: 'Quarantine' },
  { to: '/gmail/connect',   label: 'Connect Gmail' },
];

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-900 text-gray-100">
        <nav className="border-b border-gray-800 bg-gray-900/95 backdrop-blur sticky top-0 z-10 px-6 py-4 flex items-center justify-between">
          <Link to="/" className="text-xl font-bold tracking-tight text-white">
            <span className="text-indigo-400">Mal</span>Sight
          </Link>
          <div className="flex items-center gap-6">
            {NAV_LINKS.map(({ to, label }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  `text-sm transition-colors ${isActive ? 'text-indigo-400' : 'text-gray-400 hover:text-gray-200'}`
                }
              >
                {label}
              </NavLink>
            ))}
          </div>
        </nav>
        <main>
          <Routes>
            <Route path="/" element={<Upload />} />
            <Route path="/job/:job_id" element={<AgentMonitor />} />
            <Route path="/job/:job_id/report" element={<Report />} />
            <Route path="/reports" element={<History />} />
            <Route path="/mail" element={<Inbox />} />
            <Route path="/mail/email/:email_id" element={<EmailDetail />} />
            <Route path="/mail/attachment/:attachment_id/report" element={<AttachmentReport />} />
            <Route path="/mail/quarantine" element={<Quarantine />} />
            <Route path="/gmail/connect"   element={<ConnectGmail />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
