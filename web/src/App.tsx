import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/layout/Layout'
import { Dashboard } from './pages/Dashboard'
import { SecurityScans } from './pages/SecurityScans'
import { Vulnerabilities } from './pages/Vulnerabilities'
import { Reports } from './pages/Reports'
import { Analytics } from './pages/Analytics'
import { Integrations } from './pages/Integrations'
import { Database } from './pages/Database'
import { Team } from './pages/Team'
import { Settings } from './pages/Settings'
import { Test } from './pages/Test'
import { NotificationProvider } from './contexts/NotificationContext'

function App() {
  return (
    <NotificationProvider>
      <Router>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="scans" element={<SecurityScans />} />
            <Route path="test" element={<Test />} />
            <Route path="vulnerabilities" element={<Vulnerabilities />} />
            <Route path="reports" element={<Reports />} />
            <Route path="analytics" element={<Analytics />} />
            <Route path="integrations" element={<Integrations />} />
            <Route path="database" element={<Database />} />
            <Route path="team" element={<Team />} />
            <Route path="settings" element={<Settings />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
    </NotificationProvider>
  )
}

export default App
