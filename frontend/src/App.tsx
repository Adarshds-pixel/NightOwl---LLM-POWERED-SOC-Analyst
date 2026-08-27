import { lazy } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import AppLayout from './layout/AppLayout'
import DashboardPage from './pages/DashboardPage'

/**
 * Overview is imported eagerly (it is the landing route); every other page
 * is code-split, so the first paint does not carry the incident tables,
 * the MITRE matrix and the report generator with it.
 *
 * There is deliberately no /threat-intel or /threat-map route: neither
 * feature exists in NightOwl, and a route that renders a placeholder is a
 * promise the product does not keep.
 */
const IncidentsPage = lazy(() => import('./pages/IncidentsPage'))
const IncidentDetailPage = lazy(() => import('./pages/IncidentDetailPage'))
const AssistantPage = lazy(() => import('./pages/AssistantPage'))
const MitrePage = lazy(() => import('./pages/MitrePage'))
const AlertsPage = lazy(() => import('./pages/AlertsPage'))
const LogsPage = lazy(() => import('./pages/LogsPage'))
const RulesPage = lazy(() => import('./pages/RulesPage'))
const ReportsPage = lazy(() => import('./pages/ReportsPage'))
const SettingsPage = lazy(() => import('./pages/SettingsPage'))
const DemoModePage = lazy(() => import('./pages/DemoModePage'))
const NotFoundPage = lazy(() => import('./pages/NotFoundPage'))

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppLayout />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/incidents/:id" element={<IncidentDetailPage />} />
          <Route path="/assistant" element={<AssistantPage />} />
          <Route path="/mitre" element={<MitrePage />} />
          {/* The heatmap lived at its own route before the MITRE page
              existed; keep the old link working. */}
          <Route path="/heatmap" element={<Navigate to="/mitre" replace />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/demo" element={<DemoModePage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
