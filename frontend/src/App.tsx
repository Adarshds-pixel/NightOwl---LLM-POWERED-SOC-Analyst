import { lazy, Suspense } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { RedirectIfAuthenticated } from './context/auth/RedirectIfAuthenticated'
import { RequireAuth } from './context/auth/RequireAuth'
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
const LoginPage = lazy(() => import('./pages/LoginPage'))

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Sits outside AppLayout: the sign-in screen has no sidebar or
            topbar. RedirectIfAuthenticated sends an already-logged-in admin
            straight to the Dashboard instead of showing the form again.

            It carries its own Suspense because the only other boundary in
            the app lives inside AppLayout, which this route deliberately
            does not render. */}
        <Route
          path="/login"
          element={
            <RedirectIfAuthenticated>
              <Suspense fallback={null}>
                <LoginPage />
              </Suspense>
            </RedirectIfAuthenticated>
          }
        />
        {/* Every route below requires a real, currently-valid session --
            RequireAuth redirects to /login otherwise. This is the frontend
            half of the gate only: the backend independently rejects any
            request without a valid session cookie regardless of what the
            UI shows (see require_session_auth in backend/app/core/auth.py),
            so this route guard is a UX convenience, not the actual
            enforcement boundary. */}
        <Route element={<RequireAuth><AppLayout /></RequireAuth>}>
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
