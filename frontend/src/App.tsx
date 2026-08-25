import { BrowserRouter, Route, Routes } from 'react-router-dom'
import AppLayout from './layout/AppLayout'
import DashboardPage from './pages/DashboardPage'
import DemoModePage from './pages/DemoModePage'
import HeatmapPage from './pages/HeatmapPage'
import IncidentDetailPage from './pages/IncidentDetailPage'
import IncidentsPage from './pages/IncidentsPage'
import LogsPage from './pages/LogsPage'
import NotFoundPage from './pages/NotFoundPage'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppLayout />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/incidents/:id" element={<IncidentDetailPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/heatmap" element={<HeatmapPage />} />
          <Route path="/demo" element={<DemoModePage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
