import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
// Inter carries the UI; JetBrains Mono is kept for timestamps, ids, metric
// figures and the terminal/log surfaces, where a monospace column actually
// helps. Both are self-hosted via fontsource -- no external font request.
import '@fontsource-variable/inter'
import '@fontsource/jetbrains-mono/400.css'
import '@fontsource/jetbrains-mono/500.css'
import '@fontsource/jetbrains-mono/600.css'
import './index.css'
import App from './App.tsx'
import { AppProviders } from './context/AppProviders'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AppProviders>
      <App />
    </AppProviders>
  </StrictMode>,
)
