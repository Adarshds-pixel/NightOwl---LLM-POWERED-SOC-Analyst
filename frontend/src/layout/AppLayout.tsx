import clsx from 'clsx'
import { Suspense, useCallback, useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { CommandPalette } from '../components/search/CommandPalette'
import { AmbientBackground, CursorGlow, LoadingState, PageTransition, ToastViewport } from '../components/ui'
import Sidebar from './Sidebar'
import Topbar from './Topbar'

const COLLAPSE_KEY = 'nightowl:sidebar-collapsed'

/**
 * The shell every route renders inside: rail, header, scrolling content.
 *
 * Three responsive modes rather than a binary one, because a SOC console is
 * used on 1920px wall displays and 1366px laptops alike:
 *   >= 1024px  sidebar in flow, expanded or user-collapsed
 *   <  1024px  sidebar becomes an overlay drawer opened from the header
 */
export function AppLayout() {
  const { pathname } = useLocation()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem(COLLAPSE_KEY) === 'true')
  const [mobileOpen, setMobileOpen] = useState(false)
  const [searchOpen, setSearchOpen] = useState(false)

  const toggleCollapsed = useCallback(() => {
    setCollapsed((current) => {
      const next = !current
      try {
        localStorage.setItem(COLLAPSE_KEY, String(next))
      } catch {
        // Preference only -- the layout still works without persistence.
      }
      return next
    })
  }, [])

  // Ctrl/Cmd+K opens global search from anywhere, including inside inputs,
  // which is the convention every console app shares.
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setSearchOpen((open) => !open)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  // Navigating closes the mobile drawer; without this the overlay stays up
  // over the page the user just chose.
  useEffect(() => {
    setMobileOpen(false)
  }, [pathname])

  return (
    <div className="flex h-screen overflow-hidden bg-transparent text-text">
      {/* Environment layers, mounted once for the whole console. Both are
          fixed, non-interactive and sit behind #root's content; the seed
          shifts the lighting slightly from page to page. */}
      <AmbientBackground seed={pathname} />
      <CursorGlow />

      <div className="hidden lg:flex">
        <Sidebar collapsed={collapsed} onToggleCollapsed={toggleCollapsed} />
      </div>

      {mobileOpen && (
        <div className="fixed inset-0 z-40 flex lg:hidden">
          <div className="absolute inset-0 bg-bg-deep/70 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
          <div className="relative animate-rise">
            <Sidebar collapsed={false} onToggleCollapsed={() => setMobileOpen(false)} />
          </div>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onOpenSearch={() => setSearchOpen(true)} onOpenSidebar={() => setMobileOpen(true)} />
        <main className={clsx('min-h-0 flex-1 overflow-y-auto')}>
          <Suspense fallback={<LoadingState label="Loading view" className="py-20" />}>
            {/* Keyed on pathname so each route replays the entrance. */}
            <PageTransition routeKey={pathname}>
              <Outlet />
            </PageTransition>
          </Suspense>
        </main>
      </div>

      <CommandPalette open={searchOpen} onClose={() => setSearchOpen(false)} />
      <ToastViewport />
    </div>
  )
}

export default AppLayout
