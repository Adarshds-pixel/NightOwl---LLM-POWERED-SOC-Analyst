import { NavLink } from 'react-router-dom'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/incidents', label: 'Incidents', end: false },
  { to: '/heatmap', label: 'Heatmap', end: false },
  // Day 17 (Pair 2) adds a 4th link here: Rules Manager.
]

function Sidebar() {
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-slate-800 bg-slate-900">
      <div className="px-4 py-5 text-lg font-semibold text-slate-100">
        NightOwl
      </div>
      <nav className="flex flex-col gap-1 px-2">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `rounded px-3 py-2 text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-slate-800 text-slate-100'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-100'
              }`
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}

export default Sidebar
