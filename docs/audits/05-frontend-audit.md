# NightOwl Frontend UX/UI Audit Report

**Date:** September 2026  
**Document:** `docs/audits/05-frontend-audit.md`  
**Status:** Read-Only Audit Complete  
**Scope:** Complete frontend code review across all routes, components, state containers, styles, and responsive viewports.

---

## Executive Summary

NightOwl's frontend is a React 19 / Vite / Tailwind CSS v4 single-page application tailored for automated security operations and LLM-assisted triage. The interface features a distinctive "violet nocturne" aesthetic, integrating Sigma rule evaluation, MITRE ATT&CK technique mapping, and RAG-based AI investigation.

While the application possesses a cohesive aesthetic and several thoughtful engineering patterns (such as optimistic UI, centralized design tokens, and reduced-motion support), this audit identified **12 confirmed UI/logic bugs**, **10 critical UX blockers**, **8 accessibility failures**, **6 visual design inconsistencies**, and several **analyst workflow bottlenecks**. 

The most severe operational issues include:
1. **Broken table-wide sorting** on the primary Incidents list (sorting only reorders the current 10–25 visible rows rather than the catalog).
2. **Permanent prompt loss** when the AI Assistant experiences rate limits, timeouts, or API errors.
3. **Client-side filtering bugs** on Sysmon Event IDs in the Logs view that produce empty tables while displaying thousands of matching results.
4. **Print / PDF export failures** that print dark backgrounds and near-invisible text on paper.
5. **Context fragmentation** in the Incident Detail view, where analysts must constantly cycle through six disconnected tabs.

---

## 1. Confirmed UI & Logic Bugs

### BUG-01: Table Client-Side Slicing Before Sorting (Broken Global Sorting)
- **Files:** `frontend/src/pages/IncidentsPage.tsx` (lines 58, 64), `frontend/src/components/ui/DataTable.tsx` (lines 98, 211–223)
- **Problem:** In `IncidentsPage.tsx`, `filtered` (the full in-memory list of matching incidents) is sliced to `visible` (`filtered.slice(page * pageSize, ...)`), and only `visible` is passed to `<DataTable rows={visible} sort={sort} onSortChange={setSort} />`. `DataTable` sorts whatever `rows` it is handed.
- **Failure:** Clicking column headers (Severity, Time, Host) sorts *only the 10 or 25 items on the current page*, rather than reordering the entire incident dataset. If an analyst sorts by Severity descending, critical incidents residing on page 2 do not move to page 1.
- **Fix:** Sort `filtered` in `IncidentsPage.tsx` before slicing to `visible`, or pass `filtered` and pagination props directly to `DataTable`.

### BUG-02: Pagination Reset Missing on Page Size Change
- **Files:** `frontend/src/pages/AlertsPage.tsx` (line 239), `frontend/src/pages/LogsPage.tsx` (line 293)
- **Problem:** In `AlertsPage` and `LogsPage`, the pagination component is bound as `onPageSizeChange={setPageSize}`. In `IncidentsPage.tsx` (line 232), it correctly resets the page: `onPageSizeChange={(size) => { setPageSize(size); setPage(0); }}`.
- **Failure:** When an analyst navigates to page 5 with 10 rows per page (offset 50) and changes page size to 50 or 100, `page` remains at 5 (offset 250 or 500). If the dataset only contains 60 records, the table immediately displays an empty state with no rows.
- **Fix:** Update `onPageSizeChange` in both pages to reset page index: `(size) => { setPageSize(size); setPage(0); }`.

### BUG-03: Sysmon Event ID Client-Side Filter Mismatches Server Pagination
- **Files:** `frontend/src/hooks/useEvents.ts` (lines 88–94), `frontend/src/pages/LogsPage.tsx` (lines 245–255)
- **Problem:** `GET /events` does not support an `event_id` query parameter. `useEvents` requests a page of 25 arbitrary events from the database and then applies a client-side filter: `events.filter(e => e.event_id === filters.eventId)`.
- **Failure:** When an analyst filters by Sysmon Event ID 1 (Process Creation), the server returns 25 mixed events. If only 2 events on that page match Event ID 1, the table displays only 2 rows. If none match, it displays 0 rows. Concurrently, the table header and pagination claim that thousands of matching events exist. Clicking to the next page displays another random fraction of rows.
- **Fix:** Add `event_id` filtering to the backend endpoint (`GET /events?event_id=1`), or if strictly read-only on backend, explicitly label the filter in the UI as "Filter current page only".

### BUG-04: Permanent Prompt Loss on AI Chat Error or Timeout
- **Files:** `frontend/src/components/chat/CommandInput.tsx` (lines 24–29), `frontend/src/hooks/useIncidentChat.ts` (lines 94–100)
- **Problem:** When an analyst submits a query in `CommandInput`, `setDraft('')` immediately erases the input textarea. If `postChatMessage` fails due to an HTTP 429 rate limit, 500 error, network interruption, or timeout, `useIncidentChat` removes the optimistic user message: `setTurns((prev) => prev.filter((t) => t.key !== optimisticKey))`.
- **Failure:** Lengthy, complex investigation questions written by the analyst are permanently lost without recovery or retry options.
- **Fix:** Preserve the failed message in the chat turn list with an `error: true` state and a "Retry" button, or restore the prompt back into `draft` upon failure.

### BUG-05: Cropped Text Artifact on Brand Emblem Asset
- **Files:** `frontend/public/nightowl-owl.png`, `frontend/src/components/brand/NightOwlMark.tsx` (lines 22–34)
- **Problem:** The primary brand mark asset `nightowl-owl.png` contains clipped white text fragments ("HT OW") along its bottom border, left over from cropping `frontend design images/logos.png`.
- **Failure:** Visible on the large 72px sign-in screen emblem (`LoginPage.tsx:196`) and the sidebar header (`Sidebar.tsx:52`), presenting an unpolished visual appearance.
- **Fix:** Recrop the source PNG with clean transparency around the bottom circular border, matching `favicon.png`.

### BUG-06: Broken Timeline CSS Connector Line Selector
- **Files:** `frontend/src/components/ui/rows.tsx` (lines 98–104)
- **Problem:** In `TimelineItem`, the vertical rule is defined as:
  `<span aria-hidden className="absolute top-4 bottom-[-0.75rem] left-[3px] w-px bg-line last:hidden" />`.
- **Failure:** In HTML DOM structure, this `<span>` is the second child of `<li>`, followed by the item body container (`<button>` or `<div>`). Because it is never the `:last-child` of `<li>`, `last:hidden` never evaluates to true. The vertical connector line on the final timeline item overflows into the parent card's padding.
- **Fix:** Apply conditional styling or target `li:last-child span.bg-line { display: none; }`.

### BUG-07: Dual Clear Buttons in Chromium Browsers
- **Files:** `frontend/src/components/ui/controls.tsx` (lines 41–58), `frontend/src/index.css`
- **Problem:** `SearchInput` uses `<input type="search">` and renders an explicit `<button aria-label="Clear search">` at `right-2`.
- **Failure:** WebKit/Chromium browsers (Chrome, Edge, Brave) automatically render their own native `-webkit-search-cancel-button` inside `type="search"`. When a user types, two overlapping "X" clear buttons appear on top of each other.
- **Fix:** Add `input[type="search"]::-webkit-search-cancel-button { display: none; }` to `index.css`.

### BUG-08: Collapsed Spacing in Notification Dropdown
- **Files:** `frontend/src/components/notifications/NotificationPanel.tsx` (lines 53–73)
- **Problem:** The container `<div className="max-h-[380px] overflow-y-auto p-1.5">` lacks a flex layout or spacing utility. Each child is a `<Link className="flex items-start ...">`.
- **Failure:** Notifications stack directly against one another with zero margin or gap, merging borders into a solid visual block.
- **Fix:** Add `flex flex-col gap-1.5` to the list container.

### BUG-09: Print / PDF Styling Inversion Failure
- **Files:** `frontend/src/pages/ReportsPage.tsx` (line 148), `frontend/src/layout/AppLayout.tsx`, `frontend/src/index.css` (lines 396–400)
- **Problem:** `ReportsPage` exposes a "Print / PDF" action via `window.print()`. While `index.css` specifies `@media print { body { background: white; color: black; } }`, the application cards retain dark backgrounds (`bg-surface-1/70`) and light foreground text tokens (`#f5f3ff`). Furthermore, `Sidebar` and `Topbar` lack `.print-hide` classes.
- **Failure:** Generating a report prints the entire navigation rail, top header, and illegible light text on white or dark card backgrounds.
- **Fix:** Add `print-hide` to `Sidebar` and `Topbar`, and define dedicated print styles in `index.css` resetting cards to white backgrounds with solid black borders and text.

### BUG-10: Live Log Stream Crash Reloads Entire SPA
- **Files:** `frontend/src/components/dashboard/LiveLogStreamPanel.tsx` (line 49)
- **Problem:** If polling fails in `LiveLogStreamPanel`, the error fallback renders `<ErrorState message={error} onRetry={() => window.location.reload()} />`.
- **Failure:** Clicking "Retry" reloads the entire browser application rather than triggering a localized hook refresh.
- **Fix:** Provide a targeted refetch function from `useLiveLogStream` and pass it to `onRetry`.

### BUG-11: Hardcoded Actor in Incident Status Audit Log
- **Files:** `frontend/src/components/incidents/StatusControl.tsx` (line 29)
- **Problem:** Changing incident status executes `updateIncidentStatus(incidentId, { status, actor: 'analyst' })`.
- **Failure:** The audit trail always records the generic string `'analyst'` rather than the logged-in username (`useAuth().username`).
- **Fix:** Read `username` from `useAuth()` and submit `{ status, actor: username ?? 'admin' }`.

### BUG-12: Brittle Substring Detection for AI Self-Critique Flags
- **Files:** `frontend/src/hooks/useExplain.ts` (line 82), `frontend/src/components/incidents/EvidenceSourcePanel.tsx` (lines 43–53)
- **Problem:** `selfCritiqueFlagged` evaluates via: `result?.explanation.includes('**Confidence check:**') ?? false`.
- **Failure:** If the self-critique pass succeeds and outputs `"**Confidence check:** All evidence corroborated"`, the UI flags it as an alert in amber ("Self-critique flagged a claim"). Conversely, if the critique pass failed or was omitted entirely, the UI displays a green badge ("Self-critique passed").
- **Fix:** Parse structured critique fields from the backend response rather than performing brittle substring checks on the explanation text.

---

## 2. SOC User Experience & Investigation Friction

### UX-01: Instantaneous, Irreversible Incident State Transitions
- **File:** `frontend/src/components/incidents/StatusControl.tsx`
- **Issue:** Clicking "closed" or "resolved" instantly updates the incident in the backend database. There is no confirmation step, no closing note requirement, and no disposition tagging (e.g., True Positive, False Positive, Benign, Remediated).
- **SOC Impact:** Analysts can accidentally close active incidents with a stray click. SOC operations require documented closure reasons and auditability for metrics (MTTR, False Positive rates).

### UX-02: Severe Context Fragmentation in Incident Investigation
- **File:** `frontend/src/pages/IncidentDetailPage.tsx`
- **Issue:** Incident information is divided across six mutually exclusive tabs (`Overview`, `Timeline`, `Evidence`, `AI Analysis`, `Chat`, `Audit`).
- **SOC Impact:** Investigating an attack requires correlating the timeline with AI recommendations and telemetry evidence. Forcing analysts to click back and forth between tabs causes cognitive fatigue and slows triage.

### UX-03: Non-Interactive MITRE ATT&CK Matrix Cells
- **File:** `frontend/src/components/mitre/HeatmapGrid.tsx`
- **Issue:** Technique cells in the heatmap grid render as non-interactive `<div>` tags with hover-only tooltips.
- **SOC Impact:** When an analyst spots a hot technique (e.g., `T1059` with 8 detections), they cannot click the cell to inspect the matching incidents or filter the event timeline.

### UX-04: Truncated Evidence Sources with No Inspection Drawer
- **File:** `frontend/src/components/incidents/EvidenceSourcePanel.tsx` (line 82)
- **Issue:** Retrieved RAG chunks are truncated using CSS `line-clamp-2` with no expand/collapse toggle or modal inspection drawer.
- **SOC Impact:** Analysts cannot verify LLM assertions against source technical documents, hindering validation of AI recommendations.

### UX-05: Missing Export and Clipboard Affordances
- **Files:** `frontend/src/pages/IncidentDetailPage.tsx`, `frontend/src/components/incidents/EvidenceSourcePanel.tsx`
- **Issue:** There are no "Copy as Markdown" or "Copy Summary" actions for AI explanations, recommended actions, or incident timelines.
- **SOC Impact:** Analysts must manually highlight and format text when transferring findings into ticketing platforms (Jira, ServiceNow, TheHive).

### UX-06: Unsearchable Dropdown for Incident Switching in Copilot
- **File:** `frontend/src/pages/AssistantPage.tsx` (line 130)
- **Issue:** The incident selector is a standard HTML `<select>` element hard-capped at 50 items (`incidents.slice(0, 50)`).
- **SOC Impact:** In environments with >50 incidents, older cases cannot be selected. Analysts cannot search by hostname, IP, or CVE.

### UX-07: Static "Recent Questions" in AI Assistant
- **File:** `frontend/src/pages/AssistantPage.tsx` (lines 234–240)
- **Issue:** Previous questions rendered in the sidebar rail are static list rows without `onClick` handlers.
- **SOC Impact:** Clicking previous queries does not populate the input box, re-run the question, or jump to the conversation turn.

### UX-08: Command Palette Lacks Keyboard Scroll-Into-View
- **File:** `frontend/src/components/search/CommandPalette.tsx`
- **Issue:** Pressing ArrowDown navigates through search results, but the scrollable container does not automatically scroll to keep the active item visible.
- **SOC Impact:** Navigating beyond the initial 5 items causes the selection highlight to disappear below the fold.

### UX-09: Misleading Disabled Toggles in Rules Engine
- **File:** `frontend/src/pages/RulesPage.tsx` (lines 124–129)
- **Issue:** Every row contains a permanently disabled switch component with a tooltip explaining that rules are static YAML files.
- **SOC Impact:** Presenting interactive toggles that cannot be toggled creates frustration. Status badges (`Active` / `Static`) would be clearer.

### UX-10: Complete Lack of Pagination in Rules Engine
- **File:** `frontend/src/pages/RulesPage.tsx`
- **Issue:** The rules table renders all loaded rules in a single unbroken list, despite Settings claiming that "Rows per page" applies to rules.
- **SOC Impact:** As detection rule coverage expands to hundreds of rules, the page becomes unwieldy to navigate.

---

## 3. Accessibility (WCAG 2.1 AA) Problems

| ID | WCAG Criterion | Location | Problem Description |
|---|---|---|---|
| **A11Y-01** | 2.1.2 No Keyboard Trap & 2.4.3 Focus Order | `frontend/src/components/ui/overlays.tsx` | Modals and Drawers do not implement a focus trap. Pressing `Tab` cycles focus into background sidebar and topbar elements while the overlay is open. |
| **A11Y-02** | 2.1.1 Keyboard Navigable | `frontend/src/components/mitre/HeatmapGrid.tsx` | Heatmap technique cells are non-focusable `<div>` elements with hover-only tooltips, completely inaccessible to keyboard and screen reader users. |
| **A11Y-03** | 1.4.1 Use of Color | `frontend/src/components/ui/rows.tsx` (`SeverityDotMarker`) | Incident list rows in panels use colored dots with no accompanying text or `aria-label` to communicate severity to colorblind users. |
| **A11Y-04** | 3.3.2 Labels or Instructions | `frontend/src/components/ui/controls.tsx` (`SearchInput`) | Search inputs rely solely on `placeholder` attributes and lack visible `<label>` elements or accessible names associated via `id`/`for`. |
| **A11Y-05** | 2.2.2 Pause, Stop, Hide | `frontend/src/components/dashboard/LiveLogStreamPanel.tsx` | The live tail pauses on `mouseenter`, but does not pause on keyboard `focusin`. Moving focus through the table causes rows to shift unexpectedly. |
| **A11Y-06** | 1.4.3 Contrast (Minimum) | `frontend/src/index.css` | Micro-text tokens (`0.625rem`) using `--color-text-faint` (`#6b647d`) on dark backgrounds (`#0b0715`) yield a contrast ratio of ~3.2:1, failing the 4.5:1 AA standard. |
| **A11Y-07** | 4.1.2 Name, Role, Value | `frontend/src/components/ui/StatCard.tsx` | When `onClick` is passed, `StatCard` renders an outer `<button>` wrapping arbitrary `<div>` and `<p>` tags, confusing screen readers on interactive hierarchy. |
| **A11Y-08** | 2.4.4 Link Purpose | `frontend/src/components/ui/rows.tsx` (`ViewAllLink`) | Renders generic text "View all" without contextual `aria-label` specifying which resource is being viewed. |

---

## 4. Information Architecture Problems

1. **Disconnected Alerts and Telemetry Logs:**
   Alerts (`/alerts`) and Raw Logs (`/logs`) exist as two independent pages with divergent filter bars. An analyst reviewing an alert cannot click to view the raw log stream 2 minutes before and after the event without manually noting timestamps and re-entering them on `/logs`.
2. **Redundant Visualizations on Overview:**
   The Overview page contains both a 5-column MITRE Heatmap and a 3-column "Top attack vectors" donut chart. Both visualize tactic/technique distributions from the same incident dataset, competing for screen space without providing distinct diagnostic value.
3. **Misleading Radial Gauge Semantics in Pipeline Health:**
   In `PipelineHealthPanel.tsx`, gauges for "Rules" and "Ingest" render at 100% full scale as boolean flags ("we have rules loaded", "we have events ingested"). Displaying full 100% circles for non-capacity metrics distorts standard data visualization semantics.
4. **Lack of a Dedicated Host View:**
   Hostnames (`WORKSTATION-01`, `DC-01`) appear in tables, cards, and graph nodes. However, clicking a host always routes to `/incidents` or `/logs` without providing a consolidated view of host activity, user accounts, and observed techniques.

---

## 5. Visual Design Inconsistencies

1. **Ambient Lighting Overuse & Visual Noise:**
   The combination of background aurora orbs, cyber grids, particle drifts, cursor glow, and card bloom creates visual distraction that competes with security severity indicators. In high-stress SOC environments, visual clarity should take precedence over decorative effects.
2. **Login Background Photographic Clash:**
   In `LoginPage.tsx`, the background image (`login-background.png`) features pre-rendered monitors and simulated threat maps. The foreground card sits directly over this imagery, producing visual clutter and conflicting typography.
3. **Micro-Typography Readability:**
   Excessive use of `0.625rem` (10px) and `0.5625rem` (9px) font sizes for critical metadata (timestamps, process paths, MITRE IDs) strains analyst readability on standard 1080p SOC workstations.
4. **Card Padding Discrepancies:**
   Standard cards use `px-4 py-3.5`, while list cards use `px-2 pb-3`, and detail drawers use `px-5 py-4`, creating subtle visual misalignments across adjacent grid columns.

---

## 6. Performance & Network Optimization Problems

1. **Excessive Burst of Polling Requests:**
   In `IncidentsDataProvider.tsx` (lines 62–70), each refresh cycle executes `Promise.all` across 7 separate requests (`fetchAllIncidents` + 6 individual limit=1 queries for severity/status counts). On low-tier backends or reverse proxies, this burst frequently trips 429 rate limiters.
2. **Unbounded Native Fetch Requests:**
   `rawFetch` in `client.ts` does not implement timeout controls or `AbortController` signals. Stalled LLM calls or network interruptions cause requests and UI loading spinners to hang indefinitely.
3. **Unmemoized Data Transformations on Overview:**
   Functions like `tacticTechniqueMatrix(incidents)`, `hostActivity(incidents)`, and `attackVectorBreakdown(incidents)` run directly in the body of `DashboardPage.tsx` on every re-render without `useMemo`.
4. **Layout Calculations in SVG Recharts:**
   Multiple instances of `ResponsiveContainer` across the Dashboard trigger synchronous DOM dimension measurements, causing visible micro-stutter during window resizing and sidebar toggles.

---

## 7. Investigation Workflow Bottlenecks

1. **High Mean-Time-to-Triage (MTTR):**
   Triaging an incident requires navigating between Overview, Incidents list, Incident Detail tabs, Logs, and Assistant, with no persistent split-screen drawer for rapid side-by-side analysis.
2. **No Timeline-to-Log Correlation:**
   Clicking an entry in the incident timeline opens an event drawer, but does not provide an "Explore surrounding events" button to view neighboring system activity.
3. **No Dossier Export for Escalation:**
   Analysts handling critical incidents cannot export a unified PDF/HTML briefing containing the incident details, timeline, AI root-cause analysis, and audit log for escalation to Tier 3 or external response teams.

---

## 8. Recommended Frontend Improvements & SOC Value

| Priority | Recommendation | Operational Value to SOC Investigation |
|---|---|---|
| **P1** | **Global Sorting in Incidents:** Sort the full dataset before slicing pagination in `IncidentsPage.tsx`. | Ensures analysts sorting by Severity immediately surface the most dangerous threats across the entire enterprise, eliminating missed critical cases. |
| **P2** | **AI Chat Prompt Preservation & Retry:** Retain failed messages in `useIncidentChat` and provide a one-click Retry button. | Prevents loss of complex analytical queries during transient network hiccups or LLM throttling. |
| **P3** | **Interactive MITRE Matrix Cells:** Enable clicking heatmap cells to filter incidents or open technique details. | Accelerates threat hunting by allowing analysts to pivot directly from detected adversary techniques to affected endpoints. |
| **P4** | **Consolidated Incident Investigation Layout:** Replace 6 separate tabs with a modern 2-column or 3-column split view (Timeline/Evidence on left, AI Analysis & Chat on right). | Reduces cognitive context switching and allows analysts to cross-reference evidence against AI recommendations in real time. |
| **P5** | **Incident Closure & Disposition Modal:** Add a confirmation modal requiring closure disposition (True Positive, False Positive, Benign) and notes. | Eliminates accidental closures and captures structured metric data for tuning detection rules. |
| **P6** | **Server-Side Event ID Filtering:** Implement backend `event_id` query support in `GET /events`. | Enables reliable filtering of Sysmon telemetry (Process Creation, Network Connect) without blank pages or pagination discrepancies. |
| **P7** | **A11y Focus Trapping & Contrast Correction:** Implement focus trapping in `Modal`/`Drawer` and elevate micro-text contrast to 4.5:1. | Ensures compliance with accessibility standards and prevents disorientation for keyboard-driven operators. |
| **P8** | **Optimized Request Batching:** Consolidate the 7 separate metadata requests into a single `/incidents/stats` endpoint. | Slashes network overhead by 85%, eliminating self-inflicted 429 rate limiting during incident triage. |
| **P9** | **Full Source Document Expansion:** Add an expandable drawer to inspect complete RAG chunks in `EvidenceSourcePanel`. | Empowers analysts to verify LLM citations against technical threat intel, preventing hallucinated conclusions. |
| **P10** | **Clean Print & Export Styles:** Fix `@media print` rules to output high-contrast black-on-white executive incident dossiers. | Enables clean escalation of incident briefings to leadership and legal teams. |
