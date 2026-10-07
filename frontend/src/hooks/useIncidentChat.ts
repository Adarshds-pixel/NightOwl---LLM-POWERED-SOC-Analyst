import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, getChatHistory, postChatMessage, type SourceChunk } from '../api'

// Unifies GET /chat's ChatHistoryMessage (has id/created_at, never sources --
// the backend doesn't persist retrieval sources) and POST /chat's
// ChatMessageResponse (has sources, never id/created_at) into one shape.
// `createdAt` stays null rather than fabricating a timestamp for turns sent
// this session; `sources` stays null for history turns rather than pretending
// they were never grounded.
export interface ChatTurn {
  key: string
  role: string
  content: string
  createdAt: string | null
  sources: SourceChunk[] | null
  pending?: boolean
}

let localTurnCounter = 0

export function useIncidentChat(incidentId: number) {
  const [turns, setTurns] = useState<ChatTurn[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [sending, setSending] = useState(false)
  const [sendError, setSendError] = useState<string | null>(null)
  // Bumped every time the viewed incident changes -- guards both load()
  // and send() below so a response for an incident the user has since
  // switched away from can never overwrite the currently-viewed one's
  // turns (the AI Assistant page lets you switch incidents via a
  // dropdown while a request is still in flight).
  const requestId = useRef(0)
  // The in-flight history load. send() waits for it, so a message sent
  // straight away (the dashboard's "ask the assistant" prefill) is not wiped
  // when the history response lands and replaces `turns`.
  const loadPromise = useRef<Promise<void>>(Promise.resolve())

  const load = useCallback(() => {
    const thisRequest = ++requestId.current
    // A different incident (or a reload) ends any send in flight for the
    // previous one -- without this `sending` stayed true forever and the
    // input stayed disabled until a page reload.
    setSending(false)
    setSendError(null)
    setError(null)
    if (incidentId <= 0) {
      setTurns([])
      setLoading(false)
      loadPromise.current = Promise.resolve()
      return
    }
    setLoading(true)
    loadPromise.current = getChatHistory(incidentId)
      .then((res) => {
        if (thisRequest !== requestId.current) return
        setTurns(
          res.messages.map((m) => ({
            key: `history-${m.id}`,
            role: m.role,
            content: m.content,
            createdAt: m.created_at,
            sources: null,
          })),
        )
      })
      .catch((err: Error) => {
        if (thisRequest === requestId.current) setError(err.message)
      })
      .finally(() => {
        if (thisRequest === requestId.current) setLoading(false)
      })
  }, [incidentId])

  useEffect(() => {
    load()
  }, [load])

  const send = useCallback(
    async (message: string) => {
      const trimmed = message.trim()
      if (!trimmed || sending || incidentId <= 0) return

      await loadPromise.current.catch(() => undefined)
      const thisRequest = requestId.current
      setSending(true)
      setSendError(null)
      const optimisticKey = `local-${++localTurnCounter}`
      setTurns((prev) => [
        ...prev,
        { key: optimisticKey, role: 'user', content: trimmed, createdAt: null, sources: null, pending: true },
      ])

      try {
        const res = await postChatMessage(incidentId, trimmed)
        // The user may have switched to a different incident while this
        // reply was in flight -- load() will have already replaced `turns`
        // with the new incident's history, so applying this response now
        // would silently attach the old incident's reply to it.
        if (thisRequest !== requestId.current) return
        setTurns((prev) => [
          ...prev.map((t) => (t.key === optimisticKey ? { ...t, pending: false } : t)),
          {
            key: `local-${++localTurnCounter}`,
            role: res.role,
            content: res.content,
            createdAt: null,
            sources: res.sources,
          },
        ])
      } catch (err) {
        if (thisRequest !== requestId.current) return
        // Drop the optimistic bubble rather than leaving a stuck "sending..."
        // message with no real reply behind it.
        setTurns((prev) => prev.filter((t) => t.key !== optimisticKey))
        setSendError(err instanceof ApiError ? err.detail : 'Failed to send message')
      } finally {
        if (thisRequest === requestId.current) setSending(false)
      }
    },
    [incidentId, sending],
  )

  return { turns, loading, error, sending, sendError, send, refresh: load }
}
