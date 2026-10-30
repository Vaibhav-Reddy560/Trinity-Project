import { useEffect, useState } from 'react'

export type Route =
  | { name: 'overview' }
  | { name: 'findings' }
  | { name: 'finding'; id: string }
  | { name: 'scope' }
  | { name: 'activity' }
  | { name: 'report' }

export function parseHash(hash: string): Route {
  const [page, id] = hash.replace(/^#\/?/, '').split('/').filter(Boolean)
  switch (page) {
    case 'findings':
      return id ? { name: 'finding', id: decodeURIComponent(id) } : { name: 'findings' }
    case 'scope':
      return { name: 'scope' }
    case 'activity':
      return { name: 'activity' }
    case 'report':
      return { name: 'report' }
    default:
      return { name: 'overview' }
  }
}

export const href = {
  overview: '#/',
  findings: '#/findings',
  finding: (id: string) => `#/findings/${encodeURIComponent(id)}`,
  scope: '#/scope',
  activity: '#/activity',
  report: '#/report',
}

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parseHash(window.location.hash))
  useEffect(() => {
    const onChange = () => {
      setRoute(parseHash(window.location.hash))
      window.scrollTo({ top: 0 })
    }
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  return route
}
