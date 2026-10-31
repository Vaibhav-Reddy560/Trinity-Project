import { createContext, useContext } from 'react'
import { MOCK_TARGETS } from './scope'
import type { TargetsResponse } from './types'

// The active target and the curated alternatives, loaded from GET /api/v1/targets.
export const TargetContext = createContext<TargetsResponse>(MOCK_TARGETS)

export const useTargets = () => useContext(TargetContext)
export const useActiveTarget = () => useContext(TargetContext).active
