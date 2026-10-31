import { createContext, useContext } from 'react'
import type { AIStatus } from './types'

export const AI_OFF: AIStatus = { enabled: false, provider: 'anthropic', model: 'claude-opus-5-5', reason: null }
export const AIContext = createContext<AIStatus>(AI_OFF)
export const useAI = () => useContext(AIContext)

/** "Claude" or "Gemini", for copy that names the model doing the work. */
export const aiName = (ai: AIStatus) => (ai.provider === 'gemini' ? 'Gemini' : 'Claude')
