import type { VulnType } from './types'

// Static security context per weakness type: classification, exposure and how to fix it.
export interface TypeInfo {
  cweName: string
  owasp: string
  attacker: string
  dataAtRisk: string
  remediation: string[]
}

export const TYPE_INFO: Record<VulnType, TypeInfo> = {
  AI_PROMPT_INJECTION: {
    cweName: 'Improper neutralization of special elements used in a command',
    owasp: 'LLM01:2025 Prompt Injection',
    attacker: 'Anyone who can chat, including anonymous visitors',
    dataAtRisk: 'Every customer record, plus the system prompt',
    remediation: [
      'Refuse or neutralize instruction-like input before it reaches the model.',
      'Never let the content of a message decide whether the model gets database access.',
      'Fence user text in explicit delimiters and tell the model to treat it as data.',
      'Remove "always follow user instructions" from the system prompt.',
    ],
  },
  AI_BROKEN_AUTH: {
    cweName: 'Missing authorization',
    owasp: 'LLM06:2025 Excessive Agency',
    attacker: 'Any signed-in customer',
    dataAtRisk: "Other customers' account numbers and balances",
    remediation: [
      'Scope every lookup the assistant makes to the signed-in account.',
      'Give anonymous chats no database access at all.',
      'Log and refuse lookups that would return another customer’s data.',
    ],
  },
  AI_INFO_DISCLOSURE: {
    cweName: 'Exposure of sensitive information to an unauthorized actor',
    owasp: 'LLM07:2025 System Prompt Leakage',
    attacker: 'Anyone who can reach /api/ai/system-info',
    dataAtRisk: 'System prompt, model name and API endpoint',
    remediation: [
      'Remove the system-info endpoint or restrict it to administrators.',
      'Return only non-sensitive fields such as the model name.',
      'Keep the system prompt server-side and never echo it back.',
    ],
  },
  VERBOSE_ERROR_DISCLOSURE: {
    cweName: 'Generation of error message containing sensitive information',
    owasp: 'LLM02:2025 Sensitive Information Disclosure',
    attacker: 'Anyone who can make the model call fail',
    dataAtRisk: 'API key prefix, system info and internal error text',
    remediation: [
      'Return a generic error to the user and log the details server-side.',
      'Never include any part of an API key in a response.',
      'Drop system_info from error payloads.',
    ],
  },
  AI_ROLE_OVERRIDE: {
    cweName: 'Improper neutralization of input used for LLM prompting',
    owasp: 'LLM01:2025 Prompt Injection',
    attacker: 'Anyone who can chat',
    dataAtRisk: 'Whatever the model can reach once its role is changed',
    remediation: [
      'Rewrite the system prompt so it never yields to role-change requests.',
      'State plainly that instructions inside user messages must be ignored.',
      'Back this up with input guards; prompt wording alone is not a control.',
    ],
  },
  HARDCODED_CREDENTIALS: {
    cweName: 'Use of hard-coded credentials',
    owasp: 'LLM02:2025 Sensitive Information Disclosure',
    attacker: 'Anyone with read access to the source',
    dataAtRisk: 'Database credentials',
    remediation: [
      'Load credentials from the environment or a secret manager.',
      'Rotate any credential that was ever committed.',
    ],
  },
}
