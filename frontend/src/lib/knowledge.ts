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
    owasp: 'A07:2021 Identification and Authentication Failures',
    attacker: 'Anyone with read access to the source or its history',
    dataAtRisk: 'Whatever the credential unlocks: databases, APIs, admin access',
    remediation: [
      'Load the secret from the environment or a secret manager at runtime.',
      'Rotate it now: anything ever committed must be treated as leaked.',
      'Add a secret scanner to CI so new ones are caught before merge.',
    ],
  },
  SQL_INJECTION: {
    cweName: 'Improper neutralization of special elements used in an SQL command',
    owasp: 'A03:2021 Injection',
    attacker: 'Anyone who can send the input that reaches the query',
    dataAtRisk: 'Every row the database user can read or change',
    remediation: [
      'Use bound parameters (? or %s placeholders) instead of building SQL text.',
      'Keep LIKE wildcards in the parameter value, not in the query string.',
      'Run the app with a database user that only has the rights it needs.',
    ],
  },
  COMMAND_INJECTION: {
    cweName: 'Improper neutralization of special elements used in an OS command',
    owasp: 'A03:2021 Injection',
    attacker: 'Anyone who controls the value passed to the shell',
    dataAtRisk: 'The whole server: files, secrets, other services',
    remediation: [
      'Call the program directly with an argument list (subprocess.run([...])) and no shell.',
      'Never pass shell=True with input in the command.',
      'Validate input against an allow-list where the value has a known shape.',
    ],
  },
  CODE_INJECTION: {
    cweName: 'Improper neutralization of directives in dynamically evaluated code',
    owasp: 'A03:2021 Injection',
    attacker: 'Anyone who can influence the evaluated string',
    dataAtRisk: 'Everything the app process can reach',
    remediation: [
      'Remove eval/exec. Use ast.literal_eval for literals or json.loads for data.',
      'For formulas or expressions, use a small parser with an allow-list of operations.',
    ],
  },
  PATH_TRAVERSAL: {
    cweName: 'Improper limitation of a pathname to a restricted directory',
    owasp: 'A01:2021 Broken Access Control',
    attacker: 'Anyone who can choose the file name',
    dataAtRisk: 'Any file the app can read: config, keys, source code',
    remediation: [
      'Resolve the full path and refuse it unless it stays inside the allowed folder.',
      'Prefer a lookup by ID over a caller-supplied file name.',
      'Use werkzeug.utils.secure_filename or send_from_directory for uploads and downloads.',
    ],
  },
  SSRF: {
    cweName: 'Server-side request forgery',
    owasp: 'A10:2021 Server-Side Request Forgery',
    attacker: 'Anyone who can submit the URL',
    dataAtRisk: 'Internal services and cloud metadata (often including credentials)',
    remediation: [
      'Only fetch from an allow-list of hosts.',
      'Resolve the host and block private, loopback and link-local addresses.',
      'Disable redirects or re-check the destination after each one.',
    ],
  },
  INSECURE_DESERIALIZATION: {
    cweName: 'Deserialization of untrusted data',
    owasp: 'A08:2021 Software and Data Integrity Failures',
    attacker: 'Anyone who can supply the serialized bytes',
    dataAtRisk: 'The server: loading the data runs code',
    remediation: [
      'Use a data-only format such as JSON for anything that crosses a trust boundary.',
      'Use yaml.safe_load, never yaml.load with the full loader.',
      'If pickle is unavoidable, sign the data and verify the signature before loading.',
    ],
  },
  INSECURE_JWT: {
    cweName: 'Improper verification of cryptographic signature',
    owasp: 'A07:2021 Identification and Authentication Failures',
    attacker: 'Anyone, by forging a token',
    dataAtRisk: 'Every account: a forged token can claim to be any user or an admin',
    remediation: [
      'Always verify the signature with the right key.',
      'Pin the accepted algorithms (for example algorithms=["HS256"]) and never allow "none".',
      'Check expiry and audience claims.',
    ],
  },
  TLS_VERIFY_DISABLED: {
    cweName: 'Improper certificate validation',
    owasp: 'A02:2021 Cryptographic Failures',
    attacker: 'Anyone on the network path',
    dataAtRisk: 'Everything sent or received over that connection',
    remediation: [
      'Remove verify=False so certificates are checked.',
      'For internal certificate authorities, pass verify="/path/to/ca.pem" instead.',
    ],
  },
  WEAK_CRYPTO: {
    cweName: 'Use of a one-way hash with insufficient computational effort',
    owasp: 'A02:2021 Cryptographic Failures',
    attacker: 'Anyone who obtains the stored hashes',
    dataAtRisk: 'User passwords, which are often reused elsewhere',
    remediation: [
      'Hash passwords with bcrypt, scrypt or Argon2 (for example via passlib or argon2-cffi).',
      'Rehash existing passwords with the new scheme at next sign-in.',
    ],
  },
  DEBUG_MODE: {
    cweName: 'Active debug code',
    owasp: 'A05:2021 Security Misconfiguration',
    attacker: 'Anyone who can trigger an error page',
    dataAtRisk: 'The server: the debugger console runs arbitrary code',
    remediation: [
      'Turn debug off in production, for example from an environment variable.',
      'Serve the app with a production server such as gunicorn, not app.run().',
    ],
  },
  BROKEN_ACCESS_CONTROL: {
    cweName: 'Authorization bypass through user-controlled key',
    owasp: 'A01:2021 Broken Access Control',
    attacker: 'Any signed-in user who changes an id in the request',
    dataAtRisk: "Other users' records",
    remediation: [
      'Load records through the signed-in user (WHERE owner = current user), not by id alone.',
      'Return 404 rather than 403 for records the caller does not own, so ids cannot be probed.',
      'Add a test that one user cannot read or change another user’s record.',
    ],
  },
  MISSING_AUTHENTICATION: {
    cweName: 'Missing authentication for critical function',
    owasp: 'A07:2021 Identification and Authentication Failures',
    attacker: 'Anyone who can reach the route',
    dataAtRisk: 'Whatever the unprotected route reads or changes',
    remediation: [
      'Require a signed-in user on the route with the app’s existing auth decorator or dependency.',
      'Check the caller’s role for admin-only actions.',
      'Deny by default: new routes should need auth unless explicitly public.',
    ],
  },
  XSS: {
    cweName: 'Improper neutralization of input during web page generation',
    owasp: 'A03:2021 Injection',
    attacker: 'Anyone who can get text shown to another user',
    dataAtRisk: "Other users' sessions and anything they can do in the app",
    remediation: [
      'Render through templates with auto-escaping; never build HTML from user text.',
      'Avoid render_template_string, Markup() and |safe on user input.',
      'Add a Content-Security-Policy header as a second line of defence.',
    ],
  },
  OPEN_REDIRECT: {
    cweName: 'URL redirection to untrusted site',
    owasp: 'A01:2021 Broken Access Control',
    attacker: 'Anyone who can send a victim a link',
    dataAtRisk: 'User trust and credentials (phishing through your domain)',
    remediation: [
      'Redirect only to relative paths or an allow-list of known hosts.',
      'Reject URLs with a scheme or // prefix in the redirect parameter.',
    ],
  },
  CSRF: {
    cweName: 'Cross-site request forgery',
    owasp: 'A01:2021 Broken Access Control',
    attacker: 'Any website a signed-in user visits',
    dataAtRisk: 'Anything a state-changing request can do as the victim',
    remediation: [
      'Require a CSRF token on every state-changing form and request.',
      'Set session cookies with SameSite=Lax or Strict.',
      'Never change state on GET requests.',
    ],
  },
  MASS_ASSIGNMENT: {
    cweName: 'Improperly controlled modification of dynamically determined object attributes',
    owasp: 'A08:2021 Software and Data Integrity Failures',
    attacker: 'Any user who adds extra fields to a request',
    dataAtRisk: 'Fields such as role, balance or owner',
    remediation: [
      'Copy only an explicit allow-list of fields from the request.',
      'Use a schema that rejects unknown fields.',
    ],
  },
  INSECURE_FILE_UPLOAD: {
    cweName: 'Unrestricted upload of file with dangerous type',
    owasp: 'A04:2021 Insecure Design',
    attacker: 'Anyone who can upload a file',
    dataAtRisk: 'The server and other users, through stored executable content',
    remediation: [
      'Allow-list extensions and check the content type and size.',
      'Store uploads outside the web root under generated names.',
      'Serve them with Content-Disposition: attachment.',
    ],
  },
  BUSINESS_LOGIC: {
    cweName: 'Improper enforcement of behavioral workflow',
    owasp: 'A04:2021 Insecure Design',
    attacker: 'Any user who sends unexpected values or skips a step',
    dataAtRisk: 'Money, balances and anything the workflow protects',
    remediation: [
      'Validate amounts and states on the server: positive, within limits, in the right order.',
      'Do balance checks and updates in one database transaction.',
    ],
  },
  RACE_CONDITION: {
    cweName: 'Concurrent execution using shared resource with improper synchronization',
    owasp: 'A04:2021 Insecure Design',
    attacker: 'Any user who sends the same request many times at once',
    dataAtRisk: 'Balances, stock counts and one-time actions',
    remediation: [
      'Check and update in one atomic statement or a transaction with row locks.',
      'Use idempotency keys for one-time actions.',
    ],
  },
  SENSITIVE_DATA_EXPOSURE: {
    cweName: 'Exposure of sensitive information to an unauthorized actor',
    owasp: 'A02:2021 Cryptographic Failures',
    attacker: 'Anyone who can read the response or the logs',
    dataAtRisk: 'Passwords, tokens and personal data',
    remediation: [
      'Return only the fields the caller needs; never send password hashes or secrets.',
      'Keep secrets and personal data out of logs and error messages.',
    ],
  },
  OTHER_WEAKNESS: {
    cweName: 'Protection mechanism failure',
    owasp: 'A04:2021 Insecure Design',
    attacker: 'See the finding’s rationale',
    dataAtRisk: 'See the finding’s rationale',
    remediation: [
      'Follow the AI review’s fix hint, then run the proof checks on the change.',
    ],
  },
}
