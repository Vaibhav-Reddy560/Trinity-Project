Problem Statement 01: AGENTSHIELD

    Track Name: Secure the Agent, Not Just the Prompt | Focus: AI-agent / MCP / tool-use security

    The Problem: AI agents can read documents, call tools, search repositories, and take actions on behalf of users. Untrusted emails, pages, retrieved files, or tool responses may contain instructions intended to redirect an agent, disclose secrets, or misuse a permitted tool. Traditional filtering of user prompts does not establish trustworthy boundaries for tool permissions.

    Challenge Statement: Build a defensive security layer that monitors and constrains an AI agent or tool-driven assistant operating in a simulated environment. It must distinguish legitimate tasks from unauthorized instructions arriving through untrusted content, prevent at least one category of unsafe tool action, and provide an inspectable reason for its decision.

    Expected Build Scope in 24 Hours:

        Minimum working demo: one simulated agent, at least two tools or permissions, a policy enforcement point, and an audit log.

        Security scenarios: legitimate task; prompt-injected web or document content; unauthorized sensitive-data request; tool invocation beyond permission. All data synthetic.

        Show explicit allow/deny/require-approval decisions, user confirmation for high-impact actions, and fail-closed behavior when confidence/policy is insufficient.

        Optional extensions: MCP gateway, tool permission profiles, signed tool metadata, cross-agent audit trails, risk-aware approval queue.

Problem Statement 02: PATCHPROOF

    Track Name: Find the Flaw. Prove the Fix | Focus: AppSec / SAST / secure patching

    The Problem: Vulnerability scanners often produce noisy alerts, while remediation tools propose code changes that can break legitimate functionality. Smaller teams need evidence that a finding is real and that a patch removes the weakness without introducing regressions.

    Challenge Statement: Build a tool or workflow that identifies security weaknesses in deliberately vulnerable sample software, proposes or applies a defensive fix, and validates that the fix stops the original exploit condition while preserving expected application behavior. AI assistance is optional; accuracy and verification matter more than model complexity.

    Expected Build Scope in 24 Hours:

        Select a supplied or public deliberately vulnerable practice app / local fixture; document the precise in-scope files.

        Identify at least two defensible weakness cases (for example, unsafe input handling or broken access control), with evidence grounded in source or executable tests.

        Provide a minimal patch or actionable diff for at least one verified issue, then run a regression/security test.

        Display severity rationale, exact affected code location, patch rationale, and test status.

Problem Statement 03: TRUSTLENS

    Track Name: Catch the Impersonation | Focus: phishing / social engineering / identity trust

    The Problem: Phishing increasingly combines convincing wording, impersonation, shortened or confusing links, and multi-channel messages. Static keyword filters can misclassify legitimate messages and do not explain what evidence led to a warning. Indian users and small organizations also face multilingual and code-mixed messages.

    Challenge Statement: Build a privacy-conscious defensive assistant that assesses suspicious messages or simulated identity claims, explains the risk signals, and recommends safe verification steps. Support at least two realistic message types or languages. Detects risk without automatically opening links, sending replies, or taking actions on a user’s behalf.

    Expected Build Scope in 24 Hours:

        Analyze a curated synthetic dataset containing benign and suspicious examples across any two channels/languages (e.g., email + SMS; English + Kannada/Hindi).

        Extract defensible signals: sender/domain inconsistency, URL obfuscation, suspicious urgency, request for credentials or financial action, missing provenance.

        Present risk tier + cited textual evidence + clear “verify through known channel” guidance; allow users to challenge a false positive.

        Optional extension: synthetic voice/deepfake flagging, suspicious QR content, reporting dashboard. (Deepfake detection is optional, not mandatory).
