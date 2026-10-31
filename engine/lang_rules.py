"""Pattern rules for every language except Python (which has real syntax-tree rules in generic_rules.py).

Each rule is a regular expression applied to one line at a time (comments and string-only lines are skipped), tied to
the languages it makes sense for. These are deliberately narrow: input has to appear in the same expression as the
dangerous call, so a hit is a concrete path, not a style complaint. What they can't see (data flowing through several
functions) is what the AI deep scan is for.
"""

import re
from dataclasses import dataclass

from engine.generic_rules import Hit
from engine.languages import LANG_LABEL

# Where request data comes from, per language family.
JS_INPUT = r"(?:(?:req|request|ctx|event)\.(?:query|params|body|headers|cookies)|location\.(?:search|hash|href)|document\.(?:URL|referrer|cookie)|window\.name|process\.argv)"
PHP_INPUT = r"(?:\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER))"
JAVA_INPUT = r"(?:(?:request|req)\.get(?:Parameter|Header|QueryString|Cookies|InputStream)|@(?:RequestParam|PathVariable|RequestBody))"
GO_INPUT = r"(?:(?:r|req|request)\.(?:URL\.Query\(\)|FormValue|PostFormValue|Header\.Get|URL\.Path)|c\.(?:Query|Param|PostForm)\()"
RUBY_INPUT = r"(?:params\[|params\.(?:require|permit|fetch)|request\.(?:params|headers))"
CS_INPUT = r"(?:Request\.(?:Query|Form|Params|Headers|Cookies)|\[FromQuery\]|\[FromBody\]|\[FromForm\])"

SQL_WORDS = r"(?:select|insert|update|delete|where|from|into|values|order\s+by)\b"
SECRET_NAME = r"(?:passw(?:or)?d|passwd|pwd|secret|api_?key|apikey|auth_?token|access_?token|private_?key|client_?secret|credential)"
PLACEHOLDER = re.compile(
    r"^(x+|\*+|\.+|<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|change.?me.*|example.*|dummy.*|demo.*|test.*|sample.*|placeholder.*|todo.*|none|null|"
    r"password|secret|your[_-].*|replace.*|redacted|fake.*|default|process\.env.*|env\(.*|getenv.*|not.?supplied|not.?set|unset|unknown|"
    r"empty|n/?a|tbd|none.?set)$", re.I)


@dataclass
class LangRule:
    vtype: str
    severity: str
    cwe: str
    langs: frozenset[str]
    pattern: re.Pattern
    title: str
    rationale: str
    exclude: re.Pattern | None = None  # a line matching this is fine (a sanitiser on the same line)
    unquoted: bool = False  # match against the line with its string literals removed


def _r(vtype: str, severity: str, cwe: str, langs: str, pattern: str, title: str, rationale: str, exclude: str | None = None,
       unquoted: bool = False) -> LangRule:
    return LangRule(vtype, severity, cwe, frozenset(langs.split()), re.compile(pattern, re.I),
                    title, rationale, re.compile(exclude, re.I) if exclude else None, unquoted)


QUOTED = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'")


RULES: list[LangRule] = [
    # ---- injection ----
    _r("SQL_INJECTION", "HIGH", "CWE-89", "javascript",
       rf"\b(?:query|execute|raw|all|get|run|exec|prepare)\s*\(\s*(?:`[^`]*{SQL_WORDS}[^`]*\$\{{|[\"'][^\"']*{SQL_WORDS}[^\"']*[\"']\s*\+)",
       "Input pasted into a SQL query", "A value is concatenated or interpolated into the SQL text, so a crafted value can rewrite the query and read or change rows the caller should never see. Use parameter placeholders.",
       exclude=r"\?|\$\d"),
    _r("SQL_INJECTION", "HIGH", "CWE-89", "php",
       r"\"\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\b[^\"]*(?:\$\w|\{\$)|[\"']\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\b[^\"']*[\"']\s*\.\s*(?:\$|\w+\()",
       "Input pasted into a SQL query", "A PHP variable is written straight into the SQL string, so a crafted value can rewrite the query. Use prepared statements with bound parameters."),
    _r("SQL_INJECTION", "HIGH", "CWE-89", "java",
       rf"(?:executeQuery|executeUpdate|execute|createQuery|createNativeQuery|prepareStatement|queryForList|queryForObject)\s*\(\s*\"[^\"]*{SQL_WORDS}[^\"]*\"\s*\+",
       "Input pasted into a SQL query", "A value is concatenated into the SQL text, so a crafted value can rewrite the query. Use a PreparedStatement with ? placeholders."),
    _r("SQL_INJECTION", "HIGH", "CWE-89", "go",
       rf"(?:\.Query|\.QueryRow|\.Exec|\.QueryContext|\.ExecContext|\.Raw)\s*\(\s*(?:fmt\.Sprintf\(|\"[^\"]*{SQL_WORDS}[^\"]*\"\s*\+)",
       "Input pasted into a SQL query", "The query text is built with Sprintf or concatenation, so a crafted value can rewrite it. Pass values as arguments with $1/? placeholders."),
    _r("SQL_INJECTION", "HIGH", "CWE-89", "ruby",
       r"(?:where|find_by_sql|execute|select_all|order|joins)\s*\(?\s*\"[^\"]*#\{",
       "Input pasted into a SQL query", "Ruby string interpolation puts a value into the SQL text. Use placeholders: where(\"name = ?\", name)."),
    _r("SQL_INJECTION", "HIGH", "CWE-89", "csharp",
       rf"(?:new\s+SqlCommand|\.ExecuteSqlRaw|\.FromSqlRaw|\.CommandText\s*=)\s*\(?\s*(?:\$\"[^\"]*\{{|\"[^\"]*{SQL_WORDS}[^\"]*\"\s*\+)",
       "Input pasted into a SQL query", "The query is built with interpolation or concatenation. Use SqlParameter / FromSqlInterpolated."),
    _r("SQL_INJECTION", "HIGH", "CWE-943", "javascript",
       rf"\$where\s*:\s*(?:`[^`]*\$\{{|[\"'][^\"']*[\"']\s*\+|[a-z_$][\w.$]*\s*[,}}])|\.where\s*\(\s*(?:`[^`]*\$\{{|[\"'][^\"']*[\"']\s*\+)|\.find(?:One)?\s*\(\s*(?:{JS_INPUT})",
       "Input pasted into a database query (NoSQL)", "A request value becomes part of a MongoDB query or a $where JavaScript expression, so a crafted value can change what the query matches or run code in the database. Compare fields with fixed operators and validate types."),
    _r("XSS", "HIGH", "CWE-79", "javascript",
       r"autoescape\s*:\s*false|escape\s*:\s*false|\{\{\{\s*\w|<%-\s*\w|\|\s*safe\b",
       "Template output escaping turned off", "With escaping off, any text a user can influence is rendered as HTML, so stored or reflected script runs in other users' browsers."),
    _r("COMMAND_INJECTION", "CRITICAL", "CWE-78", "javascript",
       r"\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{|[^)]*\+\s*\w|[^)]*,\s*\{[^}]*shell\s*:\s*true)",
       "Shell command built from input", "A value is interpolated into a shell command, so characters like ; or && run extra commands. Use execFile/spawn with an argument array."),
    _r("COMMAND_INJECTION", "CRITICAL", "CWE-78", "php",
       rf"(?<![\w>$:])(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(.*(?:{PHP_INPUT}|\.\s*\$|\$\w)",
       "Shell command built from input", "A PHP variable reaches a shell command. Use escapeshellarg() or avoid the shell.",
       exclude=r"escapeshellarg|escapeshellcmd"),
    _r("COMMAND_INJECTION", "CRITICAL", "CWE-78", "php",
       r"`[^`]*\$\w[^`]*`",
       "Shell command built from input", "PHP's backtick operator runs a shell command with a variable in it. Use escapeshellarg() or avoid the shell.",
       unquoted=True),
    _r("COMMAND_INJECTION", "CRITICAL", "CWE-78", "java",
       r"Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:\"[^\"]*\"\s*\+|\w+\s*\+)|new\s+ProcessBuilder\s*\(\s*\"(?:sh|bash|cmd)(?:\.exe)?\"\s*,\s*\"-?[a-z/]*c\"\s*,\s*[^)]*\+",
       "Shell command built from input", "A value is concatenated into a command line. Pass arguments as a list and don't invoke a shell."),
    _r("COMMAND_INJECTION", "CRITICAL", "CWE-78", "go",
       r"exec\.Command(?:Context)?\s*\(\s*(?:ctx\s*,\s*)?\"(?:sh|bash|cmd)(?:\.exe)?\"\s*,\s*\"-?c\"\s*,\s*(?:fmt\.Sprintf|[^)]*\+)",
       "Shell command built from input", "A shell -c command is built from a value. Call the program directly with separate arguments."),
    _r("COMMAND_INJECTION", "CRITICAL", "CWE-78", "ruby",
       rf"(?:\bsystem|\bexec|%x|`|\bpopen|Open3\.\w+)\s*\(?\s*[\"`%]?[^)\n]*#\{{|\bsystem\s*\(?.*{RUBY_INPUT}",
       "Shell command built from input", "A value is interpolated into a shell command. Pass arguments separately: system(\"ls\", dir)."),
    _r("COMMAND_INJECTION", "CRITICAL", "CWE-78", "csharp",
       r"Process\.Start\s*\(\s*\"(?:cmd|powershell|bash|sh)(?:\.exe)?\"\s*,\s*(?:\$\"|[^)]*\+)",
       "Shell command built from input", "A value is concatenated into a shell command. Use ProcessStartInfo.ArgumentList."),
    _r("COMMAND_INJECTION", "CRITICAL", "CWE-78", "shell",
       r"\beval\s+[\"']?\$|\bsh\s+-c\s+[\"']?[^\"']*\$\w|\bbash\s+-c\s+[\"']?[^\"']*\$\w",
       "Shell evaluates a variable", "A variable is evaluated as shell code. Quote it and don't eval."),
    _r("CODE_INJECTION", "CRITICAL", "CWE-95", "javascript",
       r"(?<![\w.])eval\s*\(\s*[^\"'`)\s]|new\s+Function\s*\(\s*[^\"'`)\s]|set(?:Timeout|Interval)\s*\(\s*[\"'`][^\"'`]*[\"'`]\s*\+",
       "eval() runs a dynamic string", "Running a string as code lets anyone who can influence it run arbitrary code with the app's permissions."),
    _r("CODE_INJECTION", "CRITICAL", "CWE-95", "php",
       r"\b(?:eval|assert|create_function)\s*\(\s*\$|preg_replace\s*\(\s*[\"'][^\"']*/e[\"']",
       "eval() runs a dynamic string", "Running a string as PHP code lets anyone who can influence it run arbitrary code."),
    _r("CODE_INJECTION", "CRITICAL", "CWE-95", "ruby",
       r"\b(?:eval|instance_eval|class_eval|send|public_send|constantize)\s*\(?\s*(?:params|\w+\[|[a-z_]+\s*\))",
       "eval() or send() on a dynamic value", "A dynamic string is evaluated as code or used as a method name."),
    _r("XSS", "HIGH", "CWE-79", "javascript html",
       rf"\.(?:innerHTML|outerHTML)\s*(?:\+)?=\s*(?![\"'`][^\"'`$]*[\"'`]\s*;?\s*$)[^;]*(?:{JS_INPUT}|\+|\$\{{)|document\.write(?:ln)?\s*\(\s*[^\"')]|insertAdjacentHTML\s*\(\s*[\"']\w+[\"']\s*,\s*[^\"']|dangerouslySetInnerHTML\s*=\s*\{{\{{\s*__html\s*:\s*[^\"'`]|v-html\s*=",
       "HTML built from dynamic data", "Dynamic data is written into the page as HTML, so an attacker's markup or script runs in other users' browsers. Use textContent, or sanitise with a library such as DOMPurify.",
       exclude=r"DOMPurify|sanitize|escapeHtml|encodeURI"),
    _r("XSS", "HIGH", "CWE-79", "php",
       rf"\b(?:echo|print)\b[^;\n]*{PHP_INPUT}|<\?=\s*\$_",
       "Request data printed into the page", "A request value is echoed into HTML without escaping. Wrap it in htmlspecialchars().",
       exclude=r"htmlspecialchars|htmlentities|esc_html|intval|\(int\)|filter_var"),
    _r("XSS", "HIGH", "CWE-79", "ruby",
       r"\.html_safe\b|raw\s*[\(\s]\s*(?:params|@\w+)|<%==",
       "Output marked safe", "html_safe/raw disables escaping, so attacker-controlled text becomes markup.",
       exclude=r"['\"]\s*\.html_safe|\.inspect\.html_safe"),
    _r("XSS", "HIGH", "CWE-79", "csharp",
       r"Html\.Raw\s*\(|@Html\.Raw|\.InnerHtml\s*=\s*[^\"']",
       "Output rendered without encoding", "Raw HTML output disables encoding, so attacker-controlled text becomes markup."),
    _r("XSS", "HIGH", "CWE-79", "java",
       rf"(?:getWriter\(\)|out)\.(?:print|println|write|append)\s*\(.*(?:{JAVA_INPUT})",
       "Request data written into the page", "A request value is written into the response without encoding. Use an HTML encoder (OWASP Encoder, JSTL c:out).",
       exclude=r"encode|escape|Encoder"),
    _r("XSS", "HIGH", "CWE-79", "go",
       r"template\.HTML\s*\(|fmt\.Fprintf\s*\(\s*w\s*,\s*\"[^\"]*<",
       "Output rendered without encoding", "template.HTML or raw Fprintf of markup bypasses html/template escaping."),
    _r("PATH_TRAVERSAL", "HIGH", "CWE-22", "javascript",
       rf"\b(?:readFile|readFileSync|createReadStream|sendFile|download|unlink|unlinkSync|writeFile|writeFileSync|path\.join|path\.resolve)\s*\(.*(?:{JS_INPUT})",
       "File path built from input", "A request value is used in a file path, so ../ sequences reach files outside the intended folder. Resolve the path and check it stays inside the base folder.",
       exclude=r"basename|normalize\s*\([^)]*\)\s*\.replace|startsWith\s*\("),
    _r("PATH_TRAVERSAL", "HIGH", "CWE-22", "php",
       rf"(?<![\w$>:])(?:(?:include|require)(?:_once)?\b\s*\(?|(?:file_get_contents|fopen|readfile|file|unlink)\s*\()[^;]*{PHP_INPUT}",
       "File path built from input", "A request value is used as a file path or include target, which allows reading arbitrary files or running attacker code. Allow-list the names.",
       exclude=r"basename|realpath|in_array"),
    _r("PATH_TRAVERSAL", "HIGH", "CWE-22", "java",
       rf"new\s+(?:File|FileInputStream|FileReader|FileOutputStream)\s*\(.*(?:{JAVA_INPUT})|Paths\.get\s*\(.*(?:{JAVA_INPUT})",
       "File path built from input", "A request value is used in a file path. Normalise it and check it stays inside the base directory.",
       exclude=r"getFileName|normalize"),
    _r("PATH_TRAVERSAL", "HIGH", "CWE-22", "go",
       rf"(?:os\.(?:Open|OpenFile|ReadFile|Remove)|ioutil\.ReadFile|http\.ServeFile)\s*\(.*(?:{GO_INPUT})",
       "File path built from input", "A request value is used in a file path. Clean it and check the prefix of the resolved path.",
       exclude=r"filepath\.Base|filepath\.Clean"),
    _r("PATH_TRAVERSAL", "HIGH", "CWE-22", "ruby",
       rf"(?:File\.(?:read|open|join|delete)|send_file|IO\.read)\s*\(?.*(?:{RUBY_INPUT})",
       "File path built from input", "A request value is used in a file path. Use File.basename or check the expanded path's prefix.",
       exclude=r"basename|expand_path"),
    _r("PATH_TRAVERSAL", "HIGH", "CWE-22", "csharp",
       rf"(?:File\.(?:ReadAllText|ReadAllBytes|OpenRead|Delete)|Path\.Combine|PhysicalFile)\s*\(.*(?:{CS_INPUT})",
       "File path built from input", "A request value is used in a file path. Use Path.GetFileName or check the full path's prefix.",
       exclude=r"GetFileName|GetFullPath"),
    _r("SSRF", "HIGH", "CWE-918", "javascript",
       rf"\b(?:fetch|axios(?:\.(?:get|post|put|request))?|got|request|http\.get|https\.get|needle\.get)\s*\(\s*(?:`[^`]*\$\{{[^`]*(?:{JS_INPUT})|(?:{JS_INPUT}))",
       "Server fetches a URL taken from the request", "An attacker can point the server at internal services or cloud metadata endpoints (server-side request forgery). Allow-list hosts and block private addresses."),
    _r("SSRF", "HIGH", "CWE-918", "php",
       rf"(?:file_get_contents|curl_setopt\s*\(\s*\$\w+\s*,\s*CURLOPT_URL|fopen)\s*\(?[^;]*(?:{PHP_INPUT})",
       "Server fetches a URL taken from the request", "An attacker can point the server at internal services (server-side request forgery). Allow-list hosts."),
    _r("SSRF", "HIGH", "CWE-918", "java",
       rf"new\s+URL\s*\(.*(?:{JAVA_INPUT})|HttpRequest\.newBuilder\s*\(\s*URI\.create\s*\(.*(?:{JAVA_INPUT})|restTemplate\.\w+\s*\(.*(?:{JAVA_INPUT})",
       "Server fetches a URL taken from the request", "An attacker can point the server at internal services (server-side request forgery). Allow-list hosts."),
    _r("SSRF", "HIGH", "CWE-918", "go",
       rf"http\.(?:Get|Post|NewRequest)\s*\(.*(?:{GO_INPUT})",
       "Server fetches a URL taken from the request", "An attacker can point the server at internal services (server-side request forgery). Allow-list hosts."),
    _r("SSRF", "HIGH", "CWE-918", "ruby",
       rf"(?:Net::HTTP\.(?:get|get_response|start)|URI\.open|open-uri|HTTParty\.\w+|Faraday\.\w+|RestClient\.\w+)\s*\(?.*(?:{RUBY_INPUT})",
       "Server fetches a URL taken from the request", "An attacker can point the server at internal services (server-side request forgery). Allow-list hosts."),
    _r("OPEN_REDIRECT", "MEDIUM", "CWE-601", "javascript",
       rf"(?:res\.redirect|window\.location(?:\.href)?\s*=|location\.(?:href|assign|replace)\s*[=(])\s*\(?\s*(?:{JS_INPUT})",
       "Redirect to a URL taken from the request", "An attacker can send victims to a look-alike site through your domain. Redirect only to relative paths or an allow-list."),
    _r("OPEN_REDIRECT", "MEDIUM", "CWE-601", "php",
       rf"header\s*\(\s*[\"']Location:\s*[\"']?\s*\.?\s*{PHP_INPUT}",
       "Redirect to a URL taken from the request", "An attacker can send victims to a look-alike site through your domain."),
    _r("OPEN_REDIRECT", "MEDIUM", "CWE-601", "java",
       rf"sendRedirect\s*\(.*(?:{JAVA_INPUT})|new\s+RedirectView\s*\(.*(?:{JAVA_INPUT})",
       "Redirect to a URL taken from the request", "An attacker can send victims to a look-alike site through your domain."),
    _r("OPEN_REDIRECT", "MEDIUM", "CWE-601", "ruby",
       rf"redirect_to\s+(?:params|request\.referer)",
       "Redirect to a URL taken from the request", "An attacker can send victims to a look-alike site through your domain."),
    # ---- unsafe data handling ----
    _r("INSECURE_DESERIALIZATION", "HIGH", "CWE-502", "php",
       rf"\bunserialize\s*\(\s*(?:{PHP_INPUT}|\$)",
       "Untrusted data is unserialized", "Unserializing attacker-controlled data can run code through object gadgets. Use json_decode."),
    _r("INSECURE_DESERIALIZATION", "HIGH", "CWE-502", "java",
       r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)|XMLDecoder\s*\(|enableDefaultTyping|SnakeYAML|new\s+Yaml\s*\(\s*\)(?!.*SafeConstructor)",
       "Untrusted data is deserialized", "Java deserialization of attacker data can run code. Use a data format such as JSON with a strict schema."),
    _r("INSECURE_DESERIALIZATION", "HIGH", "CWE-502", "ruby",
       r"\bMarshal\.load\s*\(|\bYAML\.load\s*\((?!.*safe)|\bOj\.load\s*\(",
       "Untrusted data is deserialized", "Marshal and YAML.load can build arbitrary objects and run code. Use YAML.safe_load or JSON."),
    _r("INSECURE_DESERIALIZATION", "HIGH", "CWE-502", "csharp",
       r"BinaryFormatter|NetDataContractSerializer|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)|LosFormatter|SoapFormatter",
       "Untrusted data is deserialized", "These formatters can instantiate attacker-chosen types and run code. Use System.Text.Json."),
    _r("INSECURE_DESERIALIZATION", "HIGH", "CWE-502", "javascript",
       r"require\s*\(\s*[\"']node-serialize[\"']\s*\)|\bserialize\.unserialize\s*\(|yaml\.load\s*\((?!.*safe)",
       "Untrusted data is deserialized", "Unserializing attacker data can run code. Use JSON.parse or a safe loader."),
    # ---- crypto / transport / secrets ----
    _r("WEAK_CRYPTO", "MEDIUM", "CWE-328", "javascript",
       r"createHash\s*\(\s*[\"'](?:md5|sha1)[\"']\s*\)|\bmd5\s*\(|\bsha1\s*\(",
       "Fast, broken hash", "MD5 and SHA-1 can be brute-forced quickly, so leaked hashes give up passwords. Use bcrypt, scrypt or Argon2 for passwords."),
    _r("WEAK_CRYPTO", "MEDIUM", "CWE-328", "php",
       r"\b(?:md5|sha1|crypt)\s*\(\s*\$\w*(?:pass|pwd|secret)|password_hash\s*\([^)]*PASSWORD_(?:DEFAULT)?\s*,\s*\[[^\]]*cost\"?\s*=>\s*[0-9]\b",
       "Fast, broken hash for passwords", "MD5 and SHA-1 can be brute-forced quickly. Use password_hash() with the default algorithm."),
    _r("WEAK_CRYPTO", "MEDIUM", "CWE-328", "java",
       r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"|Cipher\.getInstance\s*\(\s*\"(?:DES|RC4|AES/ECB[^\"]*|AES)\"",
       "Weak hash or cipher", "MD5, SHA-1, DES and ECB mode are broken or leak patterns. Use SHA-256+, bcrypt for passwords, and AES-GCM."),
    _r("WEAK_CRYPTO", "MEDIUM", "CWE-328", "go",
       r"\bmd5\.(?:New|Sum)\b|\bsha1\.(?:New|Sum)\b|\"crypto/(?:md5|sha1|des|rc4)\"",
       "Weak hash or cipher", "MD5, SHA-1, DES and RC4 are broken. Use SHA-256+, and bcrypt/argon2 for passwords."),
    _r("WEAK_CRYPTO", "MEDIUM", "CWE-328", "ruby",
       r"Digest::(?:MD5|SHA1)\b|OpenSSL::Cipher.*(?:DES|RC4|ECB)",
       "Weak hash or cipher", "MD5 and SHA-1 can be brute-forced quickly. Use bcrypt for passwords."),
    _r("WEAK_CRYPTO", "MEDIUM", "CWE-328", "csharp",
       r"MD5\.Create\s*\(|SHA1\.Create\s*\(|new\s+(?:MD5|SHA1)CryptoServiceProvider|DESCryptoServiceProvider|CipherMode\.ECB",
       "Weak hash or cipher", "MD5, SHA-1, DES and ECB mode are broken. Use SHA-256+, PBKDF2/bcrypt for passwords, and AES-GCM."),
    _r("TLS_VERIFY_DISABLED", "MEDIUM", "CWE-295", "javascript",
       r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*[\"']?0|strictSSL\s*:\s*false|verify\s*:\s*false",
       "TLS certificate checks turned off", "Accepting any certificate lets anyone on the network path read or change the traffic."),
    _r("TLS_VERIFY_DISABLED", "MEDIUM", "CWE-295", "php",
       r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)|[\"']verify_peer[\"']\s*=>\s*false|[\"']verify[\"']\s*=>\s*false",
       "TLS certificate checks turned off", "Accepting any certificate lets anyone on the network path read or change the traffic."),
    _r("TLS_VERIFY_DISABLED", "MEDIUM", "CWE-295", "java",
       r"setHostnameVerifier\s*\(|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts|X509TrustManager\s*\(\s*\)\s*\{|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|NoopHostnameVerifier",
       "TLS certificate checks turned off", "A trust-everything manager or hostname verifier lets anyone on the network path read or change the traffic."),
    _r("TLS_VERIFY_DISABLED", "MEDIUM", "CWE-295", "go",
       r"InsecureSkipVerify\s*:\s*true",
       "TLS certificate checks turned off", "Accepting any certificate lets anyone on the network path read or change the traffic."),
    _r("TLS_VERIFY_DISABLED", "MEDIUM", "CWE-295", "ruby",
       r"VERIFY_NONE|verify_ssl\s*[:=]\s*false|ssl_verify_peer\s*[:=]\s*false",
       "TLS certificate checks turned off", "Accepting any certificate lets anyone on the network path read or change the traffic."),
    _r("TLS_VERIFY_DISABLED", "MEDIUM", "CWE-295", "csharp",
       r"ServerCertificateValidationCallback\s*[+=]|ServerCertificateCustomValidationCallback\s*=\s*\(?[^;]*true|DangerousAcceptAnyServerCertificateValidator",
       "TLS certificate checks turned off", "Accepting any certificate lets anyone on the network path read or change the traffic."),
    _r("INSECURE_JWT", "HIGH", "CWE-347", "javascript",
       r"jwt\.decode\s*\(|algorithms\s*:\s*\[[^\]]*[\"']none[\"']|ignoreExpiration\s*:\s*true|algorithm\s*:\s*[\"']none[\"']",
       "JWT accepted without a valid signature", "jwt.decode() does not verify the signature, and 'none' or ignoreExpiration let forged or expired tokens through. Use jwt.verify with a fixed algorithm."),
    _r("INSECURE_JWT", "HIGH", "CWE-347", "php java go ruby csharp",
       r"(?i)alg[\"']?\s*[:=]\s*[\"']none[\"']|SignatureAlgorithm\.NONE|ValidateIssuerSigningKey\s*=\s*false|RequireSignedTokens\s*=\s*false|verify\s*=\s*false.*jwt|JWT\.decode\([^)]*false",
       "JWT accepted without a valid signature", "Tokens are trusted without checking who signed them, so anyone can forge one."),
    _r("DEBUG_MODE", "MEDIUM", "CWE-489", "javascript",
       r"app\.use\s*\(\s*errorhandler\s*\(\s*\)\s*\)|debug\s*:\s*true",
       "Debug features enabled", "Debug output and error pages leak stack traces and internals to attackers."),
    _r("DEBUG_MODE", "MEDIUM", "CWE-489", "php",
       r"display_errors[\"']?\s*[,=]\s*[\"']?(?:1|on|true)|var_dump\s*\(\s*\$_|^\s*phpinfo\s*\(\s*\)\s*;",
       "Debug features enabled", "Showing errors or phpinfo() leaks paths, versions and configuration."),
    _r("DEBUG_MODE", "MEDIUM", "CWE-489", "java ruby csharp",
       r"\.printStackTrace\s*\(\s*\)|spring\.devtools|config\.consider_all_requests_local\s*=\s*true|UseDeveloperExceptionPage|customErrors\s+mode=[\"']Off|<compilation[^>]*debug=[\"']true",
       "Debug features enabled", "Stack traces and developer pages leak internals to attackers."),
    _r("MISSING_AUTHENTICATION", "MEDIUM", "CWE-306", "javascript",
       r"cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|[\"']\*[\"'])[^}]*credentials\s*:\s*true|Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*[\"']",
       "Wildcard cross-origin access", "Allowing every origin (especially with credentials) lets any website call this API as the signed-in user."),
    _r("CSRF", "MEDIUM", "CWE-352", "php java ruby csharp",
       r"protect_from_forgery\s+with:\s*:null_session|skip_before_action\s*:verify_authenticity_token|csrf\(\)\.disable\(\)|\[IgnoreAntiforgeryToken\]|csrf\.disable\(",
       "CSRF protection turned off", "Without CSRF tokens any website can make a signed-in user's browser change data."),
    _r("MASS_ASSIGNMENT", "MEDIUM", "CWE-915", "ruby",
       r"\.permit!|attr_accessible\s+:?\w+.*:?admin|\.update(?:_attributes)?\s*\(\s*params\s*\)|\.permit\([^)]*:(?:admin|role|is_admin)\b",
       "Mass assignment", "Whole request parameters are written into the model, so attackers can set fields such as role or admin."),
]

PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")
CLOUD_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{35}\b|\bgh[pousr]_[0-9A-Za-z]{36,}\b|\bxox[baprs]-[0-9A-Za-z-]{10,}\b|\bsk_live_[0-9a-zA-Z]{20,}\b")
SECRET_ASSIGN = re.compile(
    rf"(?i)(?P<name>[\"']?[\w.-]*{SECRET_NAME}[\w.-]*[\"']?)\s*(?::=|=>|=|:)\s*[\"'`](?P<value>[^\"'`\s]{{8,}})[\"'`]")
NOT_SECRET_NAME = re.compile(r"(?i)(url|uri|endpoint|header|field|name|type|label|path|file|len|length|prompt|example|format|pattern|regex|_id$|^id$|env|message|msg|error|hint|placeholder|text|title|description|key_?name|min|max|required|class|placeholder)")

COMMENT_PREFIXES = {
    "javascript": ("//", "*", "/*"), "java": ("//", "*", "/*"), "go": ("//", "*", "/*"), "csharp": ("//", "*", "/*"),
    "php": ("//", "#", "*", "/*"), "ruby": ("#",), "shell": ("#",), "rust": ("//", "*", "/*"), "c": ("//", "*", "/*"), "html": ("<!--",),
}
CODE_LANGS = {lang for rule in RULES for lang in rule.langs} | {"shell"}


TRAILING_OPERATORS = ("+", ",", "(", "[", "{", ".", "\\", "&&", "||", "?", ":", "=", ">", "-", "*", "|", "&")


def statement_span(lines: list[str], start: int, cap: int = 15) -> int:
    """Last line (1-based) of the statement that begins on `start`, for languages without a syntax tree here: it
    continues while brackets or a `template literal` are open, or the line ends with an operator, so a query or
    template spread over several lines is one finding. Quotes inside ordinary string literals are ignored."""
    depth, end, in_template = 0, start, False
    for number in range(start, min(len(lines), start + cap - 1) + 1):
        line = lines[number - 1]
        if line.replace("\\`", "").count("`") % 2:
            in_template = not in_template
        stripped = re.sub(r"`[^`]*`|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", "", line)
        stripped = re.sub(r"//.*$|#.*$", "", stripped)
        depth += sum(stripped.count(c) for c in "([{") - sum(stripped.count(c) for c in ")]}")
        end = number
        tail = stripped.rstrip()
        if in_template:
            continue
        if depth <= 0 and not (tail.endswith(TRAILING_OPERATORS) and not tail.endswith(("++", "--"))):
            break
    return end


DYNAMIC_HTML_SINK = re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=")
SANITIZED = re.compile(r"DOMPurify|sanitize|escapeHtml|escape\(|encodeURI|textContent", re.I)


def _dynamic_html(lines: list[str], number: int) -> bool:
    """An innerHTML/outerHTML assignment whose value is built from something dynamic (template ${...} or + concatenation),
    judged on the whole statement so a template literal spread over several lines is seen too."""
    end = statement_span(lines, number, cap=60)
    text = " ".join(lines[number - 1 : end])
    if SANITIZED.search(text):
        return False
    value = DYNAMIC_HTML_SINK.split(text, 1)[-1]
    without_literals = re.sub(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", "''", value)
    return "${" in value or bool(re.search(r"\+\s*[A-Za-z_$(]", without_literals)) or bool(re.search(r"\.map\s*\(", value))


def _skip_line(line: str, lang: str) -> bool:
    s = line.strip()
    return not s or s.startswith(COMMENT_PREFIXES.get(lang, ())) or len(s) > 2000  # long lines are minified or data


def _secret_hits(line: str) -> list[tuple[str, str]]:
    out = []
    if PRIVATE_KEY.search(line):
        out.append(("a private key", "A private key is committed to source. Anyone with the code has it; rotate it and load it from a secret store."))
    if CLOUD_KEY.search(line):
        out.append(("a cloud or API token", "A provider access token is committed to source. Anyone with the code has it; revoke it and load it from the environment."))
    for m in SECRET_ASSIGN.finditer(line):
        value = m.group("value")
        name = m.group("name").strip("\"'")
        if (NOT_SECRET_NAME.search(name) and not re.search(r"(?i)passw|secret|token|key|credential", name)) or PLACEHOLDER.match(value) or " " in value:
            continue
        if re.search(r"[$#]\{|^\$|%[sd]|\{\{", value) or re.fullmatch(r"[a-z_/]+#[a-z_]+", value):
            continue  # an interpolated variable, or a Rails route target such as "password_resets#create"
        if re.search(r"(?i)(env|getenv|config|process\.env|System\.getProperty)", line[: m.start()] + line[m.end():]) and "=" not in value:
            continue
        out.append((f"'{name}'", "A credential is committed to source. Anyone with the code has it, it ends up in every copy and backup, and rotating it needs a code change. Load it from the environment."))
    return out


def scan_source(source: str, lang: str) -> list[tuple[str, str, str, Hit]]:
    """[(type, severity, cwe, Hit)] for one non-Python file, one hit per matching line and rule."""
    out: list[tuple[str, str, str, Hit]] = []
    seen: dict[str, int] = {}
    in_block = False
    in_php = False
    all_lines = source.splitlines()
    for number, line in enumerate(all_lines, 1):
        if lang == "php":
            # PHP files mix code and HTML prose: only lines inside <?php ... ?> are code.
            opened = line.rfind("<?")
            closed = line.rfind("?>")
            was_php = in_php or opened != -1
            if opened != -1 or closed != -1:
                in_php = opened > closed
            if not was_php:
                continue
        stripped = line.strip()
        if lang in COMMENT_PREFIXES and "/*" in COMMENT_PREFIXES[lang]:
            if in_block:
                in_block = "*/" not in line
                continue
            if stripped.startswith("/*") and "*/" not in stripped:
                in_block = True
                continue
        if _skip_line(line, lang):
            continue

        def add(vtype: str, severity: str, cwe: str, title: str, rationale: str) -> None:
            key = f"{vtype}|{stripped[:160]}"
            seen[key] = seen.get(key, 0) + 1
            anchor = f"{lang}|{key}#{seen[key]}"
            out.append((vtype, severity, cwe, Hit(number, number, title, rationale, anchor)))

        bare = QUOTED.sub("''", line)
        for rule in RULES:
            if lang in rule.langs and rule.pattern.search(bare if rule.unquoted else line) and not (rule.exclude and rule.exclude.search(line)):
                add(rule.vtype, rule.severity, rule.cwe, f"{rule.title} ({LANG_LABEL.get(lang, lang)})", rule.rationale)
        if lang in ("javascript", "html") and DYNAMIC_HTML_SINK.search(line) and not any(o[3].start == number and o[0] == "XSS" for o in out) \
                and _dynamic_html(all_lines, number):
            add("XSS", "HIGH", "CWE-79", f"HTML built from dynamic data ({LANG_LABEL.get(lang, lang)})",
                "Dynamic data is written into the page as HTML, so an attacker's markup or script runs in other users' browsers. Use textContent, or sanitise with a library such as DOMPurify.")
        for what, why in _secret_hits(line):
            add("HARDCODED_CREDENTIALS", "MEDIUM", "CWE-798", f"Hardcoded secret: {what}", why)
    return out
