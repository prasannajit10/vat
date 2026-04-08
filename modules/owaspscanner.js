/* ============================================
   NexPent — OWASP Top 10:2025 Scanner Module
   Simulates comprehensive OWASP Top 10:2025 checks
   ============================================ */

const OwaspScannerModule = (() => {
    "use strict";

    // ── OWASP Top 10:2025 Check Definitions ──
    const owaspChecks = [
        {
            id: "A01",
            name: "Broken Access Control",
            icon: "fa-lock-open",
            checks: [
                { name: "Directory Traversal", test: "path-traversal", severity: "critical", desc: "Checks for path traversal vulnerabilities (e.g., ../../etc/passwd)" },
                { name: "Forced Browsing", test: "forced-browsing", severity: "high", desc: "Attempts to access restricted paths (/admin, /config, /backup)" },
                { name: "IDOR Detection", test: "idor", severity: "critical", desc: "Tests for Insecure Direct Object Reference in API endpoints" },
                { name: "CORS Misconfiguration", test: "cors", severity: "high", desc: "Checks Access-Control-Allow-Origin header for wildcard misconfiguration" },
                { name: "HTTP Method Tampering", test: "method-tampering", severity: "medium", desc: "Tests if PUT/DELETE methods are enabled without authorization" },
                { name: "SSRF — URL Parameter", test: "url-param", severity: "critical", desc: "Tests URL params for SSRF to internal services (merged from 2021 A10)" },
                { name: "SSRF — Open Redirect", test: "open-redirect", severity: "high", desc: "Checks for open redirect vulnerabilities allowing SSRF pivoting" },
                { name: "SSRF — Cloud Metadata", test: "cloud-metadata", severity: "critical", desc: "Checks for access to cloud metadata endpoints (169.254.169.254)" },
            ]
        },
        {
            id: "A02",
            name: "Security Misconfiguration",
            icon: "fa-sliders",
            checks: [
                { name: "Server Header Exposure", test: "server-header", severity: "medium", desc: "Checks if Server/X-Powered-By headers expose technology stack" },
                { name: "Directory Listing", test: "dir-listing", severity: "high", desc: "Tests if directory listing is enabled on web server" },
                { name: "Debug / Stack Traces", test: "debug-mode", severity: "high", desc: "Checks for verbose error messages or debug mode enabled" },
                { name: "Default Credentials", test: "default-creds", severity: "critical", desc: "Tests for common default credentials on admin panels" },
                { name: "Security Headers Check", test: "security-headers", severity: "medium", desc: "Validates X-Frame-Options, X-Content-Type-Options, CSP headers" },
                { name: "Cloud Misconfiguration", test: "cloud-misconfig", severity: "critical", desc: "Checks for overly permissive cloud storage (S3, Azure Blob) policies" },
            ]
        },
        {
            id: "A03",
            name: "Software Supply Chain Failures",
            icon: "fa-link-slash",
            checks: [
                { name: "JavaScript Library Scan", test: "js-libraries", severity: "high", desc: "Detects known vulnerable JavaScript libraries (jQuery, Angular, etc.)" },
                { name: "Server Version Detection", test: "server-version", severity: "medium", desc: "Identifies server software and version for CVE lookup" },
                { name: "CMS Detection", test: "cms-detect", severity: "medium", desc: "Identifies CMS platform and version (WordPress, Drupal, etc.)" },
                { name: "Outdated Framework", test: "framework-version", severity: "high", desc: "Checks for outdated web frameworks with known vulnerabilities" },
                { name: "Dependency Confusion", test: "dep-confusion", severity: "critical", desc: "Tests for dependency confusion / typosquatting attack vectors" },
                { name: "SBOM / Manifest Exposure", test: "sbom-check", severity: "medium", desc: "Checks for exposed package.json, requirements.txt, composer.json" },
            ]
        },
        {
            id: "A04",
            name: "Cryptographic Failures",
            icon: "fa-key",
            checks: [
                { name: "HTTPS Enforcement", test: "https-check", severity: "critical", desc: "Verifies if site enforces HTTPS connections" },
                { name: "HSTS Header", test: "hsts", severity: "high", desc: "Checks for Strict-Transport-Security header" },
                { name: "Weak TLS Detection", test: "weak-tls", severity: "high", desc: "Checks for outdated TLS versions (TLS 1.0/1.1)" },
                { name: "Sensitive Data in URL", test: "data-in-url", severity: "medium", desc: "Checks if sensitive parameters are passed in URL query strings" },
                { name: "Cookie Security Flags", test: "cookie-flags", severity: "high", desc: "Checks for Secure and HttpOnly flags on cookies" },
            ]
        },
        {
            id: "A05",
            name: "Injection",
            icon: "fa-syringe",
            checks: [
                { name: "SQL Injection Probe", test: "sqli-probe", severity: "critical", desc: "Tests for SQL error messages in response to injection payloads" },
                { name: "XSS Reflection Test", test: "xss-reflection", severity: "high", desc: "Checks if input is reflected without sanitization" },
                { name: "Command Injection", test: "cmd-injection", severity: "critical", desc: "Tests for OS command injection via special characters" },
                { name: "LDAP Injection", test: "ldap-injection", severity: "high", desc: "Tests for LDAP injection in login/search forms" },
                { name: "Template Injection", test: "ssti", severity: "critical", desc: "Checks for server-side template injection (SSTI)" },
            ]
        },
        {
            id: "A06",
            name: "Insecure Design",
            icon: "fa-drafting-compass",
            checks: [
                { name: "Rate Limiting", test: "rate-limit", severity: "high", desc: "Checks if API endpoints have rate limiting protections" },
                { name: "CAPTCHA Presence", test: "captcha", severity: "medium", desc: "Checks for CAPTCHA on login and registration forms" },
                { name: "Password Policy", test: "password-policy", severity: "high", desc: "Evaluates password complexity requirements" },
                { name: "Account Enumeration", test: "account-enum", severity: "medium", desc: "Tests if error messages reveal valid usernames" },
                { name: "Business Logic Flaws", test: "business-logic", severity: "high", desc: "Tests for client-side price/quantity manipulation in checkout flows" },
            ]
        },
        {
            id: "A07",
            name: "Authentication Failures",
            icon: "fa-user-lock",
            checks: [
                { name: "Brute Force Resistance", test: "brute-force", severity: "critical", desc: "Tests if login form is protected against brute force attacks" },
                { name: "Session Fixation", test: "session-fixation", severity: "high", desc: "Checks if session ID changes after authentication" },
                { name: "MFA Detection", test: "mfa-check", severity: "high", desc: "Verifies multi-factor authentication implementation" },
                { name: "Password Reset Flow", test: "password-reset", severity: "medium", desc: "Tests password reset mechanism for security weaknesses" },
                { name: "Session Timeout", test: "session-timeout", severity: "medium", desc: "Checks for proper session timeout configuration" },
            ]
        },
        {
            id: "A08",
            name: "Software & Data Integrity Failures",
            icon: "fa-file-shield",
            checks: [
                { name: "Subresource Integrity", test: "sri-check", severity: "high", desc: "Checks if external scripts use Subresource Integrity (SRI)" },
                { name: "Content Security Policy", test: "csp-check", severity: "high", desc: "Validates Content-Security-Policy header configuration" },
                { name: "Unsafe Deserialization", test: "deserialization", severity: "critical", desc: "Tests for unsafe deserialization endpoints" },
                { name: "Update Mechanism", test: "update-check", severity: "medium", desc: "Checks if auto-update mechanisms verify integrity" },
            ]
        },
        {
            id: "A09",
            name: "Security Logging & Alerting Failures",
            icon: "fa-bell-slash",
            checks: [
                { name: "Error Log Exposure", test: "error-log", severity: "medium", desc: "Checks if error logs are publicly accessible" },
                { name: "Access Log Exposure", test: "access-log", severity: "medium", desc: "Tests for exposed access logs on common paths" },
                { name: "WAF Detection", test: "waf-detect", severity: "low", desc: "Identifies presence of Web Application Firewall" },
                { name: "Alerting Headers", test: "sec-event-headers", severity: "medium", desc: "Checks for Report-To and NEL headers for real-time alerting" },
            ]
        },
        {
            id: "A10",
            name: "Mishandling of Exceptional Conditions",
            icon: "fa-burst",
            checks: [
                { name: "Stack Trace Exposure", test: "stack-trace", severity: "high", desc: "Sends malformed requests to trigger unhandled exceptions with stack traces" },
                { name: "Resource Exhaustion", test: "resource-exhaustion", severity: "high", desc: "Tests if oversized inputs cause application crashes or DoS" },
                { name: "Null / Edge Input Handling", test: "null-input", severity: "medium", desc: "Tests null, empty, and boundary values for improper exception handling" },
                { name: "Error Response Consistency", test: "error-consistency", severity: "low", desc: "Checks if error responses are consistent and leak no internal info" },
                { name: "Circuit Breaker / Timeout", test: "circuit-breaker", severity: "medium", desc: "Tests if app gracefully degrades on downstream service failures" },
            ]
        }
    ];

    // ── Simulated Check Results ──
    function simulateCheck(check, targetUrl) {
        const url = targetUrl.toLowerCase();
        const isHTTPS = url.startsWith("https://");
        const domain = url.replace(/https?:\/\//, "").split("/")[0];

        const detectionRates = {
            // A01 — Broken Access Control (incl. SSRF)
            "path-traversal": 0.25,
            "forced-browsing": 0.40,
            "idor": 0.30,
            "cors": 0.50,
            "method-tampering": 0.35,
            "url-param": 0.20,
            "open-redirect": 0.35,
            "cloud-metadata": 0.08,
            // A02 — Security Misconfiguration
            "server-header": 0.70,
            "dir-listing": 0.30,
            "debug-mode": 0.25,
            "default-creds": 0.15,
            "security-headers": 0.60,
            "cloud-misconfig": 0.20,
            // A03 — Software Supply Chain Failures
            "js-libraries": 0.55,
            "server-version": 0.65,
            "cms-detect": 0.40,
            "framework-version": 0.35,
            "dep-confusion": 0.12,
            "sbom-check": 0.45,
            // A04 — Cryptographic Failures
            "https-check": isHTTPS ? 0.05 : 0.95,
            "hsts": 0.55,
            "weak-tls": 0.30,
            "data-in-url": url.includes("?") ? 0.60 : 0.10,
            "cookie-flags": 0.45,
            // A05 — Injection
            "sqli-probe": 0.35,
            "xss-reflection": 0.40,
            "cmd-injection": 0.15,
            "ldap-injection": 0.10,
            "ssti": 0.12,
            // A06 — Insecure Design
            "rate-limit": 0.50,
            "captcha": 0.45,
            "password-policy": 0.35,
            "account-enum": 0.40,
            "business-logic": 0.30,
            // A07 — Authentication Failures
            "brute-force": 0.40,
            "session-fixation": 0.25,
            "mfa-check": 0.55,
            "password-reset": 0.30,
            "session-timeout": 0.35,
            // A08 — Software & Data Integrity Failures
            "sri-check": 0.60,
            "csp-check": 0.55,
            "deserialization": 0.10,
            "update-check": 0.20,
            // A09 — Security Logging & Alerting Failures
            "error-log": 0.25,
            "access-log": 0.20,
            "waf-detect": 0.35,
            "sec-event-headers": 0.65,
            // A10 — Mishandling of Exceptional Conditions
            "stack-trace": 0.30,
            "resource-exhaustion": 0.20,
            "null-input": 0.35,
            "error-consistency": 0.40,
            "circuit-breaker": 0.25,
        };

        const rate = detectionRates[check.test] || 0.30;
        if (Math.random() >= rate) return null;

        const evidenceMap = {
            // A01
            "path-traversal": `Path traversal successful: /../../../etc/passwd returned system user list.`,
            "forced-browsing": `Restricted path /admin/dashboard accessible without authentication.`,
            "idor": `Changing user_id from 1001 to 1002 returns a different user's profile data.`,
            "cors": `Access-Control-Allow-Origin: * — any origin can make authenticated requests.`,
            "method-tampering": `PUT/DELETE accepted on ${domain}/api/users without authorization checks.`,
            "url-param": `URL param "redirect_url" accepts internal URLs: http://localhost:8080/admin`,
            "open-redirect": `Open redirect via /redirect?url=https://evil.com — phishing/SSRF vector.`,
            "cloud-metadata": `SSRF to http://169.254.169.254/latest/meta-data/ returns EC2 IAM credentials.`,
            // A02
            "server-header": `Server: Apache/2.4.41 (Ubuntu) — exposes target for CVE-specific attacks.`,
            "dir-listing": `Directory listing enabled at ${url}/assets/ — internal structure exposed.`,
            "debug-mode": `Stack trace in 500 response: /var/www/app/controllers/UserController.py:42`,
            "default-creds": `Default credentials admin:admin accepted on ${domain}/admin panel.`,
            "security-headers": `Missing: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy.`,
            "cloud-misconfig": `S3 bucket ${domain}-backup publicly readable — sensitive files accessible.`,
            // A03
            "js-libraries": `jQuery 2.1.4 detected (CVE-2020-11022/23) — XSS via .html() method.`,
            "server-version": `nginx/1.14.0 — CVE-2019-9511 HTTP/2 DoS vulnerability applies.`,
            "cms-detect": `WordPress 5.2.1 via /wp-login.php — multiple critical CVEs active.`,
            "framework-version": `X-Powered-By: Express 4.16.0 — prototype pollution vulnerability present.`,
            "dep-confusion": `Public package "companyutils" found on npm — dependency confusion risk.`,
            "sbom-check": `package.json exposed at ${domain}/package.json — full dependency list public.`,
            // A04
            "https-check": `${domain} does not enforce HTTPS — data transmitted in cleartext.`,
            "hsts": `Missing Strict-Transport-Security header — SSL stripping attack possible.`,
            "weak-tls": `Server accepts TLS 1.0/1.1 — vulnerable to BEAST and POODLE attacks.`,
            "data-in-url": `Sensitive params detected in URL: ${url.split("?")[1] || "token=xxx&session=yyy"}`,
            "cookie-flags": `Session cookie missing 'Secure' and 'HttpOnly' flags — XSS/MITM exposure.`,
            // A05
            "sqli-probe": `SQL error: "You have an error in your SQL syntax near '\\'' at line 1"`,
            "xss-reflection": `Input <script>alert(1)</script> reflected unencoded in response body.`,
            "cmd-injection": `"; ls -la" injected — OS file listing returned in response (RCE confirmed).`,
            "ldap-injection": `LDAP filter "(uid=*)" returns all user records — injection confirmed.`,
            "ssti": `{{7*7}} returned 49 in response — Server-Side Template Injection confirmed.`,
            // A06
            "rate-limit": `1,000 requests in 10 seconds with no throttling — no rate limiting present.`,
            "captcha": `Login form at ${domain}/login has no CAPTCHA or bot protection.`,
            "password-policy": `Password "123456" accepted — no complexity requirements enforced.`,
            "account-enum": `"Password incorrect for admin" vs "User not found" — username enumeration enabled.`,
            "business-logic": `POST /checkout accepted {"price":0.01,"qty":999} — server trusts client price.`,
            // A07
            "brute-force": `No lockout after 50 failed login attempts — brute force attack feasible.`,
            "session-fixation": `Session ID unchanged after login — session fixation attack possible.`,
            "mfa-check": `No MFA option available on ${domain} — single-factor authentication only.`,
            "password-reset": `Reset token is MD5(email + timestamp) — predictable and guessable.`,
            "session-timeout": `Session remains valid after 24 hours of inactivity — no idle timeout.`,
            // A08
            "sri-check": `<script src="https://cdn.example.com/lib.js"> — no integrity attribute set.`,
            "csp-check": `No Content-Security-Policy header — unrestricted script sources permitted.`,
            "deserialization": `/api/import accepts Java serialized objects — potential RCE via gadget chains.`,
            "update-check": `Auto-update fetches packages over HTTP without signature verification.`,
            // A09
            "error-log": `Error log at ${domain}/logs/error.log — stack traces and paths exposed.`,
            "access-log": `Access log at ${domain}/logs/access.log — user IPs and patterns exposed.`,
            "waf-detect": `No WAF detected — malicious payloads reach the backend unfiltered.`,
            "sec-event-headers": `Missing Report-To and NEL headers — no real-time security alerting.`,
            // A10
            "stack-trace": `Malformed JSON body triggers full Java stack trace with internal class paths.`,
            "resource-exhaustion": `100MB request body causes 503 Service Unavailable — no size limit enforced.`,
            "null-input": `Null character in username field triggers 500 error with internal stack trace.`,
            "error-consistency": `"Invalid password" vs "User does not exist" — inconsistent errors aid enumeration.`,
            "circuit-breaker": `DB timeout not handled — entire app hangs for 30s on downstream failure.`,
        };

        return {
            name: check.name,
            severity: check.severity,
            evidence: evidenceMap[check.test] || `Potential ${check.name} vulnerability detected.`,
            remediation: getRemediation(check.test),
        };
    }

    function getRemediation(testType) {
        const remediations = {
            // A01
            "path-traversal": "Validate and canonicalize file paths. Use an allowlist of permitted locations.",
            "forced-browsing": "Enforce server-side access control on every request. Deny by default.",
            "idor": "Implement authorization checks for every object access. Map IDs to sessions server-side.",
            "cors": "Set Access-Control-Allow-Origin to specific trusted domains only. Never use '*' with credentials.",
            "method-tampering": "Restrict HTTP methods to only those needed. Enforce authorization on all methods.",
            "url-param": "Validate all URL parameters against an allowlist. Block private/cloud IP ranges.",
            "open-redirect": "Validate redirect URLs against an allowlist. Reject user-controlled redirect destinations.",
            "cloud-metadata": "Block requests to 169.254.169.254. Use IMDSv2 with session-oriented tokens on AWS.",
            // A02
            "server-header": "Remove or obfuscate Server and X-Powered-By response headers in production.",
            "dir-listing": "Disable directory listing in web server config (Options -Indexes in Apache).",
            "debug-mode": "Disable debug mode in production. Return generic custom error pages only.",
            "default-creds": "Force password change on first login. Remove all default accounts before production.",
            "security-headers": "Add X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and a strict CSP policy.",
            "cloud-misconfig": "Apply least-privilege ACLs on cloud storage. Enable public access block policies.",
            // A03
            "js-libraries": "Update all client-side libraries to latest versions. Use npm audit or Snyk regularly.",
            "server-version": "Update server software to the latest stable version. Subscribe to security advisories.",
            "cms-detect": "Keep CMS core and all plugins updated. Remove unused plugins and default files.",
            "framework-version": "Update frameworks to latest stable releases. Monitor CVE databases.",
            "dep-confusion": "Use scoped namespaces and private package registries. Pin and verify dependency checksums.",
            "sbom-check": "Move dependency manifests outside the web root. Block direct access via server config.",
            // A04
            "https-check": "Enforce HTTPS via server redirect and HSTS header. Maintain a valid TLS certificate.",
            "hsts": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "weak-tls": "Disable TLS 1.0/1.1. Configure TLS 1.2+ only with strong cipher suites.",
            "data-in-url": "Move sensitive data to POST body or request headers. Never include tokens in URLs.",
            "cookie-flags": "Set 'Secure', 'HttpOnly', and 'SameSite=Strict' on all session cookies.",
            // A05
            "sqli-probe": "Use parameterized queries / prepared statements. Apply input validation and WAF rules.",
            "xss-reflection": "Implement output encoding (HTML entity encoding). Set a strict Content-Security-Policy.",
            "cmd-injection": "Never pass user input to OS commands. Use language-level safe APIs.",
            "ldap-injection": "Sanitize special characters in LDAP queries. Use parameterized LDAP operations.",
            "ssti": "Avoid passing user input into templates. Use a sandboxed template engine.",
            // A06
            "rate-limit": "Implement rate limiting (10 req/min on login). Use exponential backoff and CAPTCHA.",
            "captcha": "Add CAPTCHA on login, registration, and password reset forms.",
            "password-policy": "Enforce min 12 characters, mixed case, numbers, symbols. Check against breached passwords.",
            "account-enum": "Return generic error messages: 'Invalid credentials' for all authentication failures.",
            "business-logic": "Validate all critical business values (price, quantity) server-side. Ignore client-sent values.",
            // A07
            "brute-force": "Implement progressive lockout (5 attempts → 15 min lock). Add CAPTCHA after 3 failures.",
            "session-fixation": "Regenerate session ID after successful login. Invalidate all previous session tokens.",
            "mfa-check": "Implement MFA (TOTP, WebAuthn). Make mandatory for admin and privileged accounts.",
            "password-reset": "Use cryptographically random tokens with <1 hour expiry. Rate limit reset requests.",
            "session-timeout": "Set idle session timeout to 15-30 minutes. Force re-authentication for sensitive actions.",
            // A08
            "sri-check": "Add integrity attribute to all external scripts: <script src='...' integrity='sha384-...' crossorigin>",
            "csp-check": "Implement strict CSP: default-src 'self'; script-src 'self'; upgrade-insecure-requests",
            "deserialization": "Avoid deserializing untrusted data. Use safe serialization formats like JSON.",
            "update-check": "Verify digital signatures on all updates. Use HTTPS-only update channels with pinning.",
            // A09
            "error-log": "Restrict log file access with permissions. Move logs outside web root.",
            "access-log": "Protect logs with authentication. Use centralized SIEM with automated alerting.",
            "waf-detect": "Deploy a WAF (ModSecurity, Cloudflare WAF, AWS WAF) as a layer of defense-in-depth.",
            "sec-event-headers": "Add Report-To and NEL headers for real-time client-side anomaly reporting.",
            // A10
            "stack-trace": "Add global exception handlers returning generic 500 errors. Log details server-side only.",
            "resource-exhaustion": "Set max request size, connection timeouts, and memory limits at the server level.",
            "null-input": "Validate all inputs server-side including null, empty, boundary, and oversized values.",
            "error-consistency": "Return uniform error messages for all failure types to prevent information leakage.",
            "circuit-breaker": "Implement circuit breakers and timeouts on all external / downstream service calls.",
        };
        return remediations[testType] || "Review and fix the identified vulnerability following OWASP Top 10:2025 guidelines.";
    }

    // ── Main Scanner ──
    async function runOwaspScan(targetUrl, outputEl, progressFillEl, progressTextEl, resultsCallback) {
        const allResults = [];
        const totalChecks = owaspChecks.reduce((sum, cat) => sum + cat.checks.length, 0);
        let completed = 0;

        addLine(outputEl, "system", "╔═══════════════════════════════════════════════════════════╗");
        addLine(outputEl, "info", "║   NexPent OWASP Top 10:2025 Vulnerability Scanner         ║");
        addLine(outputEl, "system", "╚═══════════════════════════════════════════════════════════╝");
        addLine(outputEl, "info", `[TARGET] ${targetUrl}`);
        addLine(outputEl, "info", `[CHECKS] ${totalChecks} security checks across ${owaspChecks.length} OWASP:2025 categories`);
        addLine(outputEl, "system", "─".repeat(62));

        for (const category of owaspChecks) {
            addLine(outputEl, "info", "");
            addLine(outputEl, "warning", `┌─ ${category.id}: ${category.name}`);
            addLine(outputEl, "system", `│  Running ${category.checks.length} checks...`);

            const catResults = { id: category.id, name: category.name, icon: category.icon, findings: [] };

            for (const check of category.checks) {
                completed++;
                const pct = Math.round((completed / totalChecks) * 100);
                progressFillEl.style.width = pct + "%";
                progressTextEl.textContent = pct + "%";

                await sleep(randomInt(100, 320));

                const finding = simulateCheck(check, targetUrl);

                if (finding) {
                    catResults.findings.push(finding);
                    const sevColor = finding.severity === "critical" ? "error"
                        : finding.severity === "high" ? "vuln"
                            : "warning";
                    addLine(outputEl, sevColor, `│  ⚠ [${finding.severity.toUpperCase()}] ${finding.name}`);
                    addLine(outputEl, "system", `│    └─ ${truncate(finding.evidence, 75)}`);
                } else {
                    addLine(outputEl, "success", `│  ✓ ${check.name} — Passed`);
                }
            }

            if (catResults.findings.length > 0) {
                addLine(outputEl, "error", `└─ ${catResults.findings.length} issue(s) found in ${category.name}`);
            } else {
                addLine(outputEl, "success", `└─ ${category.name} — All checks passed ✓`);
            }

            allResults.push(catResults);
        }

        // ── Summary ──
        const totalFindings = allResults.reduce((s, c) => s + c.findings.length, 0);
        const criticalCount = allResults.reduce((s, c) => s + c.findings.filter(f => f.severity === "critical").length, 0);
        const highCount = allResults.reduce((s, c) => s + c.findings.filter(f => f.severity === "high").length, 0);
        const mediumCount = allResults.reduce((s, c) => s + c.findings.filter(f => f.severity === "medium").length, 0);
        const lowCount = allResults.reduce((s, c) => s + c.findings.filter(f => f.severity === "low").length, 0);

        addLine(outputEl, "system", "");
        addLine(outputEl, "system", "═".repeat(62));
        addLine(outputEl, "info", "  SCAN SUMMARY — OWASP Top 10:2025");
        addLine(outputEl, "system", "═".repeat(62));
        addLine(outputEl, totalFindings > 0 ? "error" : "success", `  Total Findings: ${totalFindings}`);
        if (criticalCount > 0) addLine(outputEl, "error", `  ● Critical: ${criticalCount}`);
        if (highCount > 0) addLine(outputEl, "vuln", `  ● High:     ${highCount}`);
        if (mediumCount > 0) addLine(outputEl, "warning", `  ● Medium:   ${mediumCount}`);
        if (lowCount > 0) addLine(outputEl, "info", `  ● Low:      ${lowCount}`);
        addLine(outputEl, "system", "═".repeat(62));

        if (totalFindings === 0) {
            addLine(outputEl, "success", "  ✓ No OWASP Top 10:2025 vulnerabilities detected.");
        } else {
            addLine(outputEl, "error", `  ⚠ ${totalFindings} vulnerabilities mapped to OWASP Top 10:2025 categories.`);
        }

        addLine(outputEl, "system", "");
        addLine(outputEl, "info", "[DONE] OWASP Top 10:2025 scan complete.");

        if (resultsCallback) resultsCallback(allResults, { total: totalFindings, critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount });
        return allResults;
    }

    // ── Utilities ──
    function addLine(container, type, text) {
        const line = document.createElement("div");
        line.className = `terminal-line ${type}`;
        line.innerHTML = `<span class="msg">${text}</span>`;
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;
    }

    function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
    function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
    function truncate(str, len) { return str.length > len ? str.substring(0, len) + "..." : str; }

    return { runOwaspScan, owaspChecks };
})();
