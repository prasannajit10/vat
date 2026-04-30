/* ============================================
   NexPent — Login Brute-Force Tester Module
   ============================================ */

const BruteForceModule = (() => {
    // Common default credentials database
    const defaultCreds = [
        { user: "admin", pass: "admin" },
        { user: "admin", pass: "password" },
        { user: "admin", pass: "123456" },
        { user: "root", pass: "root" },
        { user: "root", pass: "toor" },
        { user: "test", pass: "test" },
        { user: "user", pass: "user" },
        { user: "administrator", pass: "administrator" },
        { user: "admin", pass: "admin123" },
        { user: "guest", pass: "guest" },
    ];

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

    // Real brute-force implementation using fetch
    async function runBruteForce(config, outputEl, progressEl, fillEl, textEl) {
        const { url, userField, passField, usernames, passwords, failText } = config;

        const users = usernames.split("\n").filter((u) => u.trim()).map((u) => u.trim());
        const passes = passwords.split("\n").filter((p) => p.trim()).map((p) => p.trim());
        const combos = [];
        for (const u of users) for (const p of passes) combos.push({ u, p });

        // Safeguard: Cap total attempts
        const MAX_ATTEMPTS = 100;
        const totalAttempts = Math.min(combos.length, MAX_ATTEMPTS);

        const results = {
            target: url,
            totalAttempts,
            found: [],
            tested: 0,
            weakPasswords: [],
            noLockout: true,
            rateLimited: false,
        };

        progressEl.style.display = "flex";

        addLine(outputEl, "info", "[SCAN]", `Starting functional brute-force test on: ${url}`);
        addLine(outputEl, "info", "[INFO]", `Max Attempts: ${MAX_ATTEMPTS} (Educational Cap Active)`);
        addLine(outputEl, "info", "[INFO]", `Failure Indicator: "${failText}"`);
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        let lockoutDetected = false;
        let consecutiveFails = 0;

        for (let i = 0; i < totalAttempts; i++) {
            if (lockoutDetected) break;

            const { u, p } = combos[i];
            results.tested++;

            const pct = Math.round(((i + 1) / totalAttempts) * 100);
            fillEl.style.width = pct + "%";
            textEl.textContent = `${i + 1}/${totalAttempts}`;

            // Safeguard: Throttling
            await sleep(500);

            try {
                const body = new URLSearchParams();
                body.append(userField, u);
                body.append(passField, p);

                const start = Date.now();
                const resp = await proxyFetch(url, {
                    method: "POST",
                    headers: { "Content-Type": "application/x-www-form-urlencoded" },
                    body: body.toString(),
                    redirect: "manual" // Handle redirects manually to detect success
                });
                const text = await resp.text();

                // Detection Logic
                const isSuccess = !text.toLowerCase().includes(failText.toLowerCase()) && (resp.status === 200 || resp.status === 302);
                
                if (resp.status === 429 || text.toLowerCase().includes("too many requests") || text.toLowerCase().includes("locked")) {
                    lockoutDetected = true;
                    results.noLockout = false;
                    addLine(outputEl, "warning", "[LOCK]", `Account lockout or rate limit detected at attempt ${i + 1}`);
                    addLine(outputEl, "success", "[OK]", "Security mechanism functional.");
                    break;
                }

                if (isSuccess) {
                    results.found.push({ username: u, password: p });
                    addLine(outputEl, "vuln", "[FOUND]", `✓ Potential valid credentials: ${u}:${p}`);
                    consecutiveFails = 0;

                    if (isWeakPassword(p)) {
                        results.weakPasswords.push({ u, p, reason: getWeakReason(p) });
                        addLine(outputEl, "warning", "[WEAK]", `Weak password found: "${p}" — ${getWeakReason(p)}`);
                    }
                } else {
                    consecutiveFails++;
                    addLine(outputEl, "system", `[${i + 1}/${totalAttempts}]`, `${u}:${p} — Failed (Status: ${resp.status})`);
                }
            } catch (e) {
                addLine(outputEl, "error", "[ERR]", `Request failed for ${u}:${p} — ${e.message}`);
                // If we get many network errors, assume lockout or firewall
                if (consecutiveFails > 10) lockoutDetected = true;
            }
        }

        if (totalAttempts < combos.length) {
            addLine(outputEl, "warning", "[SAFE]", `Reached educational cap of ${MAX_ATTEMPTS} attempts.`);
        }

        addLine(outputEl, "system", "[SYS]", "─".repeat(60));
        addLine(outputEl, "info", "[DONE]", `Brute-force test complete.`);
        addLine(outputEl, "info", "[STAT]", `Tested: ${results.tested} | Found: ${results.found.length}`);

        // Security Assessment
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));
        addLine(outputEl, "info", "[ASSESS]", "Security Assessment:");

        if (results.found.length > 0) {
            addLine(outputEl, "error", "[FAIL]", `${results.found.length} credential combo(s) bypassed the failure indicator.`);
        } else {
            addLine(outputEl, "success", "[PASS]", "No credentials found within test parameters.");
        }

        if (results.noLockout && !lockoutDetected) {
            addLine(outputEl, "warning", "[WARN]", "No lockout/throttling detected — System may be vulnerable to high-speed brute force.");
        }

        return results;
    }

    function isWeakPassword(pass) {
        const weakPatterns = [
            /^(password|123456|admin|root|qwerty|letmein|welcome|monkey|master|dragon)$/i,
            /^(.)\1+$/, // All same characters
            /^[0-9]{1,6}$/, // Short numeric only
            /^[a-z]{1,5}$/i, // Short alpha only
        ];
        return pass.length < 8 || weakPatterns.some((p) => p.test(pass));
    }

    function getWeakReason(pass) {
        if (pass.length < 8) return "Too short (< 8 characters)";
        if (/^[0-9]+$/.test(pass)) return "Numeric only";
        if (/^[a-z]+$/i.test(pass)) return "No numbers or special characters";
        if (/^(password|123456|admin|root|qwerty|letmein)$/i.test(pass)) return "Common dictionary word";
        return "Weak pattern detected";
    }

    function addLine(container, type, time, msg) {
        const line = document.createElement("div");
        line.className = `terminal-line ${type}`;
        line.innerHTML = `<span class="time">${time}</span><span class="msg">${msg}</span>`;
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;
    }

    function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
    function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

    return { runBruteForce };
})();

