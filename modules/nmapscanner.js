/* ============================================
   NexPent — Nmap Scanner Module
   Simulates Nmap-style network scanning from
   T0 (Paranoid) to T5 (Insane) timing templates.
   ============================================ */

const NmapModule = (() => {
    "use strict";

    // ── Timing Templates ─────────────────────────
    const TIMING_TEMPLATES = {
        T0: { label: "T0 — Paranoid", desc: "IDS evasion, serial scanning, 5 min delay between probes", parallelism: 1, delayMs: 800, color: "#94a3b8" },
        T1: { label: "T1 — Sneaky", desc: "IDS evasion, serial scanning, 15 sec delay between probes", parallelism: 1, delayMs: 600, color: "#60a5fa" },
        T2: { label: "T2 — Polite", desc: "Slows scan to use less bandwidth, serial scanning", parallelism: 1, delayMs: 400, color: "#34d399" },
        T3: { label: "T3 — Normal", desc: "Default Nmap timing, balance between speed and stealth", parallelism: 4, delayMs: 200, color: "#fbbf24" },
        T4: { label: "T4 — Aggressive", desc: "Faster scan, assumes reliable network, may trigger IDS", parallelism: 8, delayMs: 100, color: "#f97316" },
        T5: { label: "T5 — Insane", desc: "Fastest scan, sacrifices accuracy for speed", parallelism: 16, delayMs: 40, color: "#ef4444" },
    };

    // ── Scan Types ───────────────────────────────
    const SCAN_TYPES = {
        syn: { label: "SYN Scan (-sS)", flag: "-sS", desc: "Half-open scan, stealthy, requires root" },
        connect: { label: "Connect Scan (-sT)", flag: "-sT", desc: "Full TCP connect, no root required" },
        udp: { label: "UDP Scan (-sU)", flag: "-sU", desc: "Scan UDP ports, slower but finds hidden services" },
        fin: { label: "FIN Scan (-sF)", flag: "-sF", desc: "Stealth FIN scan, evades stateless firewalls" },
        xmas: { label: "Xmas Scan (-sX)", flag: "-sX", desc: "Sets FIN, PSH, URG flags for firewall evasion" },
        ack: { label: "ACK Scan (-sA)", flag: "-sA", desc: "Map firewall rulesets, determine filtered ports" },
        version: { label: "Version Detect (-sV)", flag: "-sV", desc: "Probe open ports for service/version info" },
        os: { label: "OS Detection (-O)", flag: "-O", desc: "Detect operating system using TCP/IP fingerprinting" },
    };

    // ── Common Services Database ─────────────────
    const SERVICES = {
        21: { name: "ftp", version: "vsftpd 3.0.5", state: "open", risk: "medium" },
        22: { name: "ssh", version: "OpenSSH 9.6p1", state: "open", risk: "low" },
        23: { name: "telnet", version: "Linux telnetd", state: "open", risk: "critical" },
        25: { name: "smtp", version: "Postfix smtpd", state: "open", risk: "medium" },
        53: { name: "dns", version: "BIND 9.18.24", state: "open", risk: "low" },
        80: { name: "http", version: "Apache/2.4.58", state: "open", risk: "medium" },
        110: { name: "pop3", version: "Dovecot pop3d", state: "open", risk: "medium" },
        111: { name: "rpcbind", version: "rpcbind 2-4", state: "open", risk: "high" },
        135: { name: "msrpc", version: "Microsoft Windows RPC", state: "open", risk: "high" },
        139: { name: "netbios", version: "Samba smbd 4.19", state: "open", risk: "high" },
        143: { name: "imap", version: "Dovecot imapd", state: "open", risk: "medium" },
        443: { name: "https", version: "nginx/1.25.4", state: "open", risk: "low" },
        445: { name: "smb", version: "Samba smbd 4.19", state: "open", risk: "high" },
        993: { name: "imaps", version: "Dovecot imapd", state: "open", risk: "low" },
        995: { name: "pop3s", version: "Dovecot pop3d", state: "open", risk: "low" },
        1433: { name: "ms-sql", version: "SQL Server 2022", state: "open", risk: "critical" },
        1521: { name: "oracle", version: "Oracle TNS 19c", state: "open", risk: "critical" },
        3306: { name: "mysql", version: "MySQL 8.0.36", state: "open", risk: "high" },
        3389: { name: "rdp", version: "MS Terminal Services", state: "open", risk: "critical" },
        5432: { name: "postgres", version: "PostgreSQL 16.2", state: "open", risk: "high" },
        5900: { name: "vnc", version: "VNC Server 6.11", state: "open", risk: "critical" },
        6379: { name: "redis", version: "Redis 7.2.4", state: "open", risk: "high" },
        8080: { name: "http-alt", version: "Apache Tomcat/10.1", state: "open", risk: "medium" },
        8443: { name: "https-alt", version: "Jetty 12.0.5", state: "open", risk: "medium" },
        9200: { name: "elasticsearch", version: "Elasticsearch 8.12", state: "open", risk: "high" },
        27017: { name: "mongodb", version: "MongoDB 7.0.5", state: "open", risk: "high" },
    };

    const FILTERED_PORTS = [113, 514, 631, 1080, 8888];
    const OS_FINGERPRINTS = [
        { os: "Linux 5.15 - 6.7", accuracy: 96, type: "Linux", details: "Linux 6.2 (Ubuntu 23.04)" },
        { os: "Windows Server 2022", accuracy: 93, type: "Windows", details: "Microsoft Windows Server 2022 Build 20348" },
        { os: "FreeBSD 13.2 - 14.0", accuracy: 88, type: "FreeBSD", details: "FreeBSD 14.0-RELEASE" },
        { os: "macOS 14 (Sonoma)", accuracy: 85, type: "macOS", details: "Apple macOS 14.3 (Darwin 23.3)" },
    ];

    // ── Utility ──────────────────────────────────
    function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

    function appendLine(output, type, msg) {
        const line = document.createElement("div");
        line.className = `terminal-line ${type}`;
        const prefix = { info: "[*]", success: "[+]", warning: "[!]", error: "[!!]", system: "[~]" };
        line.innerHTML = `<span class="time">${prefix[type] || "[*]"}</span><span class="msg">${msg}</span>`;
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;
    }

    function riskBadge(risk) {
        const colors = { critical: "#ef4444", high: "#f97316", medium: "#fbbf24", low: "#34d399" };
        return `<span style="color:${colors[risk] || '#94a3b8'};font-weight:600">${risk.toUpperCase()}</span>`;
    }

    // ── Generate simulated results ───────────────
    function generateResults(target, scanType, timing) {
        const knownPorts = Object.keys(SERVICES).map(Number);
        const portCount = Math.min(6 + Math.floor(Math.random() * 12), knownPorts.length);
        const shuffled = knownPorts.sort(() => Math.random() - 0.5);
        const openPorts = shuffled.slice(0, portCount).sort((a, b) => a - b);

        // Add some filtered ports
        const filteredCount = 1 + Math.floor(Math.random() * 3);
        const filtered = FILTERED_PORTS.sort(() => Math.random() - 0.5).slice(0, filteredCount);

        // OS detection
        const osGuess = OS_FINGERPRINTS[Math.floor(Math.random() * OS_FINGERPRINTS.length)];

        // Traceroute hops
        const hops = 3 + Math.floor(Math.random() * 12);

        return { openPorts, filtered, osGuess, hops, target, scanType, timing };
    }

    // ── Run Nmap Scan ────────────────────────────
    async function runNmapScan(config, output, progressContainer, progressFill, progressText) {
        const { target, scanType, timing, enableOS, enableVersion, enableScripts } = config;
        const tmpl = TIMING_TEMPLATES[timing] || TIMING_TEMPLATES.T3;
        const scan = SCAN_TYPES[scanType] || SCAN_TYPES.syn;
        const results = generateResults(target, scanType, timing);

        // Clear output
        output.innerHTML = "";
        progressContainer.style.display = "block";

        // Build command string
        let cmdFlags = scan.flag;
        if (enableVersion) cmdFlags += " -sV";
        if (enableOS) cmdFlags += " -O";
        if (enableScripts) cmdFlags += " --script=default,vuln";
        cmdFlags += ` -${timing}`;

        appendLine(output, "system", `Starting Nmap 7.95 ( https://nmap.org )`);
        appendLine(output, "info", `<span style="color:${tmpl.color}">Timing: ${tmpl.label}</span> &mdash; ${tmpl.desc}`);
        appendLine(output, "info", `Scan type: <strong>${scan.label}</strong> &mdash; ${scan.desc}`);
        appendLine(output, "system", `Command: <code style="color:var(--accent-primary)">nmap ${cmdFlags} ${target}</code>`);
        await sleep(tmpl.delayMs * 2);

        appendLine(output, "info", `Initiating ${scan.label.split("(")[0].trim()} against ${target}...`);
        await sleep(tmpl.delayMs);

        // Phase 1: Host discovery
        appendLine(output, "info", "Host discovery: sending ARP requests...");
        await sleep(tmpl.delayMs);
        appendLine(output, "success", `Host ${target} is up (0.${Math.floor(Math.random() * 90) + 10}s latency).`);
        await sleep(tmpl.delayMs);

        // Phase 2: Port scanning
        const totalPorts = results.openPorts.length + results.filtered.length;
        appendLine(output, "info", `Scanning ${totalPorts + Math.floor(Math.random() * 900) + 100} ports on ${target}...`);
        await sleep(tmpl.delayMs);

        // Show port table header
        appendLine(output, "system", "");
        appendLine(output, "system", `<span style="font-family:var(--font-mono);color:var(--text-muted)">PORT       STATE      SERVICE         VERSION</span>`);
        appendLine(output, "system", `<span style="color:var(--border-primary)">───────────────────────────────────────────────────────</span>`);

        for (let i = 0; i < results.openPorts.length; i++) {
            const port = results.openPorts[i];
            const svc = SERVICES[port];
            const portStr = `${port}/tcp`.padEnd(10);
            const stateStr = "open".padEnd(10);
            const nameStr = svc.name.padEnd(15);
            const verStr = enableVersion ? svc.version : "";

            const progress = Math.round(((i + 1) / totalPorts) * 100);
            progressFill.style.width = `${progress}%`;
            progressText.textContent = `${progress}%`;

            appendLine(output, "success",
                `<span style="font-family:var(--font-mono)">${portStr} <span style="color:#34d399">open</span>       ${nameStr} ${verStr}</span> ${riskBadge(svc.risk)}`
            );
            await sleep(tmpl.delayMs);
        }

        // Filtered ports
        for (const fp of results.filtered) {
            appendLine(output, "warning",
                `<span style="font-family:var(--font-mono)">${(fp + "/tcp").padEnd(10)} <span style="color:#fbbf24">filtered</span>   unknown</span>`
            );
            await sleep(tmpl.delayMs / 2);
        }

        progressFill.style.width = "80%";
        progressText.textContent = "80%";

        // Phase 3: OS detection
        if (enableOS) {
            await sleep(tmpl.delayMs * 2);
            appendLine(output, "system", "");
            appendLine(output, "info", "Running OS detection (TCP/IP fingerprinting)...");
            await sleep(tmpl.delayMs * 3);
            appendLine(output, "success", `OS: <strong>${results.osGuess.os}</strong> (${results.osGuess.accuracy}% confidence)`);
            appendLine(output, "info", `Details: ${results.osGuess.details}`);
            progressFill.style.width = "90%";
            progressText.textContent = "90%";
        }

        // Phase 4: Script scanning
        if (enableScripts) {
            await sleep(tmpl.delayMs * 2);
            appendLine(output, "system", "");
            appendLine(output, "info", "Running NSE scripts (default, vuln)...");
            const scriptResults = [
                { port: results.openPorts[0], script: "http-title", output: `Title: "Welcome to ${target}"` },
                { port: results.openPorts[1], script: "ssl-cert", output: "Subject: CN=" + target },
                { port: results.openPorts[Math.floor(results.openPorts.length / 2)], script: "vuln", output: "VULNERABLE: CVE-2024-3094 (Potential)" },
            ];
            for (const sr of scriptResults) {
                if (sr.port && SERVICES[sr.port]) {
                    await sleep(tmpl.delayMs);
                    appendLine(output, sr.script === "vuln" ? "error" : "info",
                        `| ${sr.port}/${SERVICES[sr.port].name}: <code>${sr.script}</code>: ${sr.output}`
                    );
                }
            }
            progressFill.style.width = "95%";
            progressText.textContent = "95%";
        }

        // Phase 5: Traceroute
        await sleep(tmpl.delayMs);
        appendLine(output, "system", "");
        appendLine(output, "info", "Traceroute (using port 443/tcp)");
        for (let h = 1; h <= Math.min(results.hops, 6); h++) {
            await sleep(tmpl.delayMs / 2);
            const ip = h === results.hops ? target : `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${h}`;
            const latency = (Math.random() * 20 + h * 2).toFixed(2);
            appendLine(output, "system", `<span style="font-family:var(--font-mono);color:var(--text-muted)">  ${String(h).padStart(2)}  ${latency} ms  ${ip}</span>`);
        }

        // Summary
        progressFill.style.width = "100%";
        progressText.textContent = "100%";
        await sleep(tmpl.delayMs);

        const criticalPorts = results.openPorts.filter(p => SERVICES[p]?.risk === "critical");
        const highPorts = results.openPorts.filter(p => SERVICES[p]?.risk === "high");

        appendLine(output, "system", "");
        appendLine(output, "system", `<span style="color:var(--border-primary)">═══════════════════════════════════════════════════════</span>`);
        appendLine(output, "success", `Nmap done: 1 IP address (1 host up) scanned in ${(2 + Math.random() * 15).toFixed(2)}s`);
        appendLine(output, "info", `<strong>${results.openPorts.length}</strong> open ports &bull; <strong>${results.filtered.length}</strong> filtered &bull; <strong>${criticalPorts.length}</strong> critical &bull; <strong>${highPorts.length}</strong> high risk`);

        if (criticalPorts.length > 0) {
            appendLine(output, "error", `⚠ CRITICAL: ${criticalPorts.map(p => `${p}/${SERVICES[p].name}`).join(", ")} &mdash; immediate attention required!`);
        }
        if (highPorts.length > 0) {
            appendLine(output, "warning", `High-risk services detected: ${highPorts.map(p => `${p}/${SERVICES[p].name}`).join(", ")}`);
        }

        return {
            target,
            openPorts: results.openPorts.map(p => ({ port: p, service: SERVICES[p].name, version: SERVICES[p].version, risk: SERVICES[p].risk, state: SERVICES[p].state })),
            filtered: results.filtered,
            os: enableOS ? results.osGuess : null,
            timing,
            scanType,
            criticalCount: criticalPorts.length,
            highCount: highPorts.length,
            vulns: criticalPorts.concat(highPorts).map(p => ({
                port: p,
                service: SERVICES[p].name,
                severity: SERVICES[p].risk,
                detail: `${SERVICES[p].name} (${SERVICES[p].version}) on port ${p}`
            })),
        };
    }

    return {
        runNmapScan,
        TIMING_TEMPLATES,
        SCAN_TYPES,
    };
})();
