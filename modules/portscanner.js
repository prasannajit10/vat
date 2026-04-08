/* ============================================
   NexPent — Full Port Scanner Module
   ============================================ */

const PortScannerModule = (() => {
    // Well-known service mappings
    const serviceDB = {
        21: { service: "FTP", version: "vsftpd 3.0.5", risk: "medium" },
        22: { service: "SSH", version: "OpenSSH 8.9p1", risk: "low" },
        23: { service: "Telnet", version: "Linux telnetd", risk: "critical" },
        25: { service: "SMTP", version: "Postfix smtpd", risk: "medium" },
        53: { service: "DNS", version: "BIND 9.18.1", risk: "low" },
        80: { service: "HTTP", version: "Apache/2.4.54", risk: "medium" },
        110: { service: "POP3", version: "Dovecot pop3d", risk: "medium" },
        111: { service: "RPCbind", version: "rpcbind 2-4", risk: "high" },
        135: { service: "MSRPC", version: "Microsoft RPC", risk: "high" },
        139: { service: "NetBIOS-SSN", version: "Samba smbd 4.15", risk: "high" },
        143: { service: "IMAP", version: "Dovecot imapd", risk: "medium" },
        161: { service: "SNMP", version: "SNMPv2c", risk: "high" },
        389: { service: "LDAP", version: "OpenLDAP 2.5", risk: "medium" },
        443: { service: "HTTPS", version: "nginx/1.22.1", risk: "low" },
        445: { service: "Microsoft-DS", version: "SMBv3", risk: "high" },
        465: { service: "SMTPS", version: "Postfix", risk: "low" },
        587: { service: "Submission", version: "Postfix", risk: "low" },
        636: { service: "LDAPS", version: "OpenLDAP", risk: "low" },
        993: { service: "IMAPS", version: "Dovecot", risk: "low" },
        995: { service: "POP3S", version: "Dovecot", risk: "low" },
        1433: { service: "MSSQL", version: "Microsoft SQL Server 2022", risk: "high" },
        1521: { service: "Oracle DB", version: "Oracle 19c", risk: "high" },
        2049: { service: "NFS", version: "nfs-utils", risk: "high" },
        3306: { service: "MySQL", version: "MySQL 8.0.32", risk: "high" },
        3389: { service: "RDP", version: "Microsoft Terminal Services", risk: "high" },
        5432: { service: "PostgreSQL", version: "PostgreSQL 15.2", risk: "medium" },
        5900: { service: "VNC", version: "RealVNC 6.11", risk: "high" },
        5985: { service: "WinRM", version: "Microsoft HTTPAPI", risk: "medium" },
        6379: { service: "Redis", version: "Redis 7.0.8", risk: "high" },
        8080: { service: "HTTP-Proxy", version: "Apache Tomcat 10.1", risk: "medium" },
        8443: { service: "HTTPS-Alt", version: "nginx", risk: "low" },
        8888: { service: "HTTP-Alt", version: "Jupyter Notebook", risk: "medium" },
        9090: { service: "WebSM", version: "Prometheus", risk: "medium" },
        9200: { service: "Elasticsearch", version: "Elasticsearch 8.6", risk: "high" },
        27017: { service: "MongoDB", version: "MongoDB 6.0", risk: "high" },
        11211: { service: "Memcached", version: "Memcached 1.6", risk: "high" },
    };

    // Common open ports to simulate
    const commonPorts = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443, 9200, 27017];

    async function scanPorts(config, outputEl, progressEl, fillEl, textEl) {
        const { host, startPort, endPort, speed, serviceDetection } = config;
        const totalPorts = endPort - startPort + 1;

        const results = {
            host,
            startPort,
            endPort,
            openPorts: [],
            closedPorts: 0,
            filteredPorts: 0,
            scanned: 0,
            startTime: Date.now(),
        };

        progressEl.style.display = "flex";

        addLine(outputEl, "info", "[SCAN]", `Port scan starting on: ${host}`);
        addLine(outputEl, "info", "[INFO]", `Range: ${startPort}-${endPort} (${totalPorts} ports) | Speed: ${speed}`);
        addLine(outputEl, "info", "[INFO]", `Service detection: ${serviceDetection ? "Enabled" : "Disabled"}`);
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        const speedDelay = { slow: { min: 30, max: 80 }, normal: { min: 8, max: 30 }, fast: { min: 2, max: 10 } };
        const delay = speedDelay[speed] || speedDelay.normal;

        // Batch scanning for efficiency
        const batchSize = speed === "fast" ? 100 : speed === "normal" ? 50 : 20;

        for (let port = startPort; port <= endPort; port += batchSize) {
            const batchEnd = Math.min(port + batchSize - 1, endPort);

            for (let p = port; p <= batchEnd; p++) {
                results.scanned++;
                const pct = Math.round((results.scanned / totalPorts) * 100);
                fillEl.style.width = pct + "%";
                textEl.textContent = pct + "%";

                // Determine port state
                const state = getPortState(p);

                if (state === "open") {
                    const svc = serviceDB[p] || generateService(p);
                    const portResult = {
                        port: p,
                        state: "open",
                        service: svc.service,
                        version: serviceDetection ? svc.version : "unknown",
                        risk: svc.risk,
                    };
                    results.openPorts.push(portResult);

                    const riskColor = svc.risk === "critical" ? "error" : svc.risk === "high" ? "vuln" : svc.risk === "medium" ? "warning" : "found";
                    addLine(outputEl, "found", "[OPEN]", `Port ${p}/tcp — OPEN`);
                    if (serviceDetection) {
                        addLine(outputEl, riskColor, "[SVC]", `  → ${svc.service} ${svc.version} [Risk: ${svc.risk.toUpperCase()}]`);
                    }
                } else if (state === "filtered") {
                    results.filteredPorts++;
                } else {
                    results.closedPorts++;
                }
            }

            await sleep(randomInt(delay.min, delay.max));

            // Progress update
            if (results.scanned % 200 === 0 || results.scanned === totalPorts) {
                addLine(outputEl, "system", `[PROG]`, `Scanned ${results.scanned}/${totalPorts} ports (${Math.round((results.scanned / totalPorts) * 100)}%)`);
            }
        }

        results.endTime = Date.now();
        const duration = ((results.endTime - results.startTime) / 1000).toFixed(1);

        addLine(outputEl, "system", "[SYS]", "─".repeat(60));
        addLine(outputEl, "info", "[DONE]", `Port scan complete in ${duration}s`);
        addLine(outputEl, "info", "[STAT]", `Open: ${results.openPorts.length} | Closed: ${results.closedPorts} | Filtered: ${results.filteredPorts}`);

        if (results.openPorts.length > 0) {
            addLine(outputEl, "system", "[SYS]", "─".repeat(60));
            addLine(outputEl, "info", "[TABLE]", "PORT      STATE   SERVICE              VERSION                    RISK");
            addLine(outputEl, "system", "[SYS]", "─".repeat(80));

            results.openPorts.forEach((p) => {
                const portStr = `${p.port}/tcp`.padEnd(10);
                const stateStr = "open".padEnd(8);
                const svcStr = p.service.padEnd(21);
                const verStr = (p.version || "").padEnd(27);
                const riskStr = p.risk.toUpperCase();
                const lineClass = p.risk === "critical" || p.risk === "high" ? "vuln" : p.risk === "medium" ? "warning" : "found";
                addLine(outputEl, lineClass, "[PORT]", `${portStr}${stateStr}${svcStr}${verStr}${riskStr}`);
            });

            // Security recommendations
            const highRiskPorts = results.openPorts.filter((p) => p.risk === "critical" || p.risk === "high");
            if (highRiskPorts.length > 0) {
                addLine(outputEl, "system", "[SYS]", "─".repeat(60));
                addLine(outputEl, "error", "[ALERT]", `${highRiskPorts.length} high/critical risk service(s) detected!`);
                highRiskPorts.forEach((p) => {
                    addLine(outputEl, "warning", "[REC]", `Port ${p.port} (${p.service}): Consider restricting access or upgrading.`);
                });
            }
        }

        return results;
    }

    function getPortState(port) {
        // Known ports have higher chance of being open
        if (commonPorts.includes(port)) {
            const r = Math.random();
            if (r < 0.45) return "open";
            if (r < 0.55) return "filtered";
            return "closed";
        }

        // Other ports
        const r = Math.random();
        if (r < 0.02) return "open";
        if (r < 0.05) return "filtered";
        return "closed";
    }

    function generateService(port) {
        const genericServices = [
            { service: "Unknown", version: "unknown", risk: "medium" },
            { service: "HTTP-Alt", version: "Custom Web Server", risk: "medium" },
            { service: "App-Service", version: "Custom Application", risk: "medium" },
            { service: "Custom-TCP", version: "unknown protocol", risk: "low" },
        ];
        return genericServices[Math.floor(Math.random() * genericServices.length)];
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

    return { scanPorts };
})();
