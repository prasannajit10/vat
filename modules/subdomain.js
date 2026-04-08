/* ============================================
   NexPent — Subdomain Enumeration Module
   ============================================ */

const SubdomainModule = (() => {
    const wordlists = {
        small: [
            "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "dns", "mx",
            "webmail", "admin", "portal", "blog", "shop", "api", "dev",
            "staging", "test", "beta", "demo", "app", "mobile", "m",
            "cdn", "static", "media", "img", "images", "assets", "upload",
            "vpn", "remote", "gateway", "proxy", "firewall", "ssh",
            "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
            "git", "svn", "jenkins", "ci", "cd", "build", "deploy",
            "status", "monitor", "grafana", "metrics", "logs", "kibana",
            "help", "support", "docs", "wiki", "kb", "forum", "community",
            "auth", "login", "sso", "oauth", "id", "accounts", "signup",
            "payment", "billing", "invoice", "checkout", "store", "cart",
            "email", "newsletter", "marketing", "crm", "hr", "erp",
            "intranet", "internal", "corp", "office", "teams", "slack",
            "chat", "messaging", "notifications", "push", "websocket",
            "search", "analytics", "tracking", "events", "report",
            "video", "stream", "live", "broadcast", "rtmp", "hls",
            "s3", "backup", "archive", "storage", "vault", "secret",
            "sandbox", "preview", "uat", "qa", "prod", "production",
            "v1", "v2", "legacy", "old", "new", "next",
        ],
        medium: [], // Will be generated
        large: [], // Will be generated
    };

    // Generate medium and large wordlists
    const extraWords = [
        "server", "host", "node", "cluster", "edge", "origin",
        "panel", "dashboard", "console", "manage", "manager",
        "api-gateway", "api-v1", "api-v2", "rest", "graphql", "grpc",
        "ws", "wss", "socket", "mqtt", "amqp", "rabbitmq", "kafka",
        "cache", "memcached", "varnish", "haproxy", "nginx", "apache",
        "docker", "k8s", "kubernetes", "swarm", "rancher", "portainer",
        "terraform", "ansible", "puppet", "chef", "vault-server",
        "prometheus", "alertmanager", "pagerduty", "opsgenie", "datadog",
        "sentry", "bugsnag", "rollbar", "newrelic", "apm",
        "ldap", "ad", "radius", "kerberos", "saml", "oidc",
        "proxy-east", "proxy-west", "us-east", "us-west", "eu-west", "ap-south",
        "cdn1", "cdn2", "edge1", "edge2", "lb1", "lb2",
        "web1", "web2", "web3", "app1", "app2", "app3",
        "db1", "db2", "db-master", "db-slave", "db-replica",
        "worker", "queue", "job", "cron", "scheduler", "task",
        "oauth2", "token", "jwt", "session", "cookie",
        "download", "release", "update", "patch", "hotfix",
        "partner", "vendor", "supplier", "client", "customer",
        "stage1", "stage2", "stage3", "canary", "blue", "green",
        "primary", "secondary", "tertiary", "fallback", "dr",
        "lab", "research", "experiment", "poc", "prototype",
        "repo", "registry", "artifact", "nexus", "sonar", "sonarqube",
        "jira", "confluence", "bitbucket", "gitlab", "github",
        "mailserver", "exchange", "postfix", "dovecot", "imap",
        "dns1", "dns2", "ns3", "ns4", "resolver",
        "ntp", "time", "snmp", "syslog", "logstash", "fluentd",
        "minio", "ceph", "gluster", "nfs", "iscsi", "san",
        "pki", "ca", "cert", "certificate", "ssl", "tls",
        "waf", "ids", "ips", "siem", "splunk", "qradar",
        "pentest", "scan", "audit", "compliance", "security",
        "dev1", "dev2", "dev3", "test1", "test2", "qa1", "qa2",
        "pre-prod", "preprod", "integration", "acceptance",
        "catalog", "inventory", "order", "shipping", "tracking-sys",
        "content", "cms", "wp", "wordpress", "drupal", "joomla",
        "magento", "shopify", "woocommerce", "prestashop",
    ];

    wordlists.medium = [...wordlists.small, ...extraWords];
    wordlists.large = [...wordlists.medium,
    ...Array.from({ length: 200 }, (_, i) => `host${i + 1}`),
    ...Array.from({ length: 50 }, (_, i) => `server${i + 1}`),
    ...Array.from({ length: 50 }, (_, i) => `node${i + 1}`),
    ...Array.from({ length: 26 }, (_, i) => String.fromCharCode(97 + i)),
    ];

    // Simulated DNS record types
    const recordTypes = ["A", "AAAA", "CNAME", "MX", "TXT"];
    const ipRanges = ["104.21.", "172.67.", "13.107.", "52.168.", "34.102.", "143.204.", "151.101.", "185.199."];

    function generateIP() {
        const prefix = ipRanges[Math.floor(Math.random() * ipRanges.length)];
        return prefix + Math.floor(Math.random() * 254 + 1) + "." + Math.floor(Math.random() * 254 + 1);
    }

    async function enumerate(config, outputEl, progressEl, fillEl, textEl) {
        const { domain, wordlistSize, resolveDNS } = config;
        const wordlist = wordlists[wordlistSize] || wordlists.medium;

        const results = {
            domain,
            subdomains: [],
            total: wordlist.length,
            checked: 0,
        };

        progressEl.style.display = "flex";

        addLine(outputEl, "info", "[SCAN]", `Subdomain enumeration starting for: ${domain}`);
        addLine(outputEl, "info", "[INFO]", `Wordlist: ${wordlistSize} (${wordlist.length} entries)`);
        addLine(outputEl, "info", "[INFO]", `DNS Resolution: ${resolveDNS ? "Enabled" : "Disabled"}`);
        addLine(outputEl, "system", "[SYS]", "─".repeat(60));

        // Phase 1: Common subdomain check
        addLine(outputEl, "info", "[PHASE]", "Phase 1: Checking common subdomains...");

        for (let i = 0; i < wordlist.length; i++) {
            const sub = wordlist[i];
            const fullDomain = `${sub}.${domain}`;
            results.checked++;

            const pct = Math.round(((i + 1) / wordlist.length) * 100);
            fillEl.style.width = pct + "%";
            textEl.textContent = pct + "%";

            // Simulate DNS lookup delay
            await sleep(randomInt(15, 60));

            // Simulate ~15% discovery rate
            if (Math.random() < 0.15) {
                const ip = generateIP();
                const recordType = recordTypes[Math.floor(Math.random() * 3)];
                const status = Math.random() < 0.85 ? "200 OK" : Math.random() < 0.5 ? "301 Redirect" : "403 Forbidden";

                const result = {
                    subdomain: fullDomain,
                    ip,
                    recordType,
                    status,
                };
                results.subdomains.push(result);

                addLine(outputEl, "found", "[FOUND]", `${fullDomain}`);
                if (resolveDNS) {
                    addLine(outputEl, "success", "[DNS]", `  → ${recordType}: ${ip} | HTTP: ${status}`);
                }
            }

            // Show progress every 50 entries
            if ((i + 1) % 50 === 0) {
                addLine(outputEl, "system", `[${i + 1}/${wordlist.length}]`, `Checked ${i + 1} entries, found ${results.subdomains.length} subdomains...`);
            }
        }

        addLine(outputEl, "system", "[SYS]", "─".repeat(60));
        addLine(outputEl, "info", "[DONE]", `Enumeration complete!`);
        addLine(outputEl, "info", "[STAT]", `Checked: ${results.checked} | Found: ${results.subdomains.length} subdomains`);

        if (results.subdomains.length > 0) {
            addLine(outputEl, "system", "[SYS]", "─".repeat(60));
            addLine(outputEl, "info", "[LIST]", "Discovered subdomains:");
            results.subdomains.forEach((s, i) => {
                addLine(outputEl, "found", `[${i + 1}]`, `${s.subdomain} → ${s.ip} (${s.recordType})`);
            });
        }

        return results;
    }

    function exportResults(results) {
        let text = `# Subdomain Enumeration Report\n`;
        text += `# Target: ${results.domain}\n`;
        text += `# Date: ${new Date().toISOString()}\n`;
        text += `# Found: ${results.subdomains.length} subdomains\n\n`;

        results.subdomains.forEach((s) => {
            text += `${s.subdomain}\t${s.ip}\t${s.recordType}\t${s.status}\n`;
        });

        const blob = new Blob([text], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `subdomains_${results.domain}_${Date.now()}.txt`;
        a.click();
        URL.revokeObjectURL(url);
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

    return { enumerate, exportResults };
})();
