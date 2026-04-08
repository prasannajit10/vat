/* ============================================
   NexPent — CVE Lookup Module
   ============================================ */

const CVELookupModule = (() => {
    // Comprehensive CVE database (simulated)
    const cveDatabase = [
        {
            id: "CVE-2024-3094",
            title: "XZ Utils Backdoor",
            desc: "Malicious code was discovered in the upstream tarballs of xz, starting from version 5.6.0. The backdoor allows remote code execution via SSH on affected systems.",
            severity: "critical",
            score: 10.0,
            vendor: "Tukaani Project",
            product: "XZ Utils",
            published: "2024-03-29",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
            cwe: "CWE-506",
        },
        {
            id: "CVE-2024-21762",
            title: "Fortinet FortiOS Out-of-Bound Write",
            desc: "A out-of-bounds write vulnerability in FortiOS SSL VPN may allow a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests.",
            severity: "critical",
            score: 9.8,
            vendor: "Fortinet",
            product: "FortiOS",
            published: "2024-02-09",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21762"],
            cwe: "CWE-787",
        },
        {
            id: "CVE-2023-44228",
            title: "Apache Log4j2 Remote Code Execution (Log4Shell)",
            desc: "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker controlled LDAP and other endpoints, enabling remote code execution.",
            severity: "critical",
            score: 10.0,
            vendor: "Apache",
            product: "Log4j",
            published: "2021-12-10",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            cwe: "CWE-917",
        },
        {
            id: "CVE-2024-1709",
            title: "ConnectWise ScreenConnect Authentication Bypass",
            desc: "Authentication bypass vulnerability in ConnectWise ScreenConnect allows an attacker to access the setup wizard and create admin accounts on already-installed instances.",
            severity: "critical",
            score: 10.0,
            vendor: "ConnectWise",
            product: "ScreenConnect",
            published: "2024-02-19",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1709"],
            cwe: "CWE-288",
        },
        {
            id: "CVE-2023-46805",
            title: "Ivanti Connect Secure Authentication Bypass",
            desc: "An authentication bypass vulnerability in the web component of Ivanti Connect Secure and Ivanti Policy Secure allows a remote attacker to access certain restricted resources without authentication.",
            severity: "critical",
            score: 8.2,
            vendor: "Ivanti",
            product: "Connect Secure",
            published: "2024-01-10",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-46805"],
            cwe: "CWE-287",
        },
        {
            id: "CVE-2024-23897",
            title: "Jenkins Arbitrary File Read",
            desc: "Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces '@' followed by a file path with the file's contents.",
            severity: "critical",
            score: 9.8,
            vendor: "Jenkins",
            product: "Jenkins",
            published: "2024-01-24",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-23897"],
            cwe: "CWE-22",
        },
        {
            id: "CVE-2023-4966",
            title: "Citrix NetScaler ADC Buffer Overflow (Citrix Bleed)",
            desc: "Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a AAA virtual server or Gateway, allowing session token theft.",
            severity: "critical",
            score: 9.4,
            vendor: "Citrix",
            product: "NetScaler ADC",
            published: "2023-10-10",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-4966"],
            cwe: "CWE-119",
        },
        {
            id: "CVE-2024-0012",
            title: "Palo Alto Networks PAN-OS Authentication Bypass",
            desc: "Authentication bypass in the management web interface of PAN-OS software enables unauthenticated attackers with network access to gain PAN-OS administrator privileges.",
            severity: "critical",
            score: 9.8,
            vendor: "Palo Alto Networks",
            product: "PAN-OS",
            published: "2024-11-18",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-0012"],
            cwe: "CWE-287",
        },
        {
            id: "CVE-2023-36884",
            title: "Microsoft Office & Windows HTML RCE",
            desc: "Microsoft is investigating reports of exploitation of this vulnerability using specially-crafted Microsoft Office documents to allow remote code execution.",
            severity: "high",
            score: 8.8,
            vendor: "Microsoft",
            product: "Office / Windows",
            published: "2023-07-11",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-36884"],
            cwe: "CWE-94",
        },
        {
            id: "CVE-2023-32315",
            title: "Openfire Admin Console Path Traversal",
            desc: "Path traversal vulnerability in Openfire's admin console allows unauthenticated users to access restricted pages and potentially execute admin functionality.",
            severity: "high",
            score: 8.6,
            vendor: "Ignite Realtime",
            product: "Openfire",
            published: "2023-05-26",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-32315"],
            cwe: "CWE-22",
        },
        {
            id: "CVE-2024-27198",
            title: "JetBrains TeamCity Authentication Bypass",
            desc: "Authentication bypass allowing an unauthenticated attacker to gain admin access in JetBrains TeamCity before 2023.11.4.",
            severity: "critical",
            score: 9.8,
            vendor: "JetBrains",
            product: "TeamCity",
            published: "2024-03-04",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-27198"],
            cwe: "CWE-288",
        },
        {
            id: "CVE-2023-20198",
            title: "Cisco IOS XE Web UI Privilege Escalation",
            desc: "A vulnerability in the web UI feature of Cisco IOS XE Software allows a remote unauthenticated attacker to create a high-privilege account.",
            severity: "critical",
            score: 10.0,
            vendor: "Cisco",
            product: "IOS XE",
            published: "2023-10-16",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-20198"],
            cwe: "CWE-269",
        },
        {
            id: "CVE-2024-6387",
            title: "OpenSSH regreSSHion RCE",
            desc: "A signal handler race condition in OpenSSH's server (sshd) allows unauthenticated remote code execution as root on glibc-based Linux systems.",
            severity: "critical",
            score: 8.1,
            vendor: "OpenBSD",
            product: "OpenSSH",
            published: "2024-07-01",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
            cwe: "CWE-362",
        },
        {
            id: "CVE-2023-38408",
            title: "OpenSSH ssh-agent RCE",
            desc: "The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution.",
            severity: "high",
            score: 7.5,
            vendor: "OpenBSD",
            product: "OpenSSH",
            published: "2023-07-20",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
            cwe: "CWE-426",
        },
        {
            id: "CVE-2024-4577",
            title: "PHP CGI Argument Injection",
            desc: "PHP CGI implementations on Windows fail to properly handle certain character sequences, enabling argument injection and remote code execution.",
            severity: "critical",
            score: 9.8,
            vendor: "PHP Group",
            product: "PHP",
            published: "2024-06-09",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"],
            cwe: "CWE-78",
        },
        {
            id: "CVE-2023-22515",
            title: "Atlassian Confluence Broken Access Control",
            desc: "Atlassian has been made aware of an issue reported by a handful of customers where external attackers may have exploited a previously unknown vulnerability in public Confluence instances to create unauthorized admin accounts.",
            severity: "critical",
            score: 10.0,
            vendor: "Atlassian",
            product: "Confluence",
            published: "2023-10-04",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-22515"],
            cwe: "CWE-284",
        },
        {
            id: "CVE-2025-0282",
            title: "Ivanti Connect Secure Stack-based Buffer Overflow",
            desc: "A stack-based buffer overflow in Ivanti Connect Secure allows remote unauthenticated code execution when exploited before authentication.",
            severity: "critical",
            score: 9.0,
            vendor: "Ivanti",
            product: "Connect Secure",
            published: "2025-01-08",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-0282"],
            cwe: "CWE-121",
        },
        {
            id: "CVE-2024-47575",
            title: "Fortinet FortiManager Missing Authentication for Critical Function",
            desc: "A missing authentication for critical function in FortiManager allows attackers to execute arbitrary code or commands via specially crafted requests.",
            severity: "critical",
            score: 9.8,
            vendor: "Fortinet",
            product: "FortiManager",
            published: "2024-10-23",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-47575"],
            cwe: "CWE-306",
        },
        {
            id: "CVE-2023-27997",
            title: "Fortinet FortiOS Heap Buffer Overflow (XORtigate)",
            desc: "A heap-based buffer overflow vulnerability in FortiOS SSL-VPN may allow a remote attacker to execute arbitrary code via specifically crafted requests.",
            severity: "critical",
            score: 9.8,
            vendor: "Fortinet",
            product: "FortiOS",
            published: "2023-06-12",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-27997"],
            cwe: "CWE-122",
        },
        {
            id: "CVE-2024-21887",
            title: "Ivanti Connect Secure Command Injection",
            desc: "A command injection vulnerability in web components of Ivanti Connect Secure and Ivanti Policy Secure allows an authenticated administrator to send specially crafted requests and execute arbitrary commands.",
            severity: "critical",
            score: 9.1,
            vendor: "Ivanti",
            product: "Connect Secure",
            published: "2024-01-10",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21887"],
            cwe: "CWE-77",
        },
    ];

    function search(query, severityFilter, yearStart, yearEnd) {
        query = query.toLowerCase().trim();

        return cveDatabase.filter((cve) => {
            // Query match
            const matchesQuery =
                cve.id.toLowerCase().includes(query) ||
                cve.title.toLowerCase().includes(query) ||
                cve.desc.toLowerCase().includes(query) ||
                cve.product.toLowerCase().includes(query) ||
                cve.vendor.toLowerCase().includes(query);

            if (!matchesQuery) return false;

            // Severity filter
            if (severityFilter !== "all" && cve.severity !== severityFilter) return false;

            // Year filter
            const year = parseInt(cve.published.substring(0, 4));
            if (year < yearStart || year > yearEnd) return false;

            return true;
        });
    }

    function renderResults(results, container) {
        container.innerHTML = "";

        if (results.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-search"></i>
                    <p>No CVEs found</p>
                    <span>Try a different search query or adjust filters</span>
                </div>
            `;
            return;
        }

        results.forEach((cve) => {
            const card = document.createElement("div");
            card.className = "cve-card";
            card.innerHTML = `
                <div class="cve-card-header">
                    <span class="cve-id">${cve.id}</span>
                    <span class="cve-severity ${cve.severity}">${cve.severity.toUpperCase()} (${cve.score})</span>
                </div>
                <div style="font-weight:600;font-size:0.85rem;margin-bottom:0.4rem;color:var(--text-primary)">${cve.title}</div>
                <div class="cve-desc">${cve.desc}</div>
                <div class="cve-meta">
                    <span><i class="fas fa-building"></i> ${cve.vendor}</span>
                    <span><i class="fas fa-cube"></i> ${cve.product}</span>
                    <span><i class="fas fa-calendar"></i> ${cve.published}</span>
                    <span><i class="fas fa-link"></i> ${cve.cwe}</span>
                </div>
            `;
            container.appendChild(card);
        });
    }

    return { search, renderResults, cveDatabase };
})();
