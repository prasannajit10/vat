# NexPent VAPT Toolkit v2.0

NexPent is an advanced automated vulnerability assessment and penetration testing toolkit. 
**This version has been adapted specifically for educational purposes.**

## ⚠️ Legal Disclaimer & Terms of Use

**NexPent is an educational tool designed strictly for learning and authorized testing purposes.**

By using this software, you agree to the following:
1. You will only use this tool against targets you own or have explicit, written permission to test (e.g., localhost, authorized sandboxes like `altoro.testfire.net`).
2. Any illegal use, unauthorized access, or malicious activity is strictly prohibited.
3. The authors are NOT responsible for any misuse, damage, or legal consequences caused by your actions.
4. This software does not collect telemetry, and all operations are performed locally on your machine.

If you do not agree with these terms, do not use this software.

## Features
- **SQL Injection Scanner**: Detect SQL injection vulnerabilities in GET & POST parameters.
- **XSS Detection**: Detect reflected and stored Cross-Site Scripting vulnerabilities.
- **Login Brute-Force Tester**: Test login form resistance against credential stuffing.
- **Static Code Scanner**: Upload source code files to detect insecure patterns.
- **Subdomain Enumeration**: Discover subdomains of a target domain.
- **Port & Nmap Scanner**: Simulated network scanning tools.
- **Report Generation**: Export findings to a professional PDF report.

## Installation

You need [Node.js](https://nodejs.org/) installed on your machine.

1. Clone or download the repository.
2. Open your terminal in the project directory.
3. Install the dependencies:
   ```bash
   npm install
   ```

## Usage

Start the local server:
```bash
npm start
```

Then open your browser and navigate to:
```
http://localhost:3000
```

*Note: Due to CORS restrictions in modern browsers, scanning external sites directly from the client side is often blocked. The tool works best against local development environments or configured test servers.*
