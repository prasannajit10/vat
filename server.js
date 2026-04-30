const express = require('express');
const path = require('path');
const app = express();
const port = process.env.PORT || 3000;

// Serve static files from the current directory
app.use(express.static(path.join(__dirname)));

app.use(express.json());

// Proxy endpoint to bypass CORS
app.post('/api/proxy', async (req, res) => {
    try {
        const { url, method, headers, body } = req.body;

        if (!url) {
            return res.status(400).json({ error: "Missing url parameter" });
        }

        const options = {
            method: method || 'GET',
            headers: headers || {},
        };

        if (body && (method === 'POST' || method === 'PUT')) {
            options.body = body;
        }

        const fetch = (await import('node-fetch')).default || globalThis.fetch;
        const targetResp = await fetch(url, options);
        const targetBody = await targetResp.text();

        res.status(targetResp.status).send(targetBody);
    } catch (error) {
        console.error("Proxy Error:", error);
        res.status(502).json({ error: "Proxy Error: " + error.message });
    }
});

// Fallback to index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => {
    console.log(`\n======================================================`);
    console.log(`  🚀 NexPent Educational Scanner is running!`);
    console.log(`  🌐 Local: http://localhost:${port}`);
    console.log(`======================================================`);
    console.log(`  ⚠️  WARNING: EDUCATIONAL USE ONLY`);
    console.log(`  Ensure you have explicit permission before scanning`);
    console.log(`  any targets. Use strictly within authorized labs.`);
    console.log(`======================================================\n`);
});
