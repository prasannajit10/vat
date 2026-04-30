export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: "Method not allowed. Use POST." });
    }

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

        // We use native fetch (available in Node 18+)
        const targetResp = await fetch(url, options);
        const targetBody = await targetResp.text();

        // Forward target status code
        res.status(targetResp.status).send(targetBody);
    } catch (error) {
        console.error("Proxy Error:", error);
        res.status(502).json({ error: "Proxy Error: " + error.message });
    }
}
