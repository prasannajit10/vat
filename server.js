const express = require('express');
const path = require('path');
const app = express();
const port = process.env.PORT || 3000;

// Serve static files from the current directory
app.use(express.static(path.join(__dirname)));

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
