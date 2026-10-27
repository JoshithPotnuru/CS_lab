const express = require('express');
const path = require('path');

const app = express();
const PORT = 3001;

// Automatically redirect root / to /csrf-get.html
app.get('/', (req, res) => {
  res.redirect('/csrf-get.html');
});

// Serve static attacker files (csrf-get.html)
app.use(express.static(__dirname));

const server = app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(` Attacker Server running at: http://localhost:${PORT}`);
  console.log(` GET CSRF Demo: http://localhost:${PORT}/csrf-get.html`);
  console.log(`====================================================`);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[ERROR] Port ${PORT} is already in use by another process.`);
    console.error(`You can kill the existing process on port ${PORT} via PowerShell:`);
    console.error(`Get-Process -Id (Get-NetTCPConnection -LocalPort ${PORT}).OwningProcess | Stop-Process -Force`);
  } else {
    console.error('[ERROR] Server error:', err);
  }
  process.exit(1);
});
