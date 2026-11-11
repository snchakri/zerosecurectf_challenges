const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());

// Generate RSA Keys for the challenge
const dir = path.join(__dirname, 'private', 'ledgers');
if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
}

console.log("Generating RSA keys... this may take a moment.");
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const ledgerPath = path.join(dir, 'veil-ledger.txt');
fs.writeFileSync(ledgerPath, JSON.stringify({ sigil: "vellum", description: "The curator's public key.", format: "JWT", publicKey: publicKey }, null, 2));

const privateKeyPath = path.join(__dirname, 'private', 'private.pem');
fs.writeFileSync(privateKeyPath, privateKey);

// Memory structures
const mirrorSubmissions = new Map();
const botQueue = [];
let submissionIdCounter = 1;

// Define the static public files later via app.use if needed, but we can do manual routes too
app.use(express.static('public'));

// Stage 1: Recon (Cinder)
app.get('/legacy/webring/embers-ring', (req, res) => {
    res.json({ sigil: "cinder", message: "The first seal is broken. The embers guide the way." });
});

// Stage 2: Mock XXE / LFI (Echo)
app.post('/legacy/oracle/preview', (req, res) => {
    const xmlData = req.body.xml;
    if (!xmlData) {
        return res.status(400).json({ error: "Missing 'xml' in body. Please provide XML to parse for the Oracle's preview." });
    }

    // Vulnerable mock parsing: look for xi:include
    const match = xmlData.match(/<xi:include\s+href="([^"]+)"/);
    if (match) {
        const href = match[1];
        if (href === 'archive://local/echo.txt') {
            return res.json({ parsed: true, content: { sigil: "echo", whisper: "The walls echo your thoughts." } });
        } else {
            return res.json({ parsed: true, content: `Error: File ${href} not found in archive.` });
        }
    }
    
    return res.json({ parsed: true, content: "No included archives found. XML seems valid." });
});

// Stage 3: Path Traversal (Vellum)
app.get('/legacy/scriptorium/export', (req, res) => {
    let requestedPath = req.query.path;
    if (!requestedPath) {
        return res.status(400).json({ error: "Missing 'path' parameter. Use format: path=scrolls/intro.txt" });
    }

    // Flawed sanitization: removes direct '../' but decodeURIComponent is called AFTER.
    let sanitizedPath = requestedPath.replace(/\.\.\//g, '');
    let finalPath;
    try {
        finalPath = decodeURIComponent(sanitizedPath);
    } catch(e) {
        return res.status(400).json({ error: "Invalid encoding" });
    }

    const safeBase = path.join(__dirname, 'public');
    const targetPath = path.resolve(safeBase, finalPath);

    fs.readFile(targetPath, 'utf8', (err, data) => {
        if (err) {
            return res.status(404).json({ error: "File not found or unreadable." });
        }
        res.send(data);
    });
});

// Stage 4: JWT Key Confusion (Veil)
app.get('/legacy/mask/curator', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Missing or invalid Bearer token. The Mask demands your identity." });
    }

    const token = authHeader.split(' ')[1];
    
    try {
        // Intentionally vulnerable configuration: allowing both RS256 and HS256 to enable Key Confusion
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256', 'HS256'] });
        
        if (decoded.role === 'curator') {
            return res.json({ sigil: "veil", message: "Welcome back, Curator. The veil is lifted." });
        } else {
            return res.status(403).json({ error: "Identity verified, but you lack the 'curator' role." });
        }
    } catch (err) {
        return res.status(403).json({ error: "Invalid signature. The Mask rejects you." });
    }
});

// Stage 5: Mirror XSS (Glass)
app.post('/legacy/mirror/submissions', (req, res) => {
    const html = req.body.html;
    if (!html) {
        return res.status(400).json({ error: "Provide 'html' in body." });
    }

    const id = (submissionIdCounter++).toString();
    mirrorSubmissions.set(id, html);
    botQueue.push(id); // Send to bot for processing

    res.json({ id: id, message: "Submission mirrored. The Curator is viewing it." });
});

app.get('/legacy/mirror/submissions/:id', (req, res) => {
    const html = mirrorSubmissions.get(req.params.id);
    if (!html) {
        return res.status(404).send("Mirror shattered. Submission not found.");
    }
    // Reflect exactly without sanitization for stored XSS
    res.send(`
        <html>
            <head><title>Mirrored Submission</title></head>
            <body>
                <h1>Submission Viewer</h1>
                <div>${html}</div>
            </body>
        </html>
    `);
});

// Bot internal endpoint to pull queue
app.get('/internal/bot/queue', (req, res) => {
    // Only bot network should reach this in real scenario, but we just want functionality here
    const id = botQueue.shift();
    res.json({ id: id || null });
});

// Stage 6: The Sanctum
app.post('/api/sanctum/verify', (req, res) => {
    const { sigils, nonce } = req.body;
    
    if (!Array.isArray(sigils) || sigils.length !== 5) {
        return res.status(400).json({ error: "You must present exactly 5 sigils in the correct array format." });
    }

    const expectedSigils = ["cinder", "echo", "vellum", "veil", "glass"];
    for (let i = 0; i < 5; i++) {
        if (sigils[i] !== expectedSigils[i]) {
            return res.status(403).json({ error: "The sigils are incorrect or out of order. The sanctum remains sealed." });
        }
    }

    // Verify the bot's nonce - wait, where does the nonce come from?
    // We didn't define memory storage for the correct nonce locally. Let's fix that.
    // The nonce should actually be derived statically or randomly generated on startup for this container.
    if (!nonce || nonce !== global.CTF_NONCE) {
        return res.status(403).json({ error: "You lack the Curator's temporal nonce. You watched the mirror, but saw nothing." });
    }

    res.json({ flag: "zerosec{cinder-echo-vellum-veil-glass_m4st3r_Of_th3_Maus0leum}" });
});

// Generate random nonce on startup
global.CTF_NONCE = crypto.randomBytes(16).toString('hex');
console.log(`[BOOT] Generated Nonce: ${global.CTF_NONCE}`);

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Alexandria Mausoleum App listening on port ${PORT}`);
});
