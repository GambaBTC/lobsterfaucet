const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('express-rate-limit');
const { Connection, PublicKey, Transaction, SystemProgram, Keypair } = require('@solana/web3.js');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

const connection = new Connection('https://api.mainnet-beta.solana.com', 'confirmed');
const faucetKeypair = Keypair.fromSecretKey(Uint8Array.from([/* Your 64-byte private key array */]));
const FAUCET_ADDRESS = 'GQMVuJCiPuEGm5fBnRYocwACGt8mo97ZYiMfDxbiMkRn';
const JWT_SECRET = 'your-secret-key'; // Replace with a strong secret
const DAILY_PAYOUT_LIMIT = 1; // SOL per day

const db = new sqlite3.Database('plays.db', (err) => {
    if (err) console.error(err.message);
    console.log('Connected to SQLite database.');
});
db.run('CREATE TABLE IF NOT EXISTS plays (sessionId TEXT PRIMARY KEY, address TEXT, ip TEXT, timestamp INTEGER, wave INTEGER, score INTEGER, reward REAL, txSignature TEXT)');
db.run('CREATE TABLE IF NOT EXISTS daily_payouts (date TEXT, total REAL)');

async function checkEligibility(address, ip) {
    return new Promise((resolve, reject) => {
        db.get('SELECT timestamp FROM plays WHERE address = ? OR ip = ?', [address, ip], (err, row) => {
            if (err) return reject(err);
            if (!row) return resolve(true);
            const now = Date.now();
            resolve(now - row.timestamp > 24 * 60 * 60 * 1000);
        });
    });
}

async function getDailyPayoutTotal(date) {
    return new Promise((resolve, reject) => {
        db.get('SELECT total FROM daily_payouts WHERE date = ?', [date], (err, row) => {
            if (err) return reject(err);
            resolve(row ? row.total : 0);
        });
    });
}

async function updateDailyPayout(date, amount) {
    const current = await getDailyPayoutTotal(date);
    db.run('INSERT OR REPLACE INTO daily_payouts (date, total) VALUES (?, ?)', [date, current + amount]);
}

async function sendSol(toAddress, amount) {
    const toPubkey = new PublicKey(toAddress);
    const lamports = amount * 1000000000;
    const transaction = new Transaction().add(
        SystemProgram.transfer({
            fromPubkey: faucetKeypair.publicKey,
            toPubkey,
            lamports
        })
    );
    const signature = await connection.sendTransaction(transaction, [faucetKeypair]);
    await connection.confirmTransaction(signature);
    return signature;
}

async function getServerBalance() {
    const balanceLamports = await connection.getBalance(new PublicKey(FAUCET_ADDRESS));
    return balanceLamports / 1000000000; // Convert lamports to SOL
}

async function getTotalPayouts() {
    return new Promise((resolve, reject) => {
        db.get('SELECT SUM(reward) as total FROM plays WHERE reward > 0', (err, row) => {
            if (err) return reject(err);
            resolve(row.total || 0);
        });
    });
}

app.post('/start-game', async (req, res) => {
    const { address } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!address || address.length !== 44 || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(address)) {
        return res.status(400).json({ success: false, error: 'Invalid Solana address' });
    }

    try {
        const eligible = await checkEligibility(address, ip);
        if (!eligible) {
            return res.status(403).json({ success: false, error: 'Address or IP has played in the last 24 hours' });
        }
        const sessionId = `${address}-${Date.now()}`;
        const token = jwt.sign({ address, ip, sessionId }, JWT_SECRET, { expiresIn: '1h' });
        db.run('INSERT INTO plays (sessionId, address, ip, timestamp, wave, score, reward) VALUES (?, ?, ?, ?, ?, ?, ?)', 
            [sessionId, address, ip, Date.now(), 1, 0, 0]);
        res.json({ success: true, token, sessionId });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.post('/update-game', async (req, res) => {
    const { sessionId, eventType, wave, score, lives, moveCount } = req.body;
    const token = req.headers.authorization;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.sessionId !== sessionId || decoded.ip !== ip) {
            return res.status(403).json({ success: false, error: 'Invalid token' });
        }

        db.get('SELECT wave, score, lives FROM plays WHERE sessionId = ?', [sessionId], async (err, row) => {
            if (err || !row) return res.status(400).json({ success: false, error: 'Invalid session' });

            const { wave: serverWave, score: serverScore, lives: serverLives } = row;
            if (wave < serverWave || score < serverScore || lives > serverLives) {
                return res.status(400).json({ success: false, error: 'Invalid game state update' });
            }

            let reward = 0;
            if (eventType === 'game-over' || eventType === 'victory') {
                reward = wave === FINAL_WAVE ? 0.01 : wave >= 5 && wave <= 9 ? 0.005 : wave >= 3 && wave <= 4 ? 0.0025 : 0;
                if (reward > 0) {
                    const date = new Date().toISOString().split('T')[0];
                    const dailyTotal = await getDailyPayoutTotal(date);
                    if (dailyTotal + reward > DAILY_PAYOUT_LIMIT) {
                        return res.status(403).json({ success: false, error: 'Daily payout limit reached' });
                    }
                    const balance = await connection.getBalance(faucetKeypair.publicKey) / 1000000000;
                    if (balance < reward) {
                        return res.status(503).json({ success: false, error: 'Faucet out of funds' });
                    }
                    const signature = await sendSol(decoded.address, reward);
                    await updateDailyPayout(date, reward);
                    db.run('UPDATE plays SET wave = ?, score = ?, lives = ?, reward = ?, txSignature = ? WHERE sessionId = ?', 
                        [wave, score, lives, reward, signature, sessionId]);
                }
            } else {
                db.run('UPDATE plays SET wave = ?, score = ?, lives = ?, moveCount = ? WHERE sessionId = ?', 
                    [wave, score, lives, moveCount, sessionId]);
            }
            res.json({ success: true });
        });
    } catch (error) {
        console.error('Update error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.get('/server-stats', async (req, res) => {
    try {
        const balance = await getServerBalance();
        const totalPayouts = await getTotalPayouts();
        res.json({ success: true, balance, totalPayouts });
    } catch (error) {
        console.error('Server stats error:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch server stats' });
    }
});

app.listen(port, () => console.log(`Server running on port ${port}`));
