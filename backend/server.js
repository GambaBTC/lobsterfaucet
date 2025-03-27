const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('express-rate-limit');
const { Connection, PublicKey, Transaction, SystemProgram, Keypair } = require('@solana/web3.js');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = 3000;

app.set('trust proxy', 1); // Trust the first proxy (Nginx)
app.use(cors());
app.use(express.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

const secretKeyArray = JSON.parse(fs.readFileSync('/home/faucetuser/lobsterfaucet/backend/faucet_keypair.json', 'utf8'));
const secretKey = Uint8Array.from(secretKeyArray);
console.log('Secret key length:', secretKey.length);
const faucetKeypair = Keypair.fromSecretKey(secretKey);
const FAUCET_ADDRESS = faucetKeypair.publicKey.toString();
const TEST_IP = '148.71.55.160';
const JWT_SECRET = process.env.JWT_SECRET;
const DAILY_PAYOUT_LIMIT_PER_ADDRESS = 0.01;
const DAILY_PAYOUT_LIMIT_SERVER = 1;

const connection = new Connection('https://api.mainnet-beta.solana.com', 'confirmed');

const db = new sqlite3.Database('plays.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) console.error('Failed to open SQLite database:', err.message);
    else console.log('Connected to SQLite database.');
});

db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS plays (sessionId TEXT PRIMARY KEY, address TEXT, ip TEXT, timestamp INTEGER, wave INTEGER, score INTEGER, lives INTEGER DEFAULT 3, reward REAL, txSignature TEXT)', (err) => {
        if (err) console.error('Error creating plays table:', err.message);
    });
    db.run('CREATE TABLE IF NOT EXISTS daily_payouts (date TEXT, total REAL)', (err) => {
        if (err) console.error('Error creating daily_payouts table:', err.message);
    });
    db.run('ALTER TABLE plays ADD COLUMN moveCount INTEGER DEFAULT 0', (err) => {
        if (err && !err.message.includes('duplicate column name')) console.error('Error adding moveCount:', err.message);
    });
});

// ... (rest of your server.js functions like checkEligibility, getDailyPayoutTotal, etc., remain unchanged)

app.post('/start-game', async (req, res) => {
    const { address } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(`Received /start-game request - Address: ${address}, IP: ${ip}`);

    if (!address || address.length !== 44 || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(address)) {
        return res.status(400).json({ success: false, error: 'Invalid Solana address' });
    }

    try {
        const eligible = await checkEligibility(address, ip);
        if (!eligible) {
            return res.status(403).json({ success: false, error: 'Address or IP has played or reached payout limit in the last 24 hours' });
        }
        const sessionId = `${address}-${Date.now()}`;
        const token = jwt.sign({ address, ip, sessionId }, JWT_SECRET, { expiresIn: '1h' });
        console.log(`Generated token: ${token}`);
        db.run('INSERT INTO plays (sessionId, address, ip, timestamp, wave, score, lives, reward) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
            [sessionId, address, ip, Date.now(), 1, 0, 3, 0], (err) => {
                if (err) console.error('DB error in /start-game:', err.message);
            });
        res.json({ success: true, token, sessionId });
    } catch (error) {
        console.error('Error in /start-game:', error.message);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.post('/update-game', async (req, res) => {
    const { sessionId, eventType, wave, score, lives, moveCount } = req.body;
    const authHeader = req.headers.authorization;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    console.log(`Received /update-game request - Session ID: ${sessionId}, Event: ${eventType}`);
    console.log(`Authorization header received: ${authHeader || 'none'}`);

    if (!authHeader) {
        console.error('No Authorization header in /update-game');
        return res.status(403).json({ success: false, error: 'No token provided' });
    }

    let token = authHeader;
    if (authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
        console.log('Token extracted with Bearer prefix');
    } else {
        console.log('Warning: Received raw token without Bearer prefix - accepting as workaround');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log(`Decoded token:`, decoded);
        if (decoded.sessionId !== sessionId || decoded.ip !== ip) {
            console.error('Token mismatch - sessionId or IP does not match');
            return res.status(403).json({ success: false, error: 'Invalid token' });
        }

        db.get('SELECT wave, score, lives FROM plays WHERE sessionId = ?', [sessionId], async (err, row) => {
            if (err || !row) {
                console.error('Invalid session:', err ? err.message : 'No row found');
                return res.status(400).json({ success: false, error: 'Invalid session' });
            }

            const { wave: serverWave, score: serverScore, lives: serverLives } = row;
            if (wave < serverWave || score < serverScore || lives > serverLives) {
                console.error('Invalid game state update');
                return res.status(400).json({ success: false, error: 'Invalid game state update' });
            }

            let reward = 0;
            if (eventType === 'game-over' || eventType === 'victory') {
                reward = wave === FINAL_WAVE ? 0.01 : wave >= 5 && wave <= 9 ? 0.005 : wave >= 3 && wave <= 4 ? 0.0025 : 0;
                if (reward > 0) {
                    const date = new Date().toISOString().split('T')[0];
                    const dailyTotalServer = await getDailyPayoutTotal(date);

                    if (decoded.address !== FAUCET_ADDRESS && dailyTotalServer + reward > DAILY_PAYOUT_LIMIT_SERVER) {
                        console.error('Server-wide daily payout limit reached');
                        return res.status(403).json({ success: false, error: 'Server-wide daily payout limit reached' });
                    }

                    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
                    const dailyTotalAddress = await new Promise((resolve, reject) => {
                        db.get('SELECT SUM(reward) as total FROM plays WHERE address = ? AND timestamp > ?', 
                            [decoded.address, oneDayAgo], (err, row) => {
                                if (err) return reject(err);
                                resolve(row.total || 0);
                            });
                    });
                    if (decoded.address !== FAUCET_ADDRESS && dailyTotalAddress + reward > DAILY_PAYOUT_LIMIT_PER_ADDRESS) {
                        console.error('Per-address daily payout limit reached');
                        return res.status(403).json({ success: false, error: 'Address has reached daily payout limit' });
                    }

                    const balance = await connection.getBalance(faucetKeypair.publicKey) / 1000000000;
                    if (balance < reward) {
                        console.error('Faucet out of funds');
                        return res.status(503).json({ success: false, error: 'Faucet out of funds' });
                    }

                    const signature = await sendSol(decoded.address, reward);
                    await updateDailyPayout(date, reward);
                    db.run('UPDATE plays SET wave = ?, score = ?, lives = ?, reward = ?, txSignature = ? WHERE sessionId = ?', 
                        [wave, score, lives, reward, signature, sessionId], (err) => {
                            if (err) console.error('DB update error:', err.message);
                            else console.log(`Game updated with payout - Reward: ${reward} SOL`);
                        });
                }
            } else {
                db.run('UPDATE plays SET wave = ?, score = ?, lives = ?, moveCount = ? WHERE sessionId = ?', 
                    [wave, score, lives, moveCount, sessionId], (err) => {
                        if (err) console.error('DB update error:', err.message);
                        else console.log(`Game state updated`);
                    });
            }
            res.json({ success: true });
        });
    } catch (error) {
        console.error('Error in /update-game:', error.message, error.stack);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.get('/server-stats', async (req, res) => {
    console.log('Received /server-stats request');
    try {
        const balance = await getServerBalance();
        const totalPayouts = await getTotalPayouts();
        res.json({ success: true, balance, totalPayouts });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to fetch server stats' });
    }
});

app.listen(port, () => console.log(`Server running on port ${port}`));
