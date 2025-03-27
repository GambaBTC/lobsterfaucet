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

const logStream = fs.createWriteStream('server.log', { flags: 'a' });
const log = (message) => {
    const timestamp = new Date().toISOString();
    const logMessage = `${timestamp} - ${message}\n`;
    console.log(logMessage.trim());
    logStream.write(logMessage);
};

app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());

// Global rate limit: 10000 requests per 15 minutes
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 10000 }));

// Custom rate limit for /update-game: 10000 requests per 15 minutes
const updateGameRateLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 10000 });

const secretKeyArray = JSON.parse(fs.readFileSync('/home/faucetuser/lobsterfaucet/backend/faucet_keypair.json', 'utf8'));
const secretKey = Uint8Array.from(secretKeyArray);
log('Secret key length: ' + secretKey.length);
const faucetKeypair = Keypair.fromSecretKey(secretKey);
const FAUCET_ADDRESS = faucetKeypair.publicKey.toString();
const TEST_IP = '148.71.55.160';
const TEST_ADDRESS = '7MQe73raf4DtyWcAG2sM7wvouZE72BUsxVe65GxRjj2A';
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';
const DAILY_PAYOUT_LIMIT_SERVER = 1;
const FINAL_WAVE = 10;

const connection = new Connection('https://api.mainnet-beta.solana.com', 'confirmed');

const db = new sqlite3.Database('plays.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) log(`Failed to open SQLite database: ${err.message}`);
    else log('Connected to SQLite database.');
});

db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS plays (sessionId TEXT PRIMARY KEY, address TEXT, ip TEXT, timestamp INTEGER, wave INTEGER, score INTEGER, lives INTEGER DEFAULT 3, reward REAL, txSignature TEXT)', (err) => {
        if (err) log(`Error creating plays table: ${err.message}`);
    });
    db.run('CREATE TABLE IF NOT EXISTS daily_payouts (date TEXT, total REAL)', (err) => {
        if (err) log(`Error creating daily_payouts table: ${err.message}`);
    });
    db.run('ALTER TABLE plays ADD COLUMN moveCount INTEGER DEFAULT 0', (err) => {
        if (err && !err.message.includes('duplicate column name')) log(`Error adding moveCount: ${err.message}`);
    });
});

async function checkEligibility(address, ip) {
    return new Promise((resolve, reject) => {
        if (address === TEST_ADDRESS && ip === TEST_IP) {
            log(`Exempting test address ${TEST_ADDRESS} and IP ${TEST_IP}`);
            return resolve(true);
        }

        const now = Date.now();
        const oneDayAgo = now - 24 * 60 * 60 * 1000;
        db.get('SELECT MAX(timestamp) as lastPayoutTime FROM plays WHERE address = ? AND timestamp > ? AND reward > 0', 
            [address, oneDayAgo], (err, row) => {
                if (err) {
                    log(`Database query error in checkEligibility: ${err.message}`);
                    return reject(err);
                }
                if (!row || !row.lastPayoutTime) {
                    log(`No payout found for address: ${address} in last 24 hours - eligible`);
                    return resolve(true);
                }
                const lastPayoutTime = row.lastPayoutTime;
                const hasRecentPayout = now - lastPayoutTime < 24 * 60 * 60 * 1000;
                log(`Eligibility check - Address: ${address}, IP: ${ip}, Last payout: ${lastPayoutTime}, Has recent: ${hasRecentPayout}`);
                resolve(!hasRecentPayout);
            });
    });
}

async function getDailyPayoutTotal(date) {
    return new Promise((resolve, reject) => {
        db.get('SELECT total FROM daily_payouts WHERE date = ?', [date], (err, row) => {
            if (err) {
                log(`Database query error in getDailyPayoutTotal: ${err.message}`);
                return reject(err);
            }
            const total = row ? row.total : 0;
            log(`Server-wide daily payout total for ${date}: ${total} SOL`);
            resolve(total);
        });
    });
}

async function updateDailyPayout(date, amount) {
    const current = await getDailyPayoutTotal(date);
    return new Promise((resolve, reject) => {
        db.run('INSERT OR REPLACE INTO daily_payouts (date, total) VALUES (?, ?)', [date, current + amount], (err) => {
            if (err) {
                log(`Database update error in updateDailyPayout: ${err.message}`);
                return reject(err);
            }
            log(`Updated daily payout for ${date}: ${current + amount} SOL`);
            resolve();
        });
    });
}

async function sendSol(toAddress, amount) {
    try {
        const toPubkey = new PublicKey(toAddress);
        const lamports = amount * 1000000000;
        const transaction = new Transaction().add(
            SystemProgram.transfer({
                fromPubkey: faucetKeypair.publicKey,
                toPubkey,
                lamports
            })
        );
        log(`Sending ${amount} SOL to ${toAddress}...`);
        const signature = await connection.sendTransaction(transaction, [faucetKeypair]);
        await connection.confirmTransaction(signature);
        log(`Payout successful - Tx Signature: ${signature}`);
        return signature;
    } catch (error) {
        log(`Error sending SOL: ${error.message}`);
        throw error;
    }
}

async function getServerBalance() {
    try {
        log('Fetching server balance from Solana RPC...');
        const balanceLamports = await connection.getBalance(new PublicKey(FAUCET_ADDRESS));
        const balance = balanceLamports / 1000000000;
        log(`Server balance fetched: ${balance} SOL`);
        return balance;
    } catch (error) {
        log(`Error fetching server balance: ${error.message}`);
        throw error;
    }
}

async function getTotalPayouts() {
    return new Promise((resolve, reject) => {
        log('Querying total payouts from database...');
        db.get('SELECT SUM(reward) as total FROM plays WHERE reward > 0', (err, row) => {
            if (err) {
                log(`Database query error in getTotalPayouts: ${err.message}`);
                return reject(err);
            }
            const total = row.total || 0;
            log(`Total payouts fetched: ${total} SOL`);
            resolve(total);
        });
    });
}

app.post('/start-game', async (req, res) => {
    const { address } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    log(`Received /start-game request - Address: ${address}, IP: ${ip}`);

    if (!address || address.length !== 44 || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(address)) {
        log('Invalid Solana address provided');
        return res.status(400).json({ success: false, error: 'Invalid Solana address' });
    }

    try {
        const eligible = await checkEligibility(address, ip);
        if (!eligible) {
            log('Address received a payout within the last 24 hours - ineligible');
            return res.status(403).json({ success: false, error: 'Address received a payout in the last 24 hours' });
        }
        const sessionId = `${address}-${Date.now()}`;
        const token = jwt.sign({ address, ip, sessionId }, JWT_SECRET, { expiresIn: '1h' });
        log(`Generated token: ${token}`);
        db.run('INSERT INTO plays (sessionId, address, ip, timestamp, wave, score, lives, reward) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
            [sessionId, address, ip, Date.now(), 1, 0, 3, 0], (err) => {
                if (err) log(`DB error in /start-game: ${err.message}`);
                else log(`New game session started - Session ID: ${sessionId}`);
            });
        res.json({ success: true, token, sessionId });
    } catch (error) {
        log(`Error in /start-game: ${error.message}`);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.post('/update-game', updateGameRateLimit, async (req, res) => {
    const { sessionId, eventType, wave, score, lives, moveCount } = req.body;
    const authHeader = req.headers.authorization;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    log(`Received /update-game request - Session ID: ${sessionId}, EventType: ${eventType}, Wave: ${wave}, Score: ${score}, Lives: ${lives}, MoveCount: ${moveCount}`);
    if (!authHeader) {
        log('No Authorization header in /update-game');
        return res.status(403).json({ success: false, error: 'No token provided' });
    }

    let token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;
    log(`Token extracted: ${token}`);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        log(`Decoded token: ${JSON.stringify(decoded)}`);
        if (decoded.sessionId !== sessionId || decoded.ip !== ip) {
            log('Token mismatch - sessionId or IP does not match');
            return res.status(403).json({ success: false, error: 'Invalid token' });
        }

        db.get('SELECT wave, score, lives FROM plays WHERE sessionId = ?', [sessionId], async (err, row) => {
            if (err || !row) {
                log(`Invalid session: ${err ? err.message : 'No row found'}`);
                return res.status(400).json({ success: false, error: 'Invalid session' });
            }

            const { wave: serverWave, score: serverScore, lives: serverLives } = row;
            if (wave < serverWave || score < serverScore || lives > serverLives) {
                log('Invalid game state update');
                return res.status(400).json({ success: false, error: 'Invalid game state update' });
            }

            const maxScore = wave <= 3 ? 150 * wave : wave <= 5 ? 300 * wave : 600 * wave;
            if (wave > FINAL_WAVE + 1 || score > maxScore || moveCount < wave * 10) {
                log(`Cheat detected - Wave: ${wave}, Score: ${score}, MoveCount: ${moveCount}`);
                return res.status(400).json({ success: false, error: 'Invalid game data' });
            }

            let reward = 0;
            if (eventType === 'game-over' || eventType === 'victory') {
                reward = wave === FINAL_WAVE ? 0.01 : wave >= 5 && wave <= 9 ? 0.005 : wave >= 3 && wave <= 4 ? 0.0025 : 0;
                if (reward > 0) {
                    const date = new Date().toISOString().split('T')[0];
                    const dailyTotalServer = await getDailyPayoutTotal(date);

                    if (decoded.address !== FAUCET_ADDRESS && dailyTotalServer + reward > DAILY_PAYOUT_LIMIT_SERVER) {
                        log('Server-wide daily payout limit reached');
                        return res.status(403).json({ success: false, error: 'Server-wide daily payout limit reached' });
                    }

                    const balance = await connection.getBalance(faucetKeypair.publicKey) / 1000000000;
                    if (balance < reward) {
                        log('Faucet out of funds');
                        return res.status(503).json({ success: false, error: 'Faucet out of funds' });
                    }

                    const signature = await sendSol(decoded.address, reward);
                    await updateDailyPayout(date, reward);
                    db.run('UPDATE plays SET wave = ?, score = ?, lives = ?, reward = ?, txSignature = ?, moveCount = ? WHERE sessionId = ?', 
                        [wave, score, lives, reward, signature, moveCount, sessionId], (err) => {
                            if (err) log(`DB update error: ${err.message}`);
                            else log(`Game updated with payout - Reward: ${reward} SOL`);
                        });
                } else {
                    db.run('UPDATE plays SET wave = ?, score = ?, lives = ?, moveCount = ? WHERE sessionId = ?', 
                        [wave, score, lives, moveCount, sessionId], (err) => {
                            if (err) log(`DB update error: ${err.message}`);
                            else log(`Game state updated`);
                        });
                }
            } else {
                log('Invalid event type for update');
                return res.status(400).json({ success: false, error: 'Invalid event type' });
            }
            res.json({ success: true });
        });
    } catch (error) {
        log(`Error in /update-game: ${error.message}, Stack: ${error.stack}`);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.get('/server-stats', async (req, res) => {
    log('Received /server-stats request');
    try {
        const balance = await getServerBalance();
        const totalPayouts = await getTotalPayouts();
        log(`Sending /server-stats response: balance=${balance}, totalPayouts=${totalPayouts}`);
        res.json({ success: true, balance, totalPayouts });
    } catch (error) {
        log(`Server stats error: ${error.message}`);
        res.status(500).json({ success: false, error: 'Failed to fetch server stats' });
    }
});

app.listen(port, () => log(`Server running on port ${port}`));
