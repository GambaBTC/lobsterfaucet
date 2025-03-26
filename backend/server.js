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
const TEST_IP = '148.71.55.160'; // Your IP for unlimited plays
const JWT_SECRET = 'your-secret-key'; // Replace with a strong secret
const DAILY_PAYOUT_LIMIT_PER_ADDRESS = 0.01; // 0.01 SOL per address per day
const DAILY_PAYOUT_LIMIT_SERVER = 1; // 1 SOL total per day for the server

// Initialize SQLite database with error handling
const db = new sqlite3.Database('plays.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error('Failed to open or create SQLite database:', err.message);
        process.exit(1); // Exit if database connection fails
    }
    console.log('Connected to SQLite database.');
});

// Ensure tables are created with 'lives' column
db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS plays (sessionId TEXT PRIMARY KEY, address TEXT, ip TEXT, timestamp INTEGER, wave INTEGER, score INTEGER, lives INTEGER DEFAULT 3, reward REAL, txSignature TEXT)', (err) => {
        if (err) console.error('Error creating plays table:', err.message);
        else console.log('Plays table created or already exists.');
    });
    db.run('CREATE TABLE IF NOT EXISTS daily_payouts (date TEXT, total REAL)', (err) => {
        if (err) console.error('Error creating daily_payouts table:', err.message);
        else console.log('Daily_payouts table created or already exists.');
    });
});

async function checkEligibility(address, ip) {
    return new Promise((resolve, reject) => {
        if (ip === TEST_IP) {
            console.log(`Bypassing eligibility check for test IP: ${ip}`);
            return resolve(true);
        }

        const now = Date.now();
        const oneDayAgo = now - 24 * 60 * 60 * 1000;

        db.get('SELECT SUM(reward) as dailyTotal, MAX(timestamp) as lastPlayed FROM plays WHERE address = ? AND timestamp > ?', 
            [address, oneDayAgo], (err, row) => {
                if (err) {
                    console.error('Database query error in checkEligibility:', err.message);
                    return reject(err);
                }
                if (!row || !row.lastPlayed) {
                    console.log(`No prior play found for address: ${address} or IP: ${ip} in last 24 hours`);
                    return resolve(true);
                }

                const dailyTotal = row.dailyTotal || 0;
                const lastPlayed = row.lastPlayed;
                const playedWithin24h = now - lastPlayed < 24 * 60 * 60 * 1000;
                const payoutLimitExceeded = dailyTotal >= DAILY_PAYOUT_LIMIT_PER_ADDRESS;

                console.log(`Eligibility check - Address: ${address}, IP: ${ip}, Last played: ${lastPlayed}, Daily total: ${dailyTotal} SOL, Played within 24h: ${playedWithin24h}, Limit exceeded: ${payoutLimitExceeded}`);

                if (playedWithin24h && payoutLimitExceeded) {
                    console.error('Address has reached daily payout limit or played within 24 hours');
                    return resolve(false);
                }
                resolve(true);
            });
    });
}

async function getDailyPayoutTotal(date) {
    return new Promise((resolve, reject) => {
        db.get('SELECT total FROM daily_payouts WHERE date = ?', [date], (err, row) => {
            if (err) {
                console.error('Database query error in getDailyPayoutTotal:', err.message);
                return reject(err);
            }
            const total = row ? row.total : 0;
            console.log(`Server-wide daily payout total for ${date}: ${total} SOL`);
            resolve(total);
        });
    });
}

async function updateDailyPayout(date, amount) {
    const current = await getDailyPayoutTotal(date);
    return new Promise((resolve, reject) => {
        db.run('INSERT OR REPLACE INTO daily_payouts (date, total) VALUES (?, ?)', [date, current + amount], (err) => {
            if (err) {
                console.error('Database update error in updateDailyPayout:', err.message);
                return reject(err);
            }
            console.log(`Updated server-wide daily payout for ${date}: ${current + amount} SOL`);
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
        console.log(`Sending ${amount} SOL to ${toAddress}...`);
        const signature = await connection.sendTransaction(transaction, [faucetKeypair]);
        await connection.confirmTransaction(signature);
        console.log(`Payout successful - Tx Signature: ${signature}`);
        return signature;
    } catch (error) {
        console.error('Error sending SOL:', error.message);
        throw error;
    }
}

async function getServerBalance() {
    try {
        console.log('Fetching server balance from Solana RPC...');
        const balanceLamports = await connection.getBalance(new PublicKey(FAUCET_ADDRESS));
        const balance = balanceLamports / 1000000000;
        console.log(`Server balance fetched: ${balance} SOL`);
        return balance;
    } catch (error) {
        console.error('Error fetching server balance:', error.message, error.stack);
        throw error;
    }
}

async function getTotalPayouts() {
    return new Promise((resolve, reject) => {
        console.log('Querying total payouts from database...');
        db.get('SELECT SUM(reward) as total FROM plays WHERE reward > 0', (err, row) => {
            if (err) {
                console.error('Database query error in getTotalPayouts:', err.message, err.stack);
                return reject(err);
            }
            const total = row.total || 0;
            console.log(`Total payouts fetched: ${total} SOL`);
            resolve(total);
        });
    });
}

app.post('/start-game', async (req, res) => {
    const { address } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    console.log(`Received /start-game request - Address: ${address}, IP: ${ip}`);

    if (!address || address.length !== 44 || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(address)) {
        console.error('Invalid Solana address provided');
        return res.status(400).json({ success: false, error: 'Invalid Solana address' });
    }

    try {
        const eligible = await checkEligibility(address, ip);
        if (!eligible) {
            console.error('Address or IP ineligible - played or reached payout limit within 24 hours');
            return res.status(403).json({ success: false, error: 'Address or IP has played or reached payout limit in the last 24 hours' });
        }
        const sessionId = `${address}-${Date.now()}`;
        const token = jwt.sign({ address, ip, sessionId }, JWT_SECRET, { expiresIn: '1h' });
        db.run('INSERT INTO plays (sessionId, address, ip, timestamp, wave, score, lives, reward) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
            [sessionId, address, ip, Date.now(), 1, 0, 3, 0], (err) => {
                if (err) console.error('Database insert error in /start-game:', err.message);
                else console.log(`New game session started - Session ID: ${sessionId}`);
            });
        res.json({ success: true, token, sessionId });
    } catch (error) {
        console.error('Error in /start-game:', error.message, error.stack);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.post('/update-game', async (req, res) => {
    const { sessionId, eventType, wave, score, lives, moveCount } = req.body;
    const authHeader = req.headers.authorization;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    console.log(`Received /update-game request - Session ID: ${sessionId}, Event: ${eventType}`);

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.error('No or invalid Authorization header in /update-game');
        return res.status(403).json({ success: false, error: 'Invalid token' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.sessionId !== sessionId || decoded.ip !== ip) {
            console.error('Token mismatch in /update-game');
            return res.status(403).json({ success: false, error: 'Invalid token' });
        }

        db.get('SELECT wave, score, lives FROM plays WHERE sessionId = ?', [sessionId], async (err, row) => {
            if (err || !row) {
                console.error('Invalid session in /update-game:', err ? err.message : 'No row found');
                return res.status(400).json({ success: false, error: 'Invalid session' });
            }

            const { wave: serverWave, score: serverScore, lives: serverLives } = row;
            if (wave < serverWave || score < serverScore || lives > serverLives) {
                console.error('Invalid game state update in /update-game');
                return res.status(400).json({ success: false, error: 'Invalid game state update' });
            }

            let reward = 0;
            if (eventType === 'game-over' || eventType === 'victory') {
                reward = wave === 10 ? 0.01 : wave >= 5 && wave <= 9 ? 0.005 : wave >= 3 && wave <= 4 ? 0.0025 : 0;
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
                            if (err) console.error('Database update error in /update-game:', err.message);
                            else console.log(`Game updated with payout - Session ID: ${sessionId}, Reward: ${reward} SOL`);
                        });
                }
            } else {
                db.run('UPDATE plays SET wave = ?, score = ?, lives = ?, moveCount = ? WHERE sessionId = ?', 
                    [wave, score, lives, moveCount, sessionId], (err) => {
                        if (err) console.error('Database update error in /update-game:', err.message);
                        else console.log(`Game state updated - Session ID: ${sessionId}`);
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
        console.log(`Sending /server-stats response: balance=${balance}, totalPayouts=${totalPayouts}`);
        res.json({ success: true, balance, totalPayouts });
    } catch (error) {
        console.error('Server stats error:', error.message, error.stack);
        res.status(500).json({ success: false, error: 'Failed to fetch server stats' });
    }
});

app.listen(port, () => console.log(`Server running on port ${port}`));
