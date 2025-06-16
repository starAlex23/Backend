// --- Umgebungsvariablen laden ---
import 'dotenv/config';

// --- Externe Abhängigkeiten ---
import express from 'express';
import { Pool } from 'pg';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import https from 'https';
import http from 'http'; // Hinzugefügt für HTTP-Server-Start
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import { v4 as uuidv4 } from 'uuid';
import Joi from 'joi';
import { fileURLToPath } from 'url'; // Für __dirname bei ES-Modulen
import cron from 'node-cron';
import { verifyRegistrationResponse } from '@simplewebauthn/server'; // Hinzugefügt für WebAuthn

// --- Eigene Module (mit .js-Endung!) ---
import { REFRESH_TOKEN_SECRET } from './config/env.js';
import { DATABASE_URL } from './config/env.js'

// --- Initialisierung ---
const app = express();
const router = express.Router();
export default router;

// --- ES-Module-kompatibles __dirname ermitteln ---
// Diese Variablen definieren __filename und __dirname für die Verwendung in ES-Modulen.
// Sie sind notwendig, um relative Pfade korrekt aufzulösen, da __dirname in ES-Modulen nicht direkt verfügbar ist.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SALT_ROUNDS = 12;

// --- Umgebungsvariablen validieren ---
// Diese Funktion prüft, ob alle notwendigen Umgebungsvariablen gesetzt sind.
// Wenn eine Variable fehlt oder ungültig ist, wird eine Fehlermeldung ausgegeben und die Anwendung beendet.
function validateEnv() {
    const requiredVars = [
        'DB_HOST',
        'DB_USER',
        'DB_PASSWORD',
        'DB_DATABASE',
        'DB_PORT',
        'JWT_SECRET',
        'REFRESH_SECRET',
        'JWT_ISSUER',
        'CORS_ORIGIN',
    ];

    for (const key of requiredVars) {
        if (!process.env[key]) {
            console.error(`❌ Fehlende Umgebungsvariable: ${key}`);
            process.exit(1);
        }
    }

    if (process.env.JWT_SECRET.length < 32) {
        console.error('❌ JWT_SECRET ist zu kurz. Mindestens 32 Zeichen erforderlich.');
        process.exit(1);
    }

    if (process.env.REFRESH_SECRET.length < 32) {
        console.error('❌ REFRESH_SECRET ist zu kurz. Mindestens 32 Zeichen erforderlich.');
        process.exit(1);
    }

    const port = parseInt(process.env.DB_PORT, 10);
    if (isNaN(port)) {
        console.error('❌ DB_PORT muss eine gültige Zahl sein.');
        process.exit(1);
    }
}

validateEnv();

// --- Pool Konfiguration für PostgreSQL ---
// Hier werden die Datenbankverbindungseinstellungen aus den Umgebungsvariablen gelesen.
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.use(cors({
  origin: 'https://nochmal-neu.vercel.app',
  credentials: true
}));


app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.url}`);
  next();
});


const JWT_SECRET = process.env.JWT_SECRET;

// --- Middleware Setup ---
// Helmet fügt wichtige HTTP-Header für die Sicherheit hinzu.
app.use(helmet());
// express.json() parst eingehende Anfragen mit JSON-Payloads.
app.use(express.json());
// cookieParser parst Cookies aus dem Request-Header.
app.use(cookieParser());

// --- Sichere CORS-Konfiguration ---
// Cross-Origin Resource Sharing (CORS) Einstellungen, um Anfragen von bestimmten Origins zu erlauben.
// 'secure' und 'sameSite: 'None'' sind wichtig für die Verwendung von Cookies über verschiedene Domains hinweg.
const corsOptions = {
    origin: [process.env.CORS_ORIGIN], // Erlaubt nur Anfragen von dieser Origin
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true, // Erlaubt das Senden von Cookies mit der Anfrage
    optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Preflight-Anfragen behandeln

// --- Rate Limiter für Login (Schutz vor Brute Force) ---
// Begrenzt die Anzahl der Login-Versuche pro IP-Adresse innerhalb eines bestimmten Zeitfensters, um Brute-Force-Angriffe zu verhindern.
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 Minuten
    max: 5, // Maximal 5 Versuche pro IP
    message: 'Zu viele Login-Versuche. Bitte warte 15 Minuten.',
    standardHeaders: true, // Standard-RateLimit-Header (RFC 6585)
    legacyHeaders: false, // Deaktiviert X-RateLimit-* Header
});

// --- Hilfsfunktionen ---
// Validiert, ob eine Zeichenkette eine gültige E-Mail-Adresse ist.
function istGueltigeEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// Sendet eine standardisierte Fehlermeldung als JSON-Antwort.
function sendError(res, code, message) {
    return res.status(code).json({ error: message });
}

// Helper: Auth-Cookies setzen (wird im Login verwendet)
function setAuthCookies(res, token, csrfToken) {
    const cookieOptionsHttpOnly = {
        httpOnly: true, // Cookie ist nicht über Client-seitiges JavaScript zugänglich
        secure: process.env.NODE_ENV === 'production', // Nur über HTTPS senden
        sameSite: 'None', // Erlaubt Cross-Site-Verwendung
        maxAge: 24 * 60 * 60 * 1000, // 1 Tag
    };
    const cookieOptionsJsAccessible = {
        httpOnly: false, // Cookie ist über Client-seitiges JavaScript zugänglich (für CSRF-Token)
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'None',
        maxAge: 24 * 60 * 60 * 1000,
    };

    res.cookie('token', token, cookieOptionsHttpOnly);
    res.cookie('csrf', csrfToken, cookieOptionsJsAccessible);
}

// Helper: Auth-Cookies löschen (Logout)
function clearAuthCookies(res) {
    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'None',
    };
    const cookieOptionsJsAccessible = { // Für CSRF, da es auch JS-zugänglich sein muss
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'None',
    };

    res.clearCookie('token', cookieOptions);
    // Beachten Sie den Pfad für den Refresh-Token, falls er spezifisch ist
    res.clearCookie('refreshToken', { ...cookieOptions, path: '/api/refresh' });
    res.clearCookie('csrf', cookieOptionsJsAccessible);
}

// Middleware, die nur Admin-Zugriff erlaubt
function adminOnlyMiddleware(req, res, next) {
    // Annahme: req.user wird von einer vorherigen Authentifizierungs-Middleware gesetzt
    if (!req.user || req.user.rolle !== 'admin') {
        return sendError(res, 403, 'Adminrechte erforderlich');
    }
    next();
}

// Funktion zum Abrufen eines Benutzers nach ID
async function getUserById(id) {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return result.rows[0];
}

// --- DB-Abfragen für QR-Passwort ---
// Ruft das QR-Passwort aus der Datenbank ab.
async function getQrPassword() {
    const result = await pool.query(`SELECT value FROM settings WHERE key = 'qr_password'`);
    if (result.rows.length === 0) {
        throw new Error('QR-Passwort nicht in der Datenbank gefunden!');
    }
    const pw = result.rows[0].value;
    console.log('QR-Passwort aus DB (mit Länge):', `"${pw}"`, pw.length);
    return pw;
}



// Setzt oder aktualisiert das QR-Passwort in der Datenbank.
async function setQrPassword(newPassword) {
    await pool.query(
        `INSERT INTO settings (key, value) VALUES ('qr_password', $1)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
        [newPassword]
    );
}

// --- Cron Job für Token-Cleanup ---
// Dieser Cron Job läuft jede Minute ('*/1 * * * *') und löscht abgelaufene Tokens aus der 'active_tokens'-Tabelle.
// Es wurde auf '*/1 * * * *' geändert, da '*/0 * * * *' nicht valide ist und wahrscheinlich eine Fehlkonfiguration war.
cron.schedule('*/50 * * * *', async () => {
    try {
        await pool.query('DELETE FROM active_tokens WHERE expires_at < NOW()');
        console.log('Cleanup der abgelaufenen Tokens erfolgreich');
    } catch (err) {
        console.error('Fehler beim Cleanup der Tokens:', err);
    }
});


// Verbesserte DB-Initialisierung mit allen notwendigen Tabellen
async function initDb() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                vorname TEXT NOT NULL,
                nachname TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                passwort TEXT NOT NULL,
                rolle TEXT DEFAULT 'user',
                fehlversuche INTEGER DEFAULT 0,
                gesperrt_bis TIMESTAMP,
                biometric_enabled BOOLEAN DEFAULT FALSE
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS zeiten (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                aktion TEXT NOT NULL,
                zeit TIMESTAMP NOT NULL
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS active_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                jti UUID UNIQUE NOT NULL, -- JWT ID für Token-Invalidierung
                issued_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                id UUID PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                credential_id TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                counter INTEGER DEFAULT 0,
                transports TEXT[],
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        `);

        // Überprüfen und Einfügen des Standard-QR-Passworts, wenn nicht vorhanden
        const res = await pool.query(`SELECT 1 FROM settings WHERE key = 'qr_password'`);
        if (res.rowCount === 0) {
            let pw = 'SIR2025!'; // Standard-Passwort
            try {
                // Versucht, das Passwort aus einer Datei zu lesen, falls vorhanden
                pw = (await fs.promises.readFile(path.join(__dirname, 'qr-passwort.txt'), 'utf8')).trim();
            } catch (e) {
                console.warn('qr-passwort.txt nicht gefunden, Standardwert wird gesetzt.');
            }
            await pool.query(`INSERT INTO settings(key, value) VALUES('qr_password', $1)`, [pw]);
            console.log('QR-Passwort initialisiert.');
        }

        console.log('✅ Tabellen erfolgreich erstellt oder geprüft und QR-Passwort initialisiert.');
    } catch (err) {
        console.error('❌ Fehler beim Erstellen der Tabellen:', err);
        process.exit(1); // Anwendung beenden, wenn DB-Initialisierung fehlschlägt
    }
}

// Datenbank-Initialisierung beim Start aufrufen
initDb();

// --- API-Routen ---

// Route zur Validierung des QR-Codes
app.post('/api/validate-qr', async (req, res) => {
  const { qr } = req.body;
  if (!qr) return sendError(res, 400, 'QR fehlt');
  try {
    const gespeichertesPasswort = await getQrPassword();

    console.log('🔍 Vergleich:', `"${qr}"`,'vs.',`"${gespeichertesPasswort}"`);
    console.log('Längen:', qr.length, gespeichertesPasswort.length);
    console.log('Codes:', [...qr].map(c => c.charCodeAt(0)), 'vs', [...gespeichertesPasswort].map(c => c.charCodeAt(0)));

    if (qr === gespeichertesPasswort) {
      return res.json({ valid: true });
    } else {
      return sendError(res, 401, 'Ungültiger QR-Code');
    }
  } catch (err) {
    console.error('Fehler beim QR-Check:', err);
    return sendError(res, 500, 'Serverfehler');
  }
});



// Route zum Setzen des QR-Passworts (Admin-Zugriff erforderlich)
app.post('/api/set-qr-passwort', authMiddleware, async (req, res) => {
    // Der authMiddleware sollte req.user.rolle setzen.
    // Falls authMiddleware nicht als AdminOnlyMiddleware fungiert, müsste hier eine zusätzliche Prüfung erfolgen.
    if (!req.user || req.user.rolle !== 'admin') {
        return sendError(res, 403, 'Adminrechte erforderlich');
    }

    const { neuesPasswort } = req.body;
    if (!neuesPasswort || neuesPasswort.length < 6) {
        return sendError(res, 400, 'Ungültiges Passwort (mindestens 6 Zeichen).');
    }

    try {
        await setQrPassword(neuesPasswort.trim());
        return res.json({ success: true, message: 'QR-Passwort erfolgreich aktualisiert.' });
    } catch (err) {
        console.error('Fehler beim Setzen des QR-Passworts:', err);
        return sendError(res, 500, 'Serverfehler.');
    }
});


// Route zur Benutzerregistrierung
app.post('/api/register', async (req, res) => {
    const { vorname, nachname, email, passwort } = req.body;

    if (!vorname || !nachname || !email || !passwort) {
        return sendError(res, 400, 'Alle Felder sind Pflicht.');
    }

    // Passwort-Regeln: min 8 Zeichen, mindestens 1 Großbuchstabe, mindestens 1 Zahl
    if (
        passwort.length < 8 ||
        !/[A-Z]/.test(passwort) ||
        !/[0-9]/.test(passwort)
    ) {
        return sendError(
            res,
            400,
            'Passwort muss mindestens 8 Zeichen lang sein, eine Zahl und einen Großbuchstaben enthalten.'
        );
    }

    // E-Mail-Validierung
    if (!istGueltigeEmail(email)) {
        return sendError(res, 400, 'Ungültige E-Mail-Adresse.');
    }

    try {
        const hashedPassword = await bcrypt.hash(passwort, SALT_ROUNDS);
        const result = await pool.query(
            `INSERT INTO users(vorname, nachname, email, passwort) VALUES($1, $2, $3, $4) RETURNING id`,
            [vorname, nachname, email, hashedPassword]
        );

        res.json({ success: true, id: result.rows[0].id, message: 'Registrierung erfolgreich!' });
    } catch (err) {
        // PostgreSQL Fehlercode für unique violation (E-Mail bereits vergeben)
        if (err.code === '23505') {
            return sendError(res, 409, 'E-Mail-Adresse bereits vergeben.');
        }
        console.error('Fehler bei der Registrierung:', err);
        return sendError(res, 500, 'Serverfehler bei der Registrierung.');
    }
});

// Route für den normalen Login
app.post('/api/login', loginLimiter, async (req, res) => {
    // Alte Cookies löschen (um sicherzustellen, dass keine alten Tokens im Umlauf sind)
    clearAuthCookies(res);

    const { email, passwort } = req.body;
    if (!email || !passwort) return sendError(res, 400, 'Alle Felder sind Pflicht.');

    try {
        const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
        const user = result.rows[0];
        if (!user) return sendError(res, 401, 'Nutzer nicht gefunden.');

        // Konto gesperrt?
        if (user.gesperrt_bis && new Date(user.gesperrt_bis) > new Date()) {
            const minuten = Math.ceil((new Date(user.gesperrt_bis).getTime() - new Date().getTime()) / 60000);
            return sendError(res, 403, `Konto gesperrt. Versuche es in ${minuten} Minuten.`);
        }

        const match = await bcrypt.compare(passwort, user.passwort);
        if (!match) {
            // Passwort falsch: Fehlversuche erhöhen und ggf. sperren
            const neueFehlversuche = user.fehlversuche + 1;
            const istGesperrt = neueFehlversuche >= 5;
            const sperrzeit = istGesperrt ? new Date(Date.now() + 15 * 60 * 1000) : null; // 15 Min Sperre

            await pool.query(
                `UPDATE users SET fehlversuche = $1, gesperrt_bis = $2 WHERE id = $3`,
                [neueFehlversuche, sperrzeit, user.id]
            );

            return sendError(
                res,
                401,
                istGesperrt ? 'Zu viele Fehlversuche. Konto gesperrt für 15 Minuten.' : 'Falsches Passwort.'
            );
        }

        // Login erfolgreich: Fehlversuche zurücksetzen
        await pool.query(`UPDATE users SET fehlversuche = 0, gesperrt_bis = NULL WHERE id = $1`, [user.id]);

        const issuedAt = Math.floor(Date.now() / 1000);
        const expiresAt = issuedAt + 15 * 60; // Access Token gültig für 15 Minuten
        const jti = uuidv4(); // Einzigartige JWT-ID für den Access Token

        // Access Token erstellen
        const accessToken = jwt.sign(
            { id: user.id, rolle: user.rolle, jti, iat: issuedAt, nbf: issuedAt },
            JWT_SECRET,
            { expiresIn: '15m', issuer: process.env.JWT_ISSUER }
        );

        // Refresh Token erstellen
        const refreshToken = jwt.sign(
            { userId: user.id },
            REFRESH_SECRET,
            { expiresIn: '7d' } // Refresh Token gültig für 7 Tage
        );

        // Access Token in active_tokens Tabelle speichern (für Invalidierung)
        await pool.query(
            `INSERT INTO active_tokens(token, user_id, jti, issued_at, expires_at) VALUES($1, $2, $3, to_timestamp($4), to_timestamp($5))`,
            [accessToken, user.id, jti, issuedAt, expiresAt]
        );

        // Abgelaufene Active Tokens bereinigen
        await pool.query(`DELETE FROM active_tokens WHERE expires_at < NOW()`);

        // Refresh Token in refresh_tokens Tabelle speichern
        const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 Tage in Millisekunden
        await pool.query(
            `INSERT INTO refresh_tokens(user_id, token, expires_at) VALUES($1, $2, $3)`,
            [user.id, refreshToken, refreshExpiresAt]
        );

        const csrfToken = crypto.randomBytes(32).toString('hex'); // CSRF Token generieren

        // Cookies setzen
        setAuthCookies(res, accessToken, csrfToken); // Verwendet die Hilfsfunktion

        // Refresh Token als HttpOnly-Cookie setzen, mit spezifischem Pfad
    res.cookie('refreshToken', refreshToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'None',
  path: '/',
  maxAge: 7 * 24 * 60 * 60 * 1000,
});



        res.json({ message: 'Login erfolgreich', csrfToken });
    } catch (err) {
        console.error('Login Error:', err);
        sendError(res, 500, 'Interner Serverfehler beim Login.');
    }
});


// Route für die Benutzerinformationen
// HINWEIS: 'authenticateToken' ist hier ein Platzhalter und muss definiert/importiert werden.
// Ich nehme an, es ist die gleiche wie 'authMiddleware'.
app.get('/api/me', authMiddleware, async (req, res) => {
    // req.user wird von authMiddleware gesetzt
    const userId = req.user.id;
    // getUserById ist oben definiert
    const user = await getUserById(userId);
    if (!user) return sendError(res, 404, 'User not found');

    res.json({
        id: user.id, // ID des Benutzers
        vorname: user.vorname,
        nachname: user.nachname,
        email: user.email,
        rolle: user.rolle,
        biometricEnabled: user.biometric_enabled, // Sicher aus DB gelesen
    });
});


// Logout (Access + Refresh + Cookies löschen)
app.post('/api/logout', authMiddleware, async (req, res) => {
    try {
        // Access Token aus active_tokens löschen, falls vorhanden
        if (req.jti) { // req.jti wird von authMiddleware gesetzt
            await pool.query('DELETE FROM active_tokens WHERE jti = $1', [req.jti]);
        }

        // Refresh-Token aus Cookie löschen und aus DB entfernen
        const refreshToken = req.cookies.refreshToken;
        if (refreshToken) {
            await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
        }

        // Alle relevanten Cookies sicher löschen
        clearAuthCookies(res);

        res.json({ message: 'Logout erfolgreich' });
    } catch (err) {
        console.error('Logout Error:', err);
        sendError(res, 500, 'Fehler beim Logout');
    }
});


// Route zum Ändern des Passworts
app.post('/change-password', authMiddleware, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const user = await getUserById(req.user.id); // req.user.id von authMiddleware

    if (!user) { // Sollte nicht passieren, wenn authMiddleware funktioniert
        return sendError(res, 404, 'Benutzer nicht gefunden.');
    }

    const match = await bcrypt.compare(oldPassword, user.passwort);
    if (!match) {
        return sendError(res, 403, 'Altes Passwort ist falsch');
    }

    // Passwort-Regeln: min 8, mindestens 1 Großbuchstabe, mindestens 1 Zahl
    if (
        newPassword.length < 8 ||
        !/[A-Z]/.test(newPassword) ||
        !/[0-9]/.test(newPassword)
    ) {
        return sendError(
            res,
            400,
            'Passwort muss mindestens 8 Zeichen lang sein, eine Zahl und einen Großbuchstaben enthalten.'
        );
    }

    const hashed = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await pool.query(
        'UPDATE users SET passwort = $1 WHERE id = $2',
        [hashed, req.user.id]
    );
    res.json({ success: true, message: 'Passwort erfolgreich aktualisiert.' });
});


// Auth Middleware: Prüft Access Token in Cookies oder Authorization-Header
async function authMiddleware(req, res, next) {
    try {
        let token;

        // Versucht, Token aus HttpOnly-Cookie zu lesen
        if (req.cookies?.token) {
            token = req.cookies.token;
        }
        // Fallback: Versucht, Token aus Authorization-Header zu lesen (Bearer Token)
        else if (req.headers.authorization?.startsWith('Bearer ')) {
            token = req.headers.authorization.slice(7);
        }

        if (!token) {
            return sendError(res, 401, 'Kein Token gefunden');
        }

        // Token verifizieren
        const payload = jwt.verify(token, JWT_SECRET);

        // Prüfe, ob Token jti (JWT ID) in active_tokens existiert (für Invalidierung)
        const jti = payload.jti;
        if (!jti) {
            return sendError(res, 401, 'Token ohne jti');
        }

        const dbRes = await pool.query('SELECT 1 FROM active_tokens WHERE jti = $1', [jti]);
        if (dbRes.rowCount === 0) {
            return sendError(res, 401, 'Token nicht aktiv oder abgelaufen');
        }

        req.user = payload; // Fügt Benutzerdaten zum Request-Objekt hinzu
        req.token = token;
        req.jti = jti; // Fügt JWT ID zum Request-Objekt hinzu
        next(); // Weiter zur nächsten Middleware/Route
    } catch (err) {
        console.error('Auth Middleware Error:', err);
        return sendError(res, 401, 'Token ungültig oder abgelaufen');
    }
}

// CSRF Middleware: Prüft CSRF-Token in Cookies und Headern
function csrfMiddleware(req, res, next) {
    // Nur für POST, PUT, DELETE prüfen
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }

    const csrfCookie = req.cookies?.csrf;
    const csrfHeader = req.headers['x-csrf-token'];

    if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
        return sendError(res, 403, 'CSRF-Token fehlt oder stimmt nicht überein');
    }
    next();
}


// Joi Schema für Zeitstempel-Aktionen
const zeitSchema = Joi.object({
    aktion: Joi.string().valid('start', 'stop', 'pause', 'resume').required(),
});

// Admin-Login-Route
app.post('/api/admin-login', loginLimiter, async (req, res) => {
    clearAuthCookies(res); // Alte Cookies löschen

    const { email, passwort } = req.body;
    if (!email || !passwort) {
        return sendError(res, 400, 'Alle Felder sind Pflicht.');
    }

    try {
        const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
        const user = result.rows[0];

        // Prüfen, ob Benutzer existiert und Admin-Rolle hat
        if (!user || user.rolle !== 'admin') {
            // Um Brute-Force-Angriffe auf Admin-Accounts zu erschweren,
            // geben wir hier keine genaue Auskunft darüber, ob der User existiert,
            // sondern nur, dass der Zugriff nicht erlaubt ist.
            return sendError(res, 403, 'Zugriff verweigert.');
        }

        // Konto gesperrt?
        if (user.gesperrt_bis && new Date(user.gesperrt_bis) > new Date()) {
            const minuten = Math.ceil((new Date(user.gesperrt_bis).getTime() - new Date().getTime()) / 60000);
            return sendError(res, 403, `Konto gesperrt. Noch ${minuten} Minuten.`);
        }

        const match = await bcrypt.compare(passwort, user.passwort);
        if (!match) {
            // Passwort falsch: Fehlversuche erhöhen und ggf. sperren
            const neueFehlversuche = user.fehlversuche + 1;
            const istGesperrt = neueFehlversuche >= 5;
            const sperrzeit = istGesperrt ? new Date(Date.now() + 15 * 60 * 1000) : null;

            await pool.query(
                `UPDATE users SET fehlversuche = $1, gesperrt_bis = $2 WHERE id = $3`,
                [neueFehlversuche, sperrzeit, user.id]
            );

            return sendError(
                res,
                401,
                istGesperrt
                    ? 'Zu viele Fehlversuche. Konto gesperrt für 15 Minuten.'
                    : 'Falsches Passwort.'
            );
        }

        // Login erfolgreich: Fehlversuche zurücksetzen
        await pool.query(`UPDATE users SET fehlversuche = 0, gesperrt_bis = NULL WHERE id = $1`, [user.id]);

        const issuedAt = Math.floor(Date.now() / 1000);
        const expiresAt = issuedAt + 15 * 60; // Access Token gültig für 15 Minuten
        const jti = uuidv4(); // Einzigartige JWT-ID

        const accessToken = jwt.sign(
            { id: user.id, rolle: user.rolle, iat: issuedAt, nbf: issuedAt, jti },
            JWT_SECRET,
            { expiresIn: '15m', issuer: process.env.JWT_ISSUER }
        );

        const refreshToken = jwt.sign(
            { userId: user.id },
            REFRESH_SECRET,
            { expiresIn: '7d' } // Refresh Token gültig für 7 Tage
        );

        // Access Token in active_tokens Tabelle speichern
        await pool.query(
            `INSERT INTO active_tokens(token, user_id, issued_at, expires_at, jti) VALUES($1, $2, to_timestamp($3), to_timestamp($4), $5)`,
            [accessToken, user.id, issuedAt, expiresAt, jti]
        );

        // Abgelaufene Active Tokens bereinigen
        await pool.query(`DELETE FROM active_tokens WHERE expires_at < NOW()`);

        // Refresh Token in refresh_tokens Tabelle speichern
        const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        await pool.query(
            `INSERT INTO refresh_tokens(user_id, token, expires_at) VALUES($1, $2, $3)`,
            [user.id, refreshToken, refreshExpiresAt]
        );

        const csrfToken = crypto.randomBytes(32).toString('hex'); // CSRF Token generieren

        // Cookies setzen
       res.cookie('token', accessToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'None',
  maxAge: 15 * 60 * 1000,
});

        res.cookie('refreshToken', refreshToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'None',
  path: '/',
  maxAge: 7 * 24 * 60 * 60 * 1000,
});
        res.cookie('csrf', csrfToken, {
            httpOnly: false, // Für Client-Zugriff
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'None',
            maxAge: 15 * 60 * 1000, // 15 Minuten
        });

        res.json({ message: 'Admin-Login erfolgreich', csrfToken });

    } catch (err) {
        console.error('Admin Login Error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// Beispiel für geschützte Admin-Route
app.post('/api/admin/irgendwas', authMiddleware, csrfMiddleware, adminOnlyMiddleware, (req, res) => {
    res.json({ message: 'Admin-Aktion erfolgreich ausgeführt.' });
});

// Route für Zeitstempel-Aktionen (Start, Stop, Pause, Resume)
app.post('/api/zeit', authMiddleware, csrfMiddleware, async (req, res) => {
    // Nur normale Benutzer dürfen Zeitstempel setzen
    if (req.user.rolle !== 'user')
        return sendError(res, 403, 'Nur für normale Nutzer erlaubt.');

    // Validierung der Aktion
    const { error, value } = zeitSchema.validate(req.body);
    if (error) {
        return sendError(res, 400, 'Ungültige Eingabe: ' + error.details[0].message);
    }

    const { aktion } = value;
    const serverZeit = new Date(); // Aktuelle Serverzeit verwenden (UTC)

    try {
        const result = await pool.query(
            `INSERT INTO zeiten(user_id, aktion, zeit) VALUES($1, $2, $3) RETURNING id`,
            [req.user.id, aktion, serverZeit]
        );
        res.json({ success: true, id: result.rows[0].id, zeit: serverZeit, message: 'Zeitstempel erfolgreich gesetzt.' });
    } catch (err) {
        console.error('Fehler beim Setzen des Zeitstempels:', err);
        sendError(res, 500, 'Serverfehler beim Setzen des Zeitstempels.');
    }
});

// GET /api/zeit/letzter-status
// Ruft den letzten Zeitstempel-Status eines Benutzers ab.
router.get('/api/zeit/letzter-status', authMiddleware, async (req, res) => {


    try {
        const userId = req.user.id;

        // Hole die letzte Aktion des Users
        const result = await pool.query(
            'SELECT aktion, zeit FROM zeiten WHERE user_id = $1 ORDER BY zeit DESC LIMIT 1',
            [userId]
        );

        if (result.rowCount === 0) {
            return res.json({ eingestempelt: false, letzteAktion: null, message: 'Keine Zeitstempel gefunden.' });
        }

        const letzteAktion = result.rows[0].aktion;

        // Eingestempelt? -> Wenn letzte Aktion 'start' oder 'resume', gilt als eingestempelt
        const eingestempelt = ['start', 'resume'].includes(letzteAktion);

        res.json({ eingestempelt, letzteAktion, message: 'Letzter Status erfolgreich abgerufen.' });
    } catch (err) {
        console.error('Fehler bei /api/zeit/letzter-status:', err);
        sendError(res, 500, 'Interner Serverfehler.');
    }
});

// Beispiel für geschützte Route mit CSRF-Schutz
app.post('/api/sichere-aktion', authMiddleware, csrfMiddleware, async (req, res) => {
    res.json({ message: 'Aktion erfolgreich ausgeführt.' });
});


// Refresh Token Endpoint
app.post('/api/refresh', async (req, res) => {
    // Der Origin-Check ist wichtig, um sicherzustellen, dass nur erlaubte Clients Tokens anfordern.
    const allowedOrigin = process.env.CORS_ORIGIN;
    const origin = req.get('Origin');
    if (!origin || origin !== allowedOrigin) {
        return sendError(res, 403, 'Ungültiger Origin');
    }

    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return sendError(res, 401, 'Kein Refresh-Token gefunden.');

    try {
        // Refresh Token in der Datenbank prüfen und Verfallsdatum checken
        const result = await pool.query(
            `SELECT * FROM refresh_tokens WHERE token = $1 AND expires_at > NOW()`,
            [refreshToken]
        );

        const entry = result.rows[0];
        if (!entry) {
            clearAuthCookies(res); // Ungültigen Refresh Token löschen
            return sendError(res, 403, 'Ungültiger oder abgelaufener Refresh-Token.');
        }

        // Benutzerdetails für den neuen Access Token abrufen
        const userResult = await pool.query(
            `SELECT id, rolle FROM users WHERE id = $1`,
            [entry.user_id]
        );
        const user = userResult.rows[0];
        if (!user) {
            clearAuthCookies(res); // Ungültige User-ID im Refresh Token
            return sendError(res, 403, 'Benutzer nicht gefunden.');
        }

        const issuedAt = Math.floor(Date.now() / 1000);
        const expiresAt = issuedAt + 15 * 60; // 15 Minuten Gültigkeit für den neuen Access Token

        const jti = uuidv4(); // Neue, eindeutige Token-ID für den Access Token

        // Neuen Access Token erstellen
        const newAccessToken = jwt.sign(
            {
                id: user.id,
                rolle: user.rolle,
                jti,
                iat: issuedAt,
                nbf: issuedAt
            },
            JWT_SECRET,
            { expiresIn: '15m', issuer: process.env.JWT_ISSUER }
        );

        // Alte Access Tokens bereinigen
        await pool.query(`DELETE FROM active_tokens WHERE expires_at < NOW()`);

        // Neue Token-ID in DB speichern
        await pool.query(
            `INSERT INTO active_tokens(token, user_id, jti, issued_at, expires_at)
             VALUES ($1, $2, $3, to_timestamp($4), to_timestamp($5))`,
            [newAccessToken, user.id, jti, issuedAt, expiresAt]
        );

        // Neuen Access Token als HttpOnly-Cookie setzen
        res.cookie('token', newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'None',
            maxAge: 15 * 60 * 1000,
        });

        res.json({ success: true, message: 'Access Token erfolgreich erneuert.' });
    } catch (err) {
        console.error('Fehler beim Token-Refresh:', err);
        clearAuthCookies(res); // Bei Fehlern alle Cookies löschen, um Sicherheit zu gewährleisten
        sendError(res, 500, 'Fehler beim Token-Refresh.');
    }
});

// zeiten abrufen (Admin)
app.get('/api/zeiten', authMiddleware, csrfMiddleware, adminOnlyMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT z.id, u.vorname, u.nachname, z.aktion, z.zeit
            FROM zeiten z
            JOIN users u ON z.user_id = u.id
            ORDER BY z.zeit DESC
        `);
        res.json(result.rows);
    } catch (err) {
        console.error('Fehler beim Abrufen der Zeiten:', err);
        sendError(res, 500, 'Serverfehler beim Abrufen der Zeiten.');
    }
});

// Admin-Funktion: Benutzerrolle ändern (AdminOnly)
app.post('/set-admin', authMiddleware, csrfMiddleware, adminOnlyMiddleware, async (req, res) => {
    try {
        const requester = await getUserById(req.user.id);
        if (!requester || requester.rolle !== 'admin') {
            return sendError(res, 403, 'Nicht erlaubt'); // Doppelte Prüfung, sollte von adminOnlyMiddleware abgefangen werden
        }

        const { userId: targetUserId, isAdmin } = req.body; // Umbenennung, um Konflikt zu vermeiden

        // Eingabe validieren
        if (typeof isAdmin !== 'boolean' || typeof targetUserId !== 'number') {
            return sendError(res, 400, 'Ungültige Eingabedaten für UserId oder isAdmin.');
        }

        // Admin kann sich nicht selbst ent-administrieren
        if (req.user.id === targetUserId && !isAdmin) {
            return sendError(res, 400, 'Du kannst dich nicht selbst ent-administrieren.');
        }

        // Prüfen, ob der Ziel-Benutzer existiert
        const result = await pool.query('SELECT id FROM users WHERE id = $1', [targetUserId]);
        if (result.rowCount === 0) {
            return sendError(res, 404, 'Nutzer nicht gefunden.');
        }

        const neueRolle = isAdmin ? 'admin' : 'user';

        await pool.query(
            'UPDATE users SET rolle = $1 WHERE id = $2',
            [neueRolle, targetUserId]
        );

        res.json({ success: true, message: 'Rolle erfolgreich aktualisiert.' });
    } catch (err) {
        console.error('Fehler in /set-admin:', err);
        sendError(res, 500, 'Serverfehler beim Aktualisieren der Rolle.');
    }
});

// Benutzerliste abrufen (Admin)
app.get('/api/users', authMiddleware, csrfMiddleware, adminOnlyMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, vorname, nachname, email, rolle FROM users');
        res.json(result.rows);
    } catch (err) {
        console.error('Fehler beim Abrufen der Benutzerliste:', err);
        sendError(res, 500, 'Serverfehler beim Abrufen der Benutzerliste.');
    }
});

// Zeitstempel filtern (Admin)
app.get('/api/zeiten/filter', authMiddleware, csrfMiddleware, adminOnlyMiddleware, async (req, res) => {
    const { start, ende } = req.query;

    // Basisvalidierung der Datumsangaben
    if (!start || !ende || isNaN(Date.parse(start)) || isNaN(Date.parse(ende))) {
        return sendError(res, 400, 'Ungültiger Zeitraum. Bitte Start- und Enddatum im gültigen Format angeben.');
    }

    try {
        const result = await pool.query(
            `SELECT z.id, u.vorname, u.nachname, z.aktion, z.zeit
             FROM zeiten z
             JOIN users u ON z.user_id = u.id
             WHERE z.zeit BETWEEN $1 AND $2
             ORDER BY z.zeit DESC`,
            [start, ende]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Fehler beim Filtern der Zeiten:', err);
        sendError(res, 500, 'Serverfehler beim Filtern der Zeiten.');
    }
});

// Manuellen Zeitstempel hinzufügen (Admin)
app.post('/api/zeit/manuell', authMiddleware, csrfMiddleware, adminOnlyMiddleware, async (req, res) => {
    const { user_id, aktion, zeit } = req.body;

    // Eingabevalidierung
    if (!user_id || !['start', 'stop', 'pause', 'resume'].includes(aktion) || isNaN(Date.parse(zeit))) {
        return sendError(res, 400, 'Ungültige Eingabedaten. Benötigt user_id (Zahl), aktion (start/stop/pause/resume) und zeit (gültiges Datum).');
    }

    try {
        const result = await pool.query(
            `INSERT INTO zeiten (user_id, aktion, zeit) VALUES ($1, $2, $3) RETURNING id`,
            [user_id, aktion, zeit]
        );
        res.json({ success: true, id: result.rows[0].id, message: 'Manueller Zeitstempel erfolgreich hinzugefügt.' });
    } catch (err) {
        console.error('Fehler beim Hinzufügen manueller Zeitstempel:', err);
        sendError(res, 500, 'Serverfehler beim Hinzufügen manueller Zeitstempel.');
    }
});

// Zeitstempel aktualisieren (Admin)
app.put('/api/zeit/:id', authMiddleware, csrfMiddleware, adminOnlyMiddleware, async (req, res) => {
    const { id } = req.params;
    const { aktion, zeit } = req.body;

    // Eingabevalidierung für Update
    if (!['start', 'stop', 'pause', 'resume'].includes(aktion) || isNaN(Date.parse(zeit))) {
        return sendError(res, 400, 'Ungültige Eingabedaten für Update. Benötigt aktion (start/stop/pause/resume) und zeit (gültiges Datum).');
    }

    try {
        const result = await pool.query(
            `UPDATE zeiten SET aktion = $1, zeit = $2 WHERE id = $3 RETURNING id`,
            [aktion, zeit, id]
        );
        if (result.rowCount === 0) {
            return sendError(res, 404, 'Zeitstempel nicht gefunden.');
        }
        res.json({ success: true, message: 'Zeitstempel erfolgreich aktualisiert.' });
    } catch (err) {
        console.error('Fehler beim Aktualisieren des Zeitstempels:', err);
        sendError(res, 500, 'Serverfehler beim Aktualisieren des Zeitstempels.');
    }
});

// Zeitstempel löschen (Admin)
app.delete('/api/zeit/:id', authMiddleware, csrfMiddleware, adminOnlyMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(`DELETE FROM zeiten WHERE id = $1 RETURNING id`, [id]);
        if (result.rowCount === 0) {
            return sendError(res, 404, 'Zeitstempel nicht gefunden.');
        }
        res.json({ success: true, message: 'Zeitstempel erfolgreich gelöscht.' });
    } catch (err) {
        console.error('Fehler beim Löschen des Zeitstempels:', err);
        sendError(res, 500, 'Serverfehler beim Löschen des Zeitstempels.');
    }
});

// Benutzer löschen (Admin)
app.delete('/api/user/:id', authMiddleware, csrfMiddleware, adminOnlyMiddleware, async (req, res) => {
    const idToDelete = parseInt(req.params.id, 10);

    // Admin kann sich nicht selbst löschen
    if (req.user.id === idToDelete) {
        return sendError(res, 400, 'Du kannst dich nicht selbst löschen.');
    }

    try {
        // Zuerst alle abhängigen Zeitstempel und Tokens löschen
        await pool.query(`DELETE FROM zeiten WHERE user_id = $1`, [idToDelete]);
        await pool.query(`DELETE FROM active_tokens WHERE user_id = $1`, [idToDelete]);
        await pool.query(`DELETE FROM refresh_tokens WHERE user_id = $1`, [idToDelete]);
        await pool.query(`DELETE FROM webauthn_credentials WHERE user_id = $1`, [idToDelete]);

        // Dann den Benutzer löschen
        const result = await pool.query(`DELETE FROM users WHERE id = $1 RETURNING id`, [idToDelete]);
        if (result.rowCount === 0) {
            return sendError(res, 404, 'Benutzer nicht gefunden.');
        }
        res.json({ success: true, message: 'Benutzer erfolgreich gelöscht.' });
    } catch (err) {
        console.error('Fehler beim Löschen des Benutzers:', err);
        sendError(res, 500, 'Serverfehler beim Löschen des Benutzers.');
    }
});


// --- WebAuthn Registrierung (Step 1: Challenge erstellen) ---
const rpName = 'Zeiterfassung';
const rpID = 'localhost'; // Für die lokale Entwicklung, in Produktion auf die echte Domain ändern (z.B. 'meinedomain.de')
const origin = process.env.CORS_ORIGIN; // Nutze CORS_ORIGIN für die Origin

// Challenge-Speicher (in Produktion Redis oder eine Datenbank verwenden, hier für Einfachheit eine Map)
const challengeMap = new Map();

app.post('/api/webauthn/register-request', async (req, res) => {
    const { userId } = req.body;
    if (!userId) return sendError(res, 400, 'User-ID fehlt');

    try {
        const result = await pool.query('SELECT email, vorname, nachname FROM users WHERE id = $1', [userId]);
        const user = result.rows[0];
        if (!user) return sendError(res, 404, 'Benutzer nicht gefunden');

        const userName = `${user.vorname} ${user.nachname}`;

        const registrationOptions = generateRegistrationOptions({
            rpName,
            rpID,
            userID: `${userId}`, // userID muss ein String sein
            userName,
            timeout: 60000, // 60 Sekunden Timeout
            attestationType: 'none', // Keine Attestierungsinformationen vom Authenticator
            authenticatorSelection: {
                residentKey: 'preferred', // Bevorzugt Resident Keys (Passkeys)
                userVerification: 'preferred', // Bevorzugt Benutzerverifikation (PIN, Biometrie)
            },
            supportedAlgorithmIDs: [-7, -257], // ES256, RS256
        });

        // Speichern der Challenge für die spätere Verifikation
        challengeMap.set(userId, registrationOptions.challenge);

        res.json(registrationOptions);
    } catch (err) {
        console.error('Register Request Error:', err);
        sendError(res, 500, 'Interner Fehler bei Registrierungsanfrage.');
    }
});

// WebAuthn Registrierung (Step 2: Antwort verifizieren und Credential speichern)
app.post('/api/webauthn/register-response', async (req, res) => {
    const { userId, credential } = req.body;
    if (!userId || !credential) return sendError(res, 400, 'Fehlende Daten');

    const expectedChallenge = challengeMap.get(userId);
    if (!expectedChallenge) return sendError(res, 400, 'Keine Challenge vorhanden oder abgelaufen.');

    try {
        const verification = await verifyRegistrationResponse({
            response: credential,
            expectedChallenge: `${expectedChallenge}`, // Challenge muss ein String sein
            expectedOrigin: origin,
            expectedRPID: rpID,
        });

        const { verified, registrationInfo } = verification;
        if (!verified) return sendError(res, 400, 'WebAuthn-Antwort ungültig.');

        const { credentialPublicKey, credentialID, counter, transports } = registrationInfo;

        // Speichern der WebAuthn-Credential-Informationen in der Datenbank
        await pool.query(
            `INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, counter, transports)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (credential_id) DO UPDATE SET public_key = EXCLUDED.public_key, counter = EXCLUDED.counter, transports = EXCLUDED.transports`,
            [uuidv4(), userId, base64url.encode(credentialID), base64url.encode(credentialPublicKey), counter, transports]
        );

        // Biometrische Anmeldung für den Benutzer aktivieren
        await pool.query(
            `UPDATE users SET biometric_enabled = TRUE WHERE id = $1`,
            [userId]
        );

        challengeMap.delete(userId); // Challenge nach Gebrauch entfernen
        res.json({ success: true, message: 'WebAuthn-Registrierung erfolgreich!' });
    } catch (err) {
        console.error('Register Response Error:', err);
        sendError(res, 500, 'Interner Fehler bei der WebAuthn-Registrierung.');
    }
});

// --- Server starten ---
// Der Server wird bedingt gestartet: entweder HTTPS (lokal, wenn Zertifikate da sind) oder HTTP (Produktion/Fallback).
const PORT = process.env.PORT || 3000;

// Prüfen, ob die App in Produktion läuft (z.B. auf Render)
const isProduction = process.env.NODE_ENV === 'production' || process.env.RENDER === 'true';

if (isProduction) {
    // In Produktion (Render, Heroku etc.) wird der Server einfach über HTTP gestartet,
    // da der Hosting-Anbieter das HTTPS-Handling übernimmt.
    http.createServer(app).listen(PORT, () => {
        console.log(`🚀 HTTP Server läuft auf Port ${PORT} (Produktions-Modus - HTTPS über Proxy)`);
    });
} else {
    // Lokale Entwicklung: Versuche HTTPS zu starten, Fallback auf HTTP bei fehlenden Zertifikaten
    const privateKeyPath = path.join(__dirname, 'ssl', 'privkey.pem');
    const certificatePath = path.join(__dirname, 'ssl', 'fullchain.pem'); // Oder 'cert.pem'

    try {
        const sslOptions = {
            key: fs.readFileSync(privateKeyPath),
            cert: fs.readFileSync(certificatePath),
        };
        https.createServer(sslOptions, app).listen(PORT, () => {
            console.log(`🚀 HTTPS Server läuft auf Port ${PORT} (lokal)`);
        });
    } catch (error) {
        console.warn(`⚠️ WARNUNG: Konnte SSL-Zertifikate nicht laden (${error.message}).`);
        console.warn(`⚠️ Starte stattdessen HTTP-Server auf Port ${PORT}.`);
        http.createServer(app).listen(PORT, () => {
            console.log(`🚀 HTTP Server läuft auf Port ${PORT} (lokaler Fallback)`);
        });
    }
}
