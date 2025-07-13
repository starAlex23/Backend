// --- Umgebungsvariablen laden ---
import 'dotenv/config';
const REFRESH_SECRET = process.env.REFRESH_SECRET;
// --- Externe Abhängigkeiten ---
import express from 'express';
import { Pool } from 'pg';
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
import cors from 'cors';
// --- Eigene Module (mit .js-Endung!) ---
import { REFRESH_TOKEN_SECRET } from './config/env.js';
import { DATABASE_URL } from './config/env.js';
//Zeit auf UTC 2+ umstellversuch
import { DateTime } from 'luxon';
// Als ISO-String für PostgreSQL:
const zeitstempel = DateTime.now().setZone('Europe/Berlin').toISO(); // z. B. 2025-07-07T14:35:00+02:00
// --- ES-Module-kompatibles __dirname ermitteln ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const code = generateSimpleCode(8); // z.B. '4F7G9J2K'
// --- Initialisierung ---
const app = express();
app.set('trust proxy', 1);
// --- Sicherheit: HTTP-Sicherheits-Header ---
app.use(helmet({ contentSecurityPolicy: false }));

app.use(
  helmet.contentSecurityPolicy({
    useDefaults: false, // ← ganz wichtig: keine Default-Blocker!
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        'https://cdn.jsdelivr.net',
        'https://unpkg.com',
      ],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);

app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));
app.use(helmet.permittedCrossDomainPolicies());
app.use(helmet.frameguard({ action: 'sameorigin' }));
app.use(helmet.noSniff());
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
app.disable('x-powered-by');

// --- Manuelle Sicherheits-Header setzen (auch für static/sendFile) ---
app.use((req, res, next) => {
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

// --- Statische Dateien mit Security-Header ---
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res) => {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    res.setHeader("Content-Security-Policy",
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; " +
      "object-src 'none'; " +
      "base-uri 'self'; " +
      "connect-src 'self';"
    );
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "camera=(self)");
  }
}));

const router = express.Router();
export default router;
const SALT_ROUNDS = 12;
const corsOptions = {
  origin: 'https://nochmal-neu.vercel.app', // Frontend-Domain erlauben
  credentials: true,                        // Cookies erlauben
};

app.use(cors(corsOptions));
// --- Umgebungsvariablen validieren ---
// Diese Funktion prüft, ob alle notwendigen Umgebungsvariablen gesetzt sind.
// Wenn eine Variable fehlt oder ungültig ist, wird eine Fehlermeldung ausgegeben und die Anwendung beendet.
function validateEnv() {
    const requiredVars = [
    'DATABASE_URL',
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
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Zeitzone für alle neuen Verbindungen setzen
pool.on('connect', client => {
  client.query(`SET TIME ZONE 'Europe/Berlin'`).catch(err => {
    console.error('❌ Fehler beim Setzen der Zeitzone:', err);
  });
});

app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.url}`);
  next();
});

const JWT_SECRET = process.env.JWT_SECRET;

// express.json() parst eingehende Anfragen mit JSON-Payloads.
app.use(express.json());
// cookieParser parst Cookies aus dem Request-Header.
app.use(cookieParser());

// --- Sichere CORS-Konfiguration ---
// Cross-Origin Resource Sharing (CORS) Einstellungen, um Anfragen von bestimmten Origins zu erlauben.
// 'secure' und 'sameSite: 'None'' sind wichtig für die Verwendung von Cookies über verschiedene Domains hinweg.


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
        secure: true, // Nur über HTTPS senden
        sameSite: 'Lax', // Erlaubt Cross-Site-Verwendung
        maxAge: 24 * 60 * 60 * 1000, // 1 Tag
    };
    const cookieOptionsJsAccessible = {
        httpOnly: false, // Cookie ist über Client-seitiges JavaScript zugänglich (für CSRF-Token)
        secure: true,
        sameSite: 'Lax',
        maxAge: 24 * 60 * 60 * 1000,
    };

    res.cookie('accessToken', token, cookieOptionsHttpOnly);
    res.cookie('csrfToken', csrfToken, cookieOptionsJsAccessible);
}

// Helper: Auth-Cookies löschen (Logout)
function clearAuthCookies(res) {
    const cookieOptions = {
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
    };
    const cookieOptionsJsAccessible = { // Für CSRF, da es auch JS-zugänglich sein muss
        httpOnly: false,
        secure: true,
        sameSite: 'Lax',
    };

    res.clearCookie('token', cookieOptions);
    // Beachten Sie den Pfad für den Refresh-Token, falls er spezifisch ist
    res.clearCookie('refreshToken', { ...cookieOptions, path: '/api/refresh' });
    res.clearCookie('csrfToken', cookieOptionsJsAccessible);
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
app.get('/api/get-qr-passwort', authMiddleware, async (req, res) => {
  if (!req.user || req.user.rolle !== 'admin') {
    return sendError(res, 403, 'Adminrechte erforderlich');
  }

  try {
    const result = await pool.query(`SELECT value FROM settings WHERE key = 'qr_password'`);
    if (result.rows.length === 0) {
      return sendError(res, 404, 'Kein QR-Passwort gefunden.');
    }

    const pw = result.rows[0].value;
    return res.json({ qrPasswort: pw });
  } catch (err) {
    console.error('Fehler beim Abrufen des QR-Passworts:', err);
    return sendError(res, 500, 'Serverfehler.');
  }
});

// Setzt oder aktualisiert das QR-Passwort in der Datenbank.
async function setQrPassword(newPassword) {
    await pool.query(
        `INSERT INTO settings (key, value) VALUES ('qr_password', $1)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
        [newPassword]
    );
}

async function getQrPassword() {
  const result = await pool.query(
    `SELECT value FROM settings WHERE key = 'qr_password'`
  );
  return result.rows[0]?.value || null;
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
    // Zeitzone festlegen für diese Verbindung
    await pool.query(`SET TIME ZONE 'Europe/Berlin'`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        vorname TEXT NOT NULL,
        nachname TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        passwort TEXT NOT NULL,
        rolle TEXT DEFAULT 'user',
        fehlversuche INTEGER DEFAULT 0,
        gesperrt_bis TIMESTAMPTZ,
        biometric_enabled BOOLEAN DEFAULT FALSE,
        ist_eingestempelt BOOLEAN DEFAULT FALSE
      )
    `);

   await pool.query(`
  CREATE TABLE IF NOT EXISTS zeiten (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    aktion TEXT NOT NULL,
    zeit TIMESTAMPTZ NOT NULL
  )
`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )
    `);

    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_name = 'users' AND column_name = 'ist_eingestempelt'
        ) THEN
          ALTER TABLE users ADD COLUMN ist_eingestempelt BOOLEAN DEFAULT FALSE;
        END IF;
      END
      $$;
    `);

    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_name = 'users' AND column_name = 'rolle'
        ) THEN
          ALTER TABLE users ADD COLUMN rolle TEXT NOT NULL DEFAULT 'user';
        END IF;
      END
      $$;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS qr_tokens (
        id SERIAL PRIMARY KEY,
        code TEXT UNIQUE NOT NULL,
        erstellt_von INTEGER REFERENCES users(id) ON DELETE CASCADE,
        erstellt_am TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
        gültig_bis TIMESTAMPTZ NOT NULL
      )
    `);

    // Abgelaufene QR-Codes entfernen
    await pool.query(`DELETE FROM qr_tokens WHERE gültig_bis < NOW()`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS active_tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        jti UUID UNIQUE NOT NULL,
        issued_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL
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
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMPTZ NOT NULL
      )
    `);

   


    // QR-Passwort in settings, falls nicht vorhanden
    const res = await pool.query(`SELECT 1 FROM settings WHERE key = 'qr_password'`);
    if (res.rowCount === 0) {
      let pw = 'SIR2025!';
      try {
        pw = (await fs.promises.readFile(path.join(__dirname, 'qr-passwort.txt'), 'utf8')).trim();
      } catch {
        console.warn('⚠️ qr-passwort.txt nicht gefunden – Standard wird verwendet.');
      }
      await pool.query(`INSERT INTO settings(key, value) VALUES('qr_password', $1)`, [pw]);
      console.log('🔐 QR-Passwort initialisiert.');
    }

    console.log('✅ Tabellen wurden erstellt oder geprüft. Zeitzone: Europe/Berlin');
  } catch (err) {
    console.error('❌ Fehler bei initDb:', err);
    process.exit(1);
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
    // 1. Prüfe in qr_tokens
    const result = await pool.query(
      `SELECT 1 FROM qr_tokens WHERE code = $1 AND gültig_bis > NOW()`,
      [qr]
    );

    if (result.rowCount > 0) {
      console.log('✅ QR-Code in qr_tokens gültig');
      return res.json({ valid: true });
    }

    // 2. Prüfe universal_code
    const gespeichertesPasswort = await getQrPassword();

    console.log('🔍 Vergleich:', qr, 'vs.', gespeichertesPasswort);
    if (qr === gespeichertesPasswort) {
      console.log('✅ QR-Code entspricht universal_code');
      return res.json({ valid: true });
    }

    // 3. Kein Treffer
    console.warn('⛔ QR ungültig');
    return sendError(res, 401, 'Ungültiger QR-Code');
  } catch (err) {
    console.error('❌ Fehler bei validate-qr:', err);
    return sendError(res, 500, 'Serverfehler');
  }
});




app.get('/api/verify-vorarbeiter-token', (req, res) => {
  const token = req.cookies.vorarbeiterToken;

  if (!token) {
    return res.status(401).json({ ok: false, error: 'Kein Token vorhanden' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (!decoded || decoded.rolle !== 'vorarbeiter') {
      return res.status(403).json({ ok: false, error: 'Keine Vorarbeiter-Berechtigung' });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ Fehler beim Vorarbeiter-Token:', err);
    return res.status(401).json({ ok: false, error: 'Token ungültig oder abgelaufen' });
  }
});


/**
 * Prüft, ob der QR-Code (Token) gültig ist, also entweder in qr_tokens existiert und noch gültig ist
 * oder alternativ als universal_code in settings hinterlegt ist.
 * @param {string} qr - Der QR-Code-Token
 * @returns {Promise<boolean>} true, wenn gültig, sonst false
 */
async function isValidQrCode(qr) {
  console.log('Validiere QR-Code:', qr);

  // 1. Prüfe in qr_tokens, ob Code gültig ist (existiert und nicht abgelaufen)
  const result = await pool.query(
    `SELECT COUNT(*) FROM qr_tokens WHERE code = $1 AND gültig_bis > NOW()`,
    [qr]
  );
  console.log('qr_tokens Treffer:', result.rows[0].count);

  if (parseInt(result.rows[0].count, 10) > 0) {
    console.log('✅ QR-Code in qr_tokens gefunden und gültig.');
    return true;
  }

  // 2. Fallback: Prüfe auf universal_code in settings
  const settingsResult = await pool.query(
    `SELECT value FROM settings WHERE key = 'universal_code'`
  );

  const universalCode = settingsResult.rows[0]?.value;
  if (universalCode && qr === universalCode) {
    console.log('✅ QR-Code entspricht dem universal_code in settings.');
    return true;
  }

  console.log('⛔ QR-Code nicht gefunden.');
  return false;
}

function generateSimpleCode(length = 8) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < length; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

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

app.post('/api/qr/create', authMiddleware, csrfMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const rolle = req.user.rolle;

    if (rolle !== 'vorarbeiter') {
      return sendError(res, 403, 'Nur Vorarbeiter dürfen QR-Codes erstellen.');
    }

    // 8-stelliger einfacher Code
    let code;
    // Optional: Code-Existenz prüfen und bei Kollision neu generieren
    do {
      code = generateSimpleCode(8);
      const { rowCount } = await pool.query(
        'SELECT 1 FROM qr_tokens WHERE code = $1',
        [code]
      );
      if (rowCount === 0) break; // code ist frei
    } while(true);

 const gültigBis = new Date().getTime() + 15 * 60 * 1000;
const gültigBisISO = new Date(gültigBis).toISOString();

   await pool.query(
  `INSERT INTO qr_tokens (code, erstellt_von, gültig_bis) VALUES ($1, $2, $3::timestamptz)`,
  [code, userId, gültigBisISO]
);


    res.json({ qrToken: code, gültigBis });  // nur Token zurückgeben
  } catch (err) {
    console.error('❌ Fehler beim QR-Generieren:', err);
    sendError(res, 500, 'Fehler beim Generieren des QR-Codes.');
  }
});

app.get('/api/qr/verify/:code', async (req, res) => {
  const { code } = req.params;

  try {
    // Prüfe, ob der QR-Code existiert und noch gültig ist
    const result = await pool.query(
      `SELECT 1 FROM qr_tokens WHERE code = $1 AND gültig_bis > NOW()`,
      [code]
    );

    if (result.rowCount === 0) {
      return sendError(res, 401, 'QR-Code ungültig oder abgelaufen.');
    }

    return res.json({ gültig: true });
  } catch (err) {
    console.error('❌ QR-Validierung fehlgeschlagen:', err);
    return sendError(res, 500, 'Fehler bei der QR-Überprüfung.');
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

//login normale nutzer
// Vereinheitlichte Login-Route
app.post('/api/login', loginLimiter, async (req, res) => {
  clearAuthCookies(res);
  const { email, passwort } = req.body;
  if (!email || !passwort) return sendError(res, 400, 'Alle Felder sind Pflicht.');

  try {
    const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
    const user = result.rows[0];
    if (!user) return sendError(res, 401, 'Nutzer nicht gefunden.');

    if (user.gesperrt_bis && new Date(user.gesperrt_bis) > new Date()) {
      const minuten = Math.ceil((new Date(user.gesperrt_bis).getTime() - new Date().getTime()) / 60000);
      return sendError(res, 403, `Konto gesperrt. Versuche es in ${minuten} Minuten.`);
    }

    const match = await bcrypt.compare(passwort, user.passwort);
    if (!match) {
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
        istGesperrt ? 'Zu viele Fehlversuche. Konto gesperrt für 15 Minuten.' : 'Falsches Passwort.'
      );
    }

    await pool.query(`UPDATE users SET fehlversuche = 0, gesperrt_bis = NULL WHERE id = $1`, [user.id]);

    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = issuedAt + 15 * 60;
    const jti = uuidv4();

    const accessToken = jwt.sign(
      { id: user.id, rolle: user.rolle, jti, iat: issuedAt, nbf: issuedAt },
      JWT_SECRET,
      { expiresIn: '15m', issuer: process.env.JWT_ISSUER }
    );

    const refreshToken = uuidv4();
    const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await pool.query(
      `INSERT INTO active_tokens(token, user_id, jti, issued_at, expires_at) VALUES($1, $2, $3, to_timestamp($4), to_timestamp($5))`,
      [accessToken, user.id, jti, issuedAt, expiresAt]
    );

    await pool.query(`DELETE FROM active_tokens WHERE expires_at < NOW()`);

    await pool.query(
      `INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)`,
      [refreshToken, user.id, refreshExpiresAt]
    );

    // ✅ Richtig geschriebene Variable verwenden
    const csrfToken = crypto.randomBytes(32).toString('hex');

    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 15 * 60 * 1000
    });

   res.cookie('refreshToken', refreshToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'Lax',
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 Tage
  path: '/api/refresh'
});

res.cookie('csrfToken', csrfToken, {
  httpOnly: false,
  secure: true,
  sameSite: 'Lax',
  maxAge: 24 * 60 * 60 * 1000
});

// Nur wenn Vorarbeiter
if (user.rolle === 'vorarbeiter') {
  const existingToken = req.cookies.vorarbeiterToken;

  // Wenn keiner da → neuen Vorarbeiter-Token setzen
  if (!existingToken) {
    const vToken = jwt.sign(
      { id: user.id, rolle: 'vorarbeiter' },
      JWT_SECRET,
      { expiresIn: '30d', issuer: process.env.JWT_ISSUER }
    );

    res.cookie('vorarbeiterToken', vToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 Tage
    });

    console.log(`✅ Vorarbeiter-Token gesetzt für ${user.email}`);
  }
}

    
res.json({
  message: 'Login erfolgreich',
  csrfToken,
  user: {
    id: user.id,
    name: `${user.vorname} ${user.nachname}`,
    email: user.email,
    rolle: user.rolle,
  }
});
  } catch (err) {
    console.error('❌ Login-Fehler:', err);
    sendError(res, 500, 'Interner Serverfehler');
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
    let token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') && req.headers.authorization.slice(7));

    if (!token) {
      return sendError(res, 401, 'Kein Token vorhanden');
    }

    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }); // falls du algo spezifizieren willst

    // Optional: Token-Issued-At in der Zukunft → Angriff/Manipulation
    if (payload.iat && payload.iat > Math.floor(Date.now() / 1000)) {
      return sendError(res, 401, 'Ungültiger Zeitstempel im Token');
    }

    // JTI prüfen gegen active_tokens (Blacklist)
    if (payload.jti) {
      const dbRes = await pool.query('SELECT 1 FROM active_tokens WHERE jti = $1', [payload.jti]);
      if (dbRes.rowCount === 0) {
        return sendError(res, 401, 'Token nicht aktiv oder abgelaufen');
      }
      req.jti = payload.jti;
    }

    req.user = payload;
    req.token = token;

    next();
  } catch (err) {
    console.error('Auth Middleware Error:', err);
    return sendError(res, 401, 'Token ungültig oder abgelaufen');
  }
}

// CSRF Middleware: Prüft CSRF-Token in Cookies und Headern
function timingSafeEqual(a, b) {
  const bufA = Buffer.from(a || '');
  const bufB = Buffer.from(b || '');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function csrfMiddleware(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const csrfCookie = req.cookies?.csrfToken;
  const csrfHeader = req.headers['x-csrf-token'];

  if (!csrfCookie || !csrfHeader || !timingSafeEqual(csrfCookie, csrfHeader)) {
    return sendError(res, 403, 'CSRF-Token fehlt oder stimmt nicht überein');
  }

  next();
}

function requireVorarbeiter(req, res, next) {
  try {
    const token = req.cookies.vorarbeiterToken;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== 'vorarbeiter') {
      return res.status(403).send('Nicht erlaubt');
    }

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send('Token fehlt oder ungültig');
  }
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
  sameSite: 'None', // <-- WICHTIG für cross-site Cookies
  maxAge: 15 * 60 * 1000,
});
res.cookie('refreshToken', refreshToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'None', // <-- auch hier
  path: '/',
  maxAge: 7 * 24 * 60 * 60 * 1000,
});
res.cookie('csrfToken', csrfToken, {
  httpOnly: false,
  secure: true,
  sameSite: 'None', // <-- auch hier
  maxAge: 15 * 60 * 1000,
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


app.get('/api/status', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT ist_eingestempelt FROM users WHERE id = $1', [req.user.id]);
    res.json({ ist_eingestempelt: result.rows[0].ist_eingestempelt });
  } catch (err) {
    console.error('Fehler beim Abrufen des Status:', err);
    sendError(res, 500, 'Statusabfrage fehlgeschlagen');
  }
});


// Route für Zeitstempel-Aktionen (Start, Stop, Pause, Resume)
app.post('/api/zeit', authMiddleware, csrfMiddleware, async (req, res) => {
  const erlaubteRollen = ['user', 'vorarbeiter', 'admin'];
  if (!erlaubteRollen.includes(req.user.rolle)) {
    return sendError(res, 403, 'Nicht berechtigt, Zeitstempel zu setzen.');
  }

  const { error, value } = zeitSchema.validate(req.body);
  if (error) {
    return sendError(res, 400, 'Ungültige Eingabe: ' + error.details[0].message);
  }

  const { aktion } = value;
  const userId = req.user.id;

  // Deutsche Ortszeit (automatisch Sommer/Winter korrekt)
  const serverZeit = DateTime.now().setZone('Europe/Berlin').toJSDate();

  try {
    const result = await pool.query(
      'SELECT ist_eingestempelt FROM users WHERE id = $1',
      [userId]
    );
    const istEingestempelt = result.rows[0]?.ist_eingestempelt;

    if (aktion === 'start') {
      if (istEingestempelt) {
        return sendError(res, 400, 'Du bist bereits eingestempelt.');
      }

      await pool.query(
        `INSERT INTO zeiten (user_id, aktion, zeit) VALUES ($1, $2, $3)`,
        [userId, 'start', serverZeit]
      );
      await pool.query(`UPDATE users SET ist_eingestempelt = TRUE WHERE id = $1`, [userId]);

      return res.json({
        success: true,
        message: 'Eingestempelt',
        zeit: serverZeit
      });
    }

    if (aktion === 'stop') {
      if (!istEingestempelt) {
        return sendError(res, 400, 'Du bist noch nicht eingestempelt.');
      }

      await pool.query(
        `INSERT INTO zeiten (user_id, aktion, zeit) VALUES ($1, $2, $3)`,
        [userId, 'stop', serverZeit]
      );
      await pool.query(`UPDATE users SET ist_eingestempelt = FALSE WHERE id = $1`, [userId]);

      return res.json({
        success: true,
        message: 'Ausgestempelt',
        zeit: serverZeit
      });
    }

    return sendError(res, 400, 'Ungültige Aktion.');
  } catch (err) {
    console.error('❌ Fehler bei Zeiterfassung:', err);
    sendError(res, 500, 'Serverfehler beim Zeitstempeln.');
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
  const allowedOrigin = process.env.CORS_ORIGIN;
  const origin = req.get('Origin');
  if (!origin || origin !== allowedOrigin) {
    return sendError(res, 403, 'Ungültiger Origin');
  }

  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return sendError(res, 401, 'Kein Refresh-Token gefunden.');

  try {
    const result = await pool.query(
      `SELECT * FROM refresh_tokens WHERE token = $1 AND expires_at > NOW()`,
      [refreshToken]
    );

    const entry = result.rows[0];
    if (!entry) {
      clearAuthCookies(res);
      return sendError(res, 403, 'Ungültiger oder abgelaufener Refresh-Token.');
    }

    const userResult = await pool.query(
      `SELECT * FROM users WHERE id = $1`,
      [entry.user_id]
    );
    const user = userResult.rows[0];
    if (!user) {
      clearAuthCookies(res);
      return sendError(res, 403, 'Benutzer nicht gefunden.');
    }

    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = issuedAt + 15 * 60;
    const jti = uuidv4();

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

    await pool.query(`DELETE FROM active_tokens WHERE expires_at < NOW()`);
    await pool.query(
      `INSERT INTO active_tokens(token, user_id, jti, issued_at, expires_at)
       VALUES ($1, $2, $3, to_timestamp($4), to_timestamp($5))`,
      [newAccessToken, user.id, jti, issuedAt, expiresAt]
    );

    const newCsrfToken = crypto.randomBytes(32).toString('hex');

    // ⛓ Access-Token als Cookie (gleich wie in /login)
    res.cookie('token', newAccessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      path: '/',
      maxAge: 15 * 60 * 1000,
    });

    // 🔓 CSRF-Token für JS lesbar
    res.cookie('csrfToken', newCsrfToken, {
      httpOnly: false,
      secure: true,
      sameSite: 'Lax',
      path: '/',
      maxAge: 15 * 60 * 1000,
    });

    res.json({
      success: true
    });
  } catch (err) {
    console.error('Fehler beim Token-Refresh:', err);
    clearAuthCookies(res);
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
app.post('/api/set-role', authMiddleware, csrfMiddleware, adminOnlyMiddleware, async (req, res) => {
  try {
    const requester = await getUserById(req.user.id);
    if (!requester || requester.rolle !== 'admin') {
      return sendError(res, 403, 'Nicht erlaubt');
    }

    const { userId: targetUserId, rolle } = req.body;

    // Eingabe validieren
    const erlaubteRollen = ['user', 'vorarbeiter', 'admin'];
    if (!erlaubteRollen.includes(rolle) || typeof targetUserId !== 'number') {
      return sendError(res, 400, 'Ungültige Eingabedaten oder Rolle.');
    }

    // Selbst-Degradierung verhindern
    if (req.user.id === targetUserId && rolle !== 'admin') {
      return sendError(res, 400, 'Du kannst dich nicht selbst herabstufen.');
    }

    // Zielnutzer prüfen
    const result = await pool.query('SELECT id FROM users WHERE id = $1', [targetUserId]);
    if (result.rowCount === 0) {
      return sendError(res, 404, 'Nutzer nicht gefunden.');
    }

    await pool.query(
      'UPDATE users SET rolle = $1 WHERE id = $2',
      [rolle, targetUserId]
    );

    res.json({ success: true, message: `Rolle erfolgreich zu '${rolle}' geändert.` });
  } catch (err) {
    console.error('Fehler in /set-role:', err);
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

// Benutzer löschen (Admin)
app.delete('/api/user/:id', authMiddleware, csrfMiddleware, adminOnlyMiddleware, async (req, res) => {
    const idToDelete = parseInt(req.params.id, 10);

    if (req.user.id === idToDelete) {
        return sendError(res, 400, 'Du kannst dich nicht selbst löschen.');
    }

    try {
        // Zeitstempel des Benutzers anonymisieren (user_id auf NULL setzen)
        await pool.query(`UPDATE zeiten SET user_id = NULL WHERE user_id = $1`, [idToDelete]);

        // Auth-bezogene Daten löschen
        await pool.query(`DELETE FROM active_tokens WHERE user_id = $1`, [idToDelete]);
        await pool.query(`DELETE FROM refresh_tokens WHERE user_id = $1`, [idToDelete]);
        await pool.query(`DELETE FROM webauthn_credentials WHERE user_id = $1`, [idToDelete]);

        // Benutzer löschen
        const result = await pool.query(`DELETE FROM users WHERE id = $1 RETURNING id`, [idToDelete]);
        if (result.rowCount === 0) {
            return sendError(res, 404, 'Benutzer nicht gefunden.');
        }

        // Alte Zeitstempel (älter als 10 Jahre) entfernen
        await pool.query(`
            DELETE FROM zeiten
            WHERE zeit < NOW() - INTERVAL '10 years'
        `);

        res.json({ success: true, message: 'Benutzer gelöscht. Alte Zeitstempel bereinigt.' });
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
async function startServer() {
  try {
    // Zeitzone in der DB setzen
    await pool.query("SET timezone='Europe/Berlin'");

    const PORT = process.env.PORT || 3000;
    const isProduction = process.env.NODE_ENV === 'production' || process.env.RENDER === 'true';

    if (isProduction) {
      http.createServer(app).listen(PORT, () => {
        console.log(`🚀 HTTP Server läuft auf Port ${PORT} (Produktions-Modus - HTTPS über Proxy)`);
      });
    } else {
      const privateKeyPath = path.join(__dirname, 'ssl', 'privkey.pem');
      const certificatePath = path.join(__dirname, 'ssl', 'fullchain.pem');

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
  } catch (err) {
    console.error('❌ Fehler beim Setzen der DB-Zeitzone:', err);
    process.exit(1); // Server nicht starten, wenn DB-Setup fehlschlägt
  }
}

startServer();

