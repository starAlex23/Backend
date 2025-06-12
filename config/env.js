// config/env.js
import dotenv from 'dotenv';
dotenv.config();

// Pflicht-Checks
const required = (key) => {
  if (!process.env[key]) {
    throw new Error(`${key} fehlt in den Umgebungsvariablen (.env oder Render)!`);
  }
};

// Kritische Variablen prüfen
['ACCESS_TOKEN_SECRET', 'REFRESH_TOKEN_SECRET', 'DB_USER', 'DB_PASSWORD', 'DB_DATABASE', 'JWT_ISSUER', 'CORS_ORIGIN'].forEach(required);

// Export: Tokens
export const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
export const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

// Export: Datenbank
export const DB_HOST = process.env.DB_HOST || 'localhost';
export const DB_PORT = parseInt(process.env.DB_PORT) || 5432;
export const DB_USER = process.env.DB_USER;
export const DB_PASSWORD = process.env.DB_PASSWORD;
export const DB_NAME = process.env.DB_DATABASE;

// Export: Sicherheit & Auth
export const JWT_ISSUER = process.env.JWT_ISSUER;
export const CORS_ORIGIN = process.env.CORS_ORIGIN;

// Export: Server
export const PORT = parseInt(process.env.PORT) || 3000;
export const NODE_ENV = process.env.NODE_ENV || 'development';
export const IS_RENDER = process.env.RENDER !== undefined;

// Export: HTTPS (optional, nur wenn lokal mit SSL)
export const HTTPS_KEY_PATH = process.env.HTTPS_KEY_PATH || null;
export const HTTPS_CERT_PATH = process.env.HTTPS_CERT_PATH || null;

