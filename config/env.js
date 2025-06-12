// config/env.js

if (!process.env.ACCESS_TOKEN_SECRET) throw new Error("ACCESS_TOKEN_SECRET fehlt!");
if (!process.env.REFRESH_TOKEN_SECRET) throw new Error("REFRESH_TOKEN_SECRET fehlt!");

// Entweder einzelne DB-Variablen oder DATABASE_URL müssen gesetzt sein
if (!process.env.DATABASE_URL && (!process.env.DB_USER || !process.env.DB_PASSWORD || !process.env.DB_DATABASE)) {
  throw new Error("Datenbank-Konfiguration fehlt: entweder DATABASE_URL oder DB_USER, DB_PASSWORD, DB_DATABASE");
}

export const PORT = process.env.PORT || 3000;
export const NODE_ENV = process.env.NODE_ENV || 'development';

// Nutze DATABASE_URL, wenn vorhanden, sonst Einzelwerte
export const DATABASE_URL = process.env.DATABASE_URL || null;

export const DB_HOST = process.env.DB_HOST || 'localhost';
export const DB_PORT = process.env.DB_PORT || 5432;
export const DB_USER = process.env.DB_USER;
export const DB_PASSWORD = process.env.DB_PASSWORD;
export const DB_DATABASE = process.env.DB_DATABASE;

export const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
export const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

export const JWT_ISSUER = process.env.JWT_ISSUER || 'localhost';
export const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';

export const HTTPS_KEY_PATH = process.env.HTTPS_KEY_PATH || './ssl/privkey.pem';
export const HTTPS_CERT_PATH = process.env.HTTPS_CERT_PATH || './ssl/fullchain.pem';


