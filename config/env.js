// config/env.js

// Prüfung: wichtige Umgebungsvariablen müssen gesetzt sein
if (!process.env.ACCESS_TOKEN_SECRET) throw new Error("ACCESS_TOKEN_SECRET fehlt!");
if (!process.env.REFRESH_TOKEN_SECRET) throw new Error("REFRESH_TOKEN_SECRET fehlt!");
if (!process.env.DB_USER) throw new Error("DB_USER fehlt!");
if (!process.env.DB_PASSWORD) throw new Error("DB_PASSWORD fehlt!");
if (!process.env.DB_DATABASE) throw new Error("DB_DATABASE fehlt!");

export const PORT = process.env.PORT || 3000;
export const NODE_ENV = process.env.NODE_ENV || 'development';

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


