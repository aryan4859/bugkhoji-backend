import dotenv from "dotenv"

// Load environment variables
dotenv.config()

export const config = {
  // Database
  DATABASE_URL: process.env.DATABASE_URL,

  // JWT
  JWT_SECRET: process.env.JWT_SECRET,
  JWT_ACCESS_EXPIRE: process.env.JWT_ACCESS_EXPIRE || "15m",
  JWT_REFRESH_EXPIRE: process.env.JWT_REFRESH_EXPIRE || "7d",

  // Server
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV || "development",

  // CORS
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS?.split(",") || ["http://localhost:3000"],

  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: Number.parseInt(process.env.RATE_LIMIT_WINDOW_MS || "900000"), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: Number.parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || "5"),

  // Security
  BCRYPT_SALT_ROUNDS: Number.parseInt(process.env.BCRYPT_SALT_ROUNDS || "12"),

  // Logging
  LOG_LEVEL: process.env.LOG_LEVEL || "info",
}

// Validate required environment variables
const requiredEnvVars = ["DATABASE_URL", "JWT_SECRET"]

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Required environment variable ${envVar} is not set`)
  }
}
