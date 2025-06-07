import winston from "winston"

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
}

// Define log colors
const colors = {
  error: "red",
  warn: "yellow",
  info: "green",
  http: "magenta",
  debug: "blue",
}

// Add colors to winston
winston.addColors(colors)

// Define log format
const format = winston.format.combine(
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss:ms" }),
  winston.format.colorize({ all: true }),
  winston.format.printf((info) => `${info.timestamp} ${info.level}: ${info.message}`),
)

// Define which transports to use based on environment
const transports = [
  // Always log to console
  new winston.transports.Console(),

  // Log errors to a file
  new winston.transports.File({
    filename: "logs/error.log",
    level: "error",
  }),

  // Log all to a file
  new winston.transports.File({ filename: "logs/all.log" }),
]

// Create the logger
export const logger = winston.createLogger({
  level: process.env.NODE_ENV === "development" ? "debug" : "info",
  levels,
  format,
  transports,
})

// Create a separate audit logger for security events
export const auditLogger = winston.createLogger({
  level: "info",
  format: winston.format.combine(winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss:ms" }), winston.format.json()),
  defaultMeta: { service: "audit" },
  transports: [new winston.transports.File({ filename: "logs/audit.log" })],
})
