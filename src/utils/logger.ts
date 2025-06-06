import winston from 'winston';
import { env } from './environment';

const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    // Mask sensitive data
    const sanitizedMeta = JSON.stringify(meta).replace(
      /(password|token|secret|key)/gi,
      (match) => `${match.substring(0, 3)}***`
    );
    return `${timestamp} [${level.toUpperCase()}]: ${message} ${sanitizedMeta !== '{}' ? sanitizedMeta : ''}`;
  })
);

export const logger = winston.createLogger({
  level: env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: logFormat,
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.File({ filename: 'logs/audit.log', level: 'info' })
  ],
});

export const auditLog = (action: string, userId: string, details: any) => {
  logger.info('AUDIT', {
    action,
    userId,
    timestamp: new Date().toISOString(),
    details,
    ip: details.ip || 'unknown'
  });
};