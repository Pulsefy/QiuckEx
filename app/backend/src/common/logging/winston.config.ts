import * as winston from 'winston';

/**
 * Structured logging format for Winston.
 *
 * All log entries include:
 *   - timestamp (ISO 8601)
 *   - level (error, warn, info, debug)
 *   - message
 *   - service name
 *   - any additional metadata
 *
 * File transports use JSON format for machine parsing.
 * Console transport uses colourised simple format for dev readability.
 */
const structuredFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
);

const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'HH:mm:ss.SSS' }),
  winston.format.colorize(),
  winston.format.printf(({ timestamp, level, message, context, ...meta }) => {
    const ctx = context ? `[${context}]` : '';
    const extra = Object.keys(meta).length
      ? ` ${JSON.stringify(meta)}`
      : '';
    return `${timestamp} ${level} ${ctx} ${message}${extra}`;
  }),
);

export const winstonConfig = {
  transports: [
    // Console: human-friendly for development
    new winston.transports.Console({
      format: consoleFormat,
    }),
    // Error log: only errors, structured JSON
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      format: structuredFormat,
      maxsize: 10 * 1024 * 1024, // 10 MB
      maxFiles: 5,
    }),
    // Combined log: all levels, structured JSON
    new winston.transports.File({
      filename: 'logs/combined.log',
      format: structuredFormat,
      maxsize: 10 * 1024 * 1024, // 10 MB
      maxFiles: 5,
    }),
  ],
};