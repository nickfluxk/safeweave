export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVELS: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };

const currentLevel: LogLevel = (process.env.LOG_LEVEL as LogLevel) || 'info';

function shouldLog(level: LogLevel): boolean {
  return LEVELS[level] >= LEVELS[currentLevel];
}

function formatMessage(level: LogLevel, service: string, msg: string, meta?: Record<string, unknown>): string {
  const entry: Record<string, unknown> = {
    timestamp: new Date().toISOString(),
    level,
    service,
    msg,
    ...meta,
  };
  return JSON.stringify(entry);
}

export function createLogger(service: string) {
  return {
    debug(msg: string, meta?: Record<string, unknown>) {
      if (shouldLog('debug')) console.log(formatMessage('debug', service, msg, meta));
    },
    info(msg: string, meta?: Record<string, unknown>) {
      if (shouldLog('info')) console.log(formatMessage('info', service, msg, meta));
    },
    warn(msg: string, meta?: Record<string, unknown>) {
      if (shouldLog('warn')) console.warn(formatMessage('warn', service, msg, meta));
    },
    error(msg: string, meta?: Record<string, unknown>) {
      if (shouldLog('error')) console.error(formatMessage('error', service, msg, meta));
    },
  };
}
