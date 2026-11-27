import { ApiError } from '../api/client';
import type { SafeCount } from '../api/types';
import {
  normalizeRoutingDomainInput,
  validateRoutingDomainInput,
  type CorrelationErrorSummary,
} from './correlationHelpers';

export { normalizeRoutingDomainInput, validateRoutingDomainInput };

export const INT64_MIN_BIGINT = -(1n << 63n);
export const INT64_MAX_BIGINT = (1n << 63n) - 1n;

const NON_NEG_INT_RE = /^\d+$/;
const UTC_ISO_TIMESTAMP_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?Z?$/;

/**
 * Format a SafeCount integer or null counter neutrally without floating-point coercion
 * or locale comma reformatting.
 */
export function formatSafeCount(value: SafeCount | null): string {
  if (value === null) {
    return 'Not recorded';
  }
  return typeof value === 'string' ? value : String(value);
}

/**
 * Validate an optional non-negative 64-bit signed integer filter input using BigInt
 * so values up to 9223372036854775807 never silently round through JS Number.
 */
export function validateNonNegativeInt64Input(raw: string, fieldLabel: string): string | null {
  if (raw === '') {
    return null;
  }
  const trimmed = raw.trim();
  if (trimmed === '') {
    return `${fieldLabel} must not be blank whitespace. Clear the field to remove this filter.`;
  }
  if (!NON_NEG_INT_RE.test(trimmed)) {
    return `${fieldLabel} must be a non-negative integer.`;
  }
  const parsed = BigInt(trimmed);
  if (parsed > INT64_MAX_BIGINT) {
    return `${fieldLabel} exceeds maximum supported 64-bit integer (${INT64_MAX_BIGINT.toString()}).`;
  }
  return null;
}

/**
 * Normalize a validated optional non-negative int64 filter to its canonical decimal string.
 */
export function normalizeNonNegativeInt64Input(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (trimmed === '') {
    return undefined;
  }
  return BigInt(trimmed).toString();
}

/**
 * Validate an optional sensor_id filter input (fail-closed on blank whitespace).
 */
export function validateSensorIdInput(raw: string): string | null {
  if (raw === '') {
    return null;
  }
  if (raw.trim() === '') {
    return 'Sensor ID must not be blank whitespace. Clear the field to query all sensors.';
  }
  return null;
}

/**
 * Normalize a validated optional sensor_id input (`sensor.strip().lower()`).
 */
export function normalizeSensorIdInput(raw: string): string | undefined {
  const normalized = raw.trim().toLowerCase();
  return normalized === '' ? undefined : normalized;
}

/**
 * Parse a UTC ISO-8601 timestamp string (YYYY-MM-DDTHH:MM[:SS[.nnnnnnnnn]][Z])
 * into an exact signed 64-bit nanosecond decimal string using BigInt arithmetic.
 *
 * Rejects timezone offsets other than UTC and validates calendar fields and
 * signed 64-bit int range fail-closed without float coercion.
 */
export function parseUtcTimestampToEpochNs(
  raw: string,
  fieldLabel: string
): { ns?: string; error?: string } {
  if (raw === '') {
    return {};
  }
  const trimmed = raw.trim();
  if (trimmed === '') {
    return {
      error: `${fieldLabel} must not be blank whitespace. Clear the field to remove this filter.`,
    };
  }

  const match = UTC_ISO_TIMESTAMP_RE.exec(trimmed);
  if (!match) {
    return {
      error: `${fieldLabel} must use UTC ISO-8601 format: YYYY-MM-DDTHH:MM[:SS[.nnnnnnnnn]][Z].`,
    };
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = match[6] ? Number(match[6]) : 0;
  const fracStr = match[7] ?? '';

  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return { error: `${fieldLabel} contains an out-of-range calendar date or time component.` };
  }

  const utcDate = new Date(0);
  utcDate.setUTCFullYear(year, month - 1, day);
  utcDate.setUTCHours(hour, minute, second, 0);

  if (
    Number.isNaN(utcDate.getTime()) ||
    utcDate.getUTCFullYear() !== year ||
    utcDate.getUTCMonth() !== month - 1 ||
    utcDate.getUTCDate() !== day ||
    utcDate.getUTCHours() !== hour ||
    utcDate.getUTCMinutes() !== minute ||
    utcDate.getUTCSeconds() !== second
  ) {
    return { error: `${fieldLabel} is not a valid UTC calendar timestamp.` };
  }

  const epochMs = BigInt(utcDate.getTime());
  const fracNs = fracStr ? BigInt(fracStr.padEnd(9, '0')) : 0n;
  const totalNs = epochMs * 1_000_000n + fracNs;

  if (totalNs < INT64_MIN_BIGINT || totalNs > INT64_MAX_BIGINT) {
    return {
      error: `${fieldLabel} exceeds supported signed 64-bit timestamp_epoch_ns index bounds.`,
    };
  }

  return { ns: totalNs.toString() };
}

/**
 * Validate optional Start/End UTC time inputs and ensure start <= end via exact BigInt comparison.
 */
export function validateUtcTimeRange(
  startRaw: string,
  endRaw: string
): {
  startNs?: string;
  endNs?: string;
  field?: 'startTime' | 'endTime';
  error?: string;
} {
  const startParsed = parseUtcTimestampToEpochNs(startRaw, 'Start Time (UTC)');
  if (startParsed.error) {
    return { field: 'startTime', error: startParsed.error };
  }
  const endParsed = parseUtcTimestampToEpochNs(endRaw, 'End Time (UTC)');
  if (endParsed.error) {
    return { field: 'endTime', error: endParsed.error };
  }
  if (startParsed.ns !== undefined && endParsed.ns !== undefined) {
    if (BigInt(startParsed.ns) > BigInt(endParsed.ns)) {
      return {
        field: 'endTime',
        error: 'End Time (UTC) must not be earlier than Start Time (UTC).',
      };
    }
  }
  return {
    startNs: startParsed.ns,
    endNs: endParsed.ns,
  };
}

/**
 * Translate ApiError and unexpected fetch failures when loading V2 Suricata AlertEvents.
 */
export function describeAlertTriageListApiError(
  err: unknown,
  context: { routingDomainId?: string }
): CorrelationErrorSummary {
  if (err instanceof ApiError) {
    if (err.status === 422) {
      return {
        status: 422,
        title: 'Invalid AlertEvent Query Parameters (HTTP 422)',
        message: err.detail || 'The backend rejected the submitted filter or pagination parameters.',
        canRetry: false,
      };
    }

    if (err.status === 503) {
      return {
        status: 503,
        title: 'Database Service Temporarily Unavailable (HTTP 503)',
        message:
          'The Neo4j graph database is currently unreachable. This indicates a service availability issue and does not mean Suricata AlertEvents are absent.',
        canRetry: true,
      };
    }

    if (err.status >= 500) {
      return {
        status: err.status,
        title: `Internal Server Error (HTTP ${err.status})`,
        message:
          'The backend server encountered an unexpected error while retrieving Suricata AlertEvents. No stack traces are exposed; please retry or inspect backend logs.',
        canRetry: true,
      };
    }

    if (err.status === 0) {
      return {
        status: 0,
        title: 'Network Connection Error',
        message:
          'Could not connect to the API server while loading Suricata AlertEvents. Verify backend availability and retry.',
        canRetry: true,
      };
    }

    return {
      status: err.status,
      title: `Suricata AlertEvents Request Failed (HTTP ${err.status})`,
      message: `The Suricata AlertEvents request could not be completed (HTTP ${err.status})${
        context.routingDomainId ? ` for RoutingDomain "${context.routingDomainId}"` : ''
      }.`,
      canRetry: true,
    };
  }

  return {
    status: null,
    title: 'Unexpected Error',
    message: 'An unexpected client error occurred while loading Suricata AlertEvents.',
    canRetry: true,
  };
}
