import { ApiError } from '../api/client';
import type { AlertFlowCorrelationResponse } from '../api/types';

export const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/;

export interface CorrelationErrorSummary {
  status: number | null;
  title: string;
  message: string;
  canRetry: boolean;
}

/**
 * Validate an optional RoutingDomain filter input using fail-closed rules
 * matching the backend API (explicit whitespace or '#' is rejected).
 */
export function validateRoutingDomainInput(raw: string): string | null {
  if (raw === '') {
    return null;
  }
  if (raw.trim() === '') {
    return 'RoutingDomain must not be blank whitespace when specified. Clear the field to query all domains.';
  }
  if (raw.includes('#')) {
    return 'RoutingDomain cannot contain the reserved "#" delimiter.';
  }
  return null;
}

/**
 * Validate an optional 64-character lowercase SHA-256 hex identifier filter input.
 */
export function validateSha256Input(raw: string, fieldLabel: string): string | null {
  if (raw === '') {
    return null;
  }
  const trimmed = raw.trim();
  if (trimmed === '') {
    return `${fieldLabel} must not be blank whitespace. Clear the field to remove this filter.`;
  }
  if (!SHA256_HEX_REGEX.test(trimmed)) {
    return `${fieldLabel} must be a 64-character lowercase hexadecimal SHA-256 identifier.`;
  }
  return null;
}

/**
 * Format a compact display representation of a long identifier without mutating the underlying value.
 */
export function truncateIdentifier(
  value: string,
  prefixLen: number = 12,
  suffixLen: number = 6
): string {
  if (value.length <= prefixLen + suffixLen + 1) {
    return value;
  }
  return `${value.slice(0, prefixLen)}…${value.slice(-suffixLen)}`;
}

/**
 * Generate deterministic, non-index-primary React keys for persisted correlation rows.
 * Preserves duplicate parallel edges as distinct rows by appending a repeat counter
 * when identical persisted tuple signatures appear on the same page, without exposing
 * Neo4j internal elementId values.
 */
export function buildStableCorrelationRowKeys(items: AlertFlowCorrelationResponse[]): string[] {
  const seenCounts = new Map<string, number>();
  return items.map((item) => {
    const baseKey = [
      item.event_id,
      item.observation_id,
      item.routing_domain_id,
      item.verification_status,
      item.evidence_digest ?? 'no-digest',
      item.decided_at_utc ?? 'no-decided-ts',
      item.last_incomplete_at_utc ?? 'no-incomplete-ts',
    ].join('|');
    const count = seenCounts.get(baseKey) ?? 0;
    seenCounts.set(baseKey, count + 1);
    return count === 0 ? baseKey : `${baseKey}#dup-${count}`;
  });
}

/**
 * Render persisted nullable evidence values neutrally without inventing defaults
 * or coercing arbitrary-precision Decimal strings into JavaScript numbers.
 */
export function formatPersistedValue(value: string | boolean | null): string {
  if (value === null || value === '') {
    return 'Not recorded';
  }
  if (typeof value === 'boolean') {
    return value ? 'Yes (true)' : 'No (false)';
  }
  return value;
}

/**
 * Translate ApiError and unexpected fetch failures into clear, non-leaky UI messages
 * distinguishing 404 (missing AlertEvent), 422 (validation), 503 (DB unavailable),
 * 500 (internal error), and network failures.
 */
export function describeCorrelationApiError(
  err: unknown,
  context: { isEventDetailQuery: boolean; eventId?: string; routingDomainId?: string }
): CorrelationErrorSummary {
  if (err instanceof ApiError) {
    if (err.status === 404) {
      const domainNote = context.routingDomainId
        ? ` in RoutingDomain "${context.routingDomainId}"`
        : '';
      return {
        status: 404,
        title: 'Suricata AlertEvent Not Found (HTTP 404)',
        message:
          context.isEventDetailQuery && context.eventId
            ? `No persisted Suricata AlertEvent matching "${context.eventId}" exists${domainNote}. (${err.detail})`
            : err.detail || 'The requested AlertEvent resource was not found.',
        canRetry: true,
      };
    }

    if (err.status === 422) {
      return {
        status: 422,
        title: 'Invalid Correlation Query Parameters (HTTP 422)',
        message: err.detail || 'The backend rejected the submitted filter or pagination parameters.',
        canRetry: false,
      };
    }

    if (err.status === 503) {
      return {
        status: 503,
        title: 'Database Service Temporarily Unavailable (HTTP 503)',
        message:
          'The Neo4j graph database is currently unreachable. This indicates a backend service availability issue and does not mean the requested AlertEvent or correlations are missing.',
        canRetry: true,
      };
    }

    if (err.status >= 500) {
      return {
        status: err.status,
        title: `Internal Server Error (HTTP ${err.status})`,
        message:
          'The backend server encountered an unexpected error while retrieving persisted correlations. No stack traces are exposed; please retry or inspect backend logs.',
        canRetry: true,
      };
    }

    if (err.status === 0) {
      return {
        status: 0,
        title: 'Network Connection Error',
        message:
          'Could not connect to the correlation API server. Verify backend availability and network connectivity, then retry.',
        canRetry: true,
      };
    }

    return {
      status: err.status,
      title: `Correlation Query Failed (HTTP ${err.status})`,
      message: err.detail || 'The correlation API request could not be completed.',
      canRetry: true,
    };
  }

  return {
    status: null,
    title: 'Unexpected Error',
    message: 'An unexpected client error occurred while loading persisted correlations.',
    canRetry: true,
  };
}
