import React from 'react';
import { Check, Copy, RefreshCw } from 'lucide-react';
import { formatPersistedValue, type CorrelationErrorSummary } from '../../utils/correlationHelpers';
import { Skeleton } from '../common/Skeleton';

export interface EvidenceFieldRowProps {
  label: string;
  value: string | number | boolean | null;
  mono?: boolean;
  helperText?: string;
  copyAriaLabel?: string;
  copied?: boolean;
  onCopy?: (rawValue: string) => void;
}

/**
 * Shared read-only evidence card rendering persisted values neutrally ("Not recorded" for null/empty).
 */
export const EvidenceFieldRow: React.FC<EvidenceFieldRowProps> = ({
  label,
  value,
  mono = false,
  helperText,
  copyAriaLabel,
  copied = false,
  onCopy,
}) => {
  const formatted = formatPersistedValue(value);
  const isMissing = value === null || value === '';
  const canCopy = typeof value === 'string' && value !== '' && Boolean(onCopy);

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '0.28rem',
        padding: '0.65rem 0.75rem',
        backgroundColor: 'var(--bg-surface-secondary)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-sm)',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '0.5rem',
        }}
      >
        <span
          style={{
            fontSize: '0.72rem',
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.04em',
            color: 'var(--text-secondary)',
          }}
        >
          {label}
        </span>
        {canCopy && onCopy && typeof value === 'string' && (
          <button
            type="button"
            className="btn-ghost"
            onClick={() => onCopy(value)}
            aria-label={copyAriaLabel || `Copy ${label}`}
            title={copied ? 'Copied' : `Copy ${label}`}
            style={{
              padding: '0.15rem 0.4rem',
              fontSize: '0.72rem',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.25rem',
              color: copied ? 'var(--accent-emerald-hover)' : 'var(--text-secondary)',
            }}
          >
            {copied ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        )}
      </div>

      <div
        className={mono && !isMissing ? 'font-mono' : undefined}
        style={{
          fontSize: mono ? '0.78rem' : '0.84rem',
          color: isMissing ? 'var(--text-muted)' : 'var(--text-primary)',
          fontStyle: isMissing ? 'italic' : 'normal',
          wordBreak: 'break-all',
          overflowWrap: 'anywhere',
        }}
      >
        {formatted}
      </div>

      {helperText && (
        <span style={{ fontSize: '0.73rem', color: 'var(--text-muted)' }}>
          {helperText}
        </span>
      )}
    </div>
  );
};

interface ObservationDetailAsyncStateProps {
  loadingLabel: string;
  loading: boolean;
  error: CorrelationErrorSummary | null;
  onRetry: () => void;
}

/**
 * Shared loading skeleton and non-leaky retryable error state for lazy V2 detail panels.
 */
export const ObservationDetailAsyncState: React.FC<ObservationDetailAsyncStateProps> = ({
  loadingLabel,
  loading,
  error,
  onRetry,
}) => {
  if (loading) {
    return (
      <div
        aria-busy="true"
        aria-label={loadingLabel}
        style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}
      >
        <Skeleton height="54px" width="100%" />
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 220px), 1fr))',
            gap: '0.7rem',
          }}
        >
          {Array.from({ length: 6 }).map((_, idx) => (
            <Skeleton key={idx} height="64px" width="100%" />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    const isClientScopeIssue = error.status === 404 || error.status === 422;
    return (
      <div
        role="alert"
        style={{
          backgroundColor: isClientScopeIssue
            ? 'var(--accent-amber-dim)'
            : 'var(--accent-rose-dim)',
          border: isClientScopeIssue
            ? '1px solid var(--accent-amber-border)'
            : '1px solid var(--accent-rose-border)',
          color: isClientScopeIssue
            ? 'var(--accent-amber-hover)'
            : 'var(--accent-rose-hover)',
          padding: '0.85rem 1rem',
          borderRadius: 'var(--radius-md)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
          <strong style={{ fontSize: '0.88rem' }}>{error.title}</strong>
          <span style={{ fontSize: '0.83rem' }}>{error.message}</span>
        </div>
        {error.canRetry && (
          <button type="button" className="btn-secondary" onClick={onRetry}>
            <RefreshCw size={14} aria-hidden="true" />
            <span>Retry</span>
          </button>
        )}
      </div>
    );
  }

  return null;
};
