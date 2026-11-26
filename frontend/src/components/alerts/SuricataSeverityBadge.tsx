import React from 'react';
import type { SafeCount } from '../../api/types';

interface SuricataSeverityBadgeProps {
  severity: SafeCount | null;
}

/**
 * Factual, non-color-only badge for recorded Suricata alert severity integers.
 * Never fabricates subjective labels ('Critical', 'High', etc.) or confidence scores.
 */
export const SuricataSeverityBadge: React.FC<SuricataSeverityBadgeProps> = ({ severity }) => {
  if (severity === null) {
    return (
      <span
        className="badge-priority-unknown"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          padding: '0.15rem 0.5rem',
          borderRadius: 'var(--radius-sm)',
          backgroundColor: 'var(--priority-unknown-bg)',
          color: 'var(--priority-unknown-text)',
          border: '1px solid var(--priority-unknown-border)',
          fontSize: '0.72rem',
          fontWeight: 600,
          whiteSpace: 'nowrap',
        }}
      >
        Not recorded
      </span>
    );
  }

  const label = `Severity ${String(severity)}`;
  let bg = 'var(--priority-unknown-bg)';
  let color = 'var(--priority-unknown-text)';
  let border = 'var(--priority-unknown-border)';
  let className = 'badge-priority-unknown';

  if (severity === 1) {
    className = 'badge-priority-1';
    bg = 'var(--priority-1-bg)';
    color = 'var(--priority-1-text)';
    border = 'var(--priority-1-border)';
  } else if (severity === 2) {
    className = 'badge-priority-2';
    bg = 'var(--priority-2-bg)';
    color = 'var(--priority-2-text)';
    border = 'var(--priority-2-border)';
  } else if (severity === 3) {
    className = 'badge-priority-3';
    bg = 'var(--priority-3-bg)';
    color = 'var(--priority-3-text)';
    border = 'var(--priority-3-border)';
  }

  return (
    <span
      className={className}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '0.15rem 0.5rem',
        borderRadius: 'var(--radius-sm)',
        backgroundColor: bg,
        color,
        border: `1px solid ${border}`,
        fontSize: '0.72rem',
        fontWeight: 600,
        letterSpacing: '0.02em',
        whiteSpace: 'nowrap',
      }}
    >
      {label}
    </span>
  );
};
