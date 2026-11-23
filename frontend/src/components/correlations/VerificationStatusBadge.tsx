import React from 'react';
import { AlertTriangle, CheckCircle2, HelpCircle } from 'lucide-react';
import type { CorrelationVerificationStatus } from '../../api/types';

interface VerificationStatusBadgeProps {
  status: CorrelationVerificationStatus | string;
}

/**
 * Accessible, non-color-only badge communicating the persisted verification
 * lifecycle status from the latest stored correlation evaluation.
 * Never presents unknown or unrecognized runtime values as verified.
 */
export const VerificationStatusBadge: React.FC<VerificationStatusBadgeProps> = ({ status }) => {
  const isVerified = status === 'verified';
  const isUnverifiedIncomplete = status === 'unverified_incomplete';

  const normalizedDataStatus = isVerified
    ? 'verified'
    : isUnverifiedIncomplete
      ? 'unverified_incomplete'
      : 'unknown';

  const title = isVerified
    ? 'Persisted verification status from the latest correlation evaluation (not real-time revalidation).'
    : isUnverifiedIncomplete
      ? 'Previous correlation evidence was preserved, but the latest reevaluation could not establish completeness.'
      : 'Unrecognized verification status value; do not treat this relationship as verified.';

  const backgroundColor = isVerified
    ? 'var(--accent-emerald-dim)'
    : isUnverifiedIncomplete
      ? 'var(--accent-amber-dim)'
      : 'var(--accent-rose-dim)';

  const color = isVerified
    ? 'var(--accent-emerald-hover)'
    : isUnverifiedIncomplete
      ? 'var(--accent-amber-hover)'
      : 'var(--accent-rose-hover)';

  const border = isVerified
    ? '1px solid var(--accent-emerald-border)'
    : isUnverifiedIncomplete
      ? '1px dashed var(--accent-amber-border)'
      : '1px dotted var(--accent-rose-border)';

  const label = isVerified
    ? 'Verified'
    : isUnverifiedIncomplete
      ? 'Previously Verified — Current Check Incomplete'
      : 'Unknown Verification Status';

  return (
    <span
      data-status={normalizedDataStatus}
      title={title}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        padding: '0.18rem 0.55rem',
        borderRadius: 'var(--radius-sm)',
        backgroundColor,
        color,
        border,
        fontSize: '0.73rem',
        fontWeight: 600,
        lineHeight: 1.35,
        whiteSpace: 'normal',
        overflowWrap: 'anywhere',
        maxWidth: '100%',
      }}
    >
      {isVerified ? (
        <CheckCircle2 size={13} aria-hidden="true" style={{ flexShrink: 0 }} />
      ) : isUnverifiedIncomplete ? (
        <AlertTriangle size={13} aria-hidden="true" style={{ flexShrink: 0 }} />
      ) : (
        <HelpCircle size={13} aria-hidden="true" style={{ flexShrink: 0 }} />
      )}
      <span>{label}</span>
    </span>
  );
};
