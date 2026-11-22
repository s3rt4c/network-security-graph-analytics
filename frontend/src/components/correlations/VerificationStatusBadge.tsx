import React from 'react';
import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import type { CorrelationVerificationStatus } from '../../api/types';

interface VerificationStatusBadgeProps {
  status: CorrelationVerificationStatus;
}

/**
 * Accessible, non-color-only badge communicating the persisted verification
 * lifecycle status from the latest stored correlation evaluation.
 */
export const VerificationStatusBadge: React.FC<VerificationStatusBadgeProps> = ({ status }) => {
  const isVerified = status === 'verified';

  return (
    <span
      data-status={status}
      title={
        isVerified
          ? 'Persisted verification status from the latest correlation evaluation (not real-time revalidation).'
          : 'Previous correlation evidence was preserved, but the latest reevaluation could not establish completeness.'
      }
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        padding: '0.18rem 0.55rem',
        borderRadius: 'var(--radius-sm)',
        backgroundColor: isVerified ? 'var(--accent-emerald-dim)' : 'var(--accent-amber-dim)',
        color: isVerified ? 'var(--accent-emerald-hover)' : 'var(--accent-amber-hover)',
        border: isVerified
          ? '1px solid var(--accent-emerald-border)'
          : '1px dashed var(--accent-amber-border)',
        fontSize: '0.73rem',
        fontWeight: 600,
        lineHeight: 1.35,
        whiteSpace: 'nowrap',
      }}
    >
      {isVerified ? (
        <CheckCircle2 size={13} aria-hidden="true" />
      ) : (
        <AlertTriangle size={13} aria-hidden="true" />
      )}
      <span>
        {isVerified ? 'Verified' : 'Previously Verified — Current Check Incomplete'}
      </span>
    </span>
  );
};
