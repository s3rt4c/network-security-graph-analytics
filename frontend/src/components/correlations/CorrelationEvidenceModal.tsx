import React, { useEffect, useRef, useState } from 'react';
import { Check, Copy, ShieldAlert } from 'lucide-react';
import type { AlertFlowCorrelationResponse } from '../../api/types';
import { formatPersistedValue } from '../../utils/correlationHelpers';
import { Modal } from '../common/Modal';
import { VerificationStatusBadge } from './VerificationStatusBadge';

interface CorrelationEvidenceModalProps {
  correlation: AlertFlowCorrelationResponse | null;
  onClose: () => void;
}

interface EvidenceFieldRowProps {
  label: string;
  value: string | boolean | null;
  mono?: boolean;
  helperText?: string;
  copyAriaLabel?: string;
  copied?: boolean;
  onCopy?: (rawValue: string) => void;
}

const EvidenceFieldRow: React.FC<EvidenceFieldRowProps> = ({
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

/**
 * Read-only inspector modal displaying every persisted evidence field exposed by Phase 4C
 * for a selected AlertEvent–FlowObservation correlation edge.
 */
export const CorrelationEvidenceModal: React.FC<CorrelationEvidenceModalProps> = ({
  correlation,
  onClose,
}) => {
  const [copiedState, setCopiedState] = useState<{
    target: AlertFlowCorrelationResponse;
    field: string;
  } | null>(null);
  const copyTimerRef = useRef<number | null>(null);
  const isMountedRef = useRef<boolean>(true);
  const activeCorrelationRef = useRef<AlertFlowCorrelationResponse | null>(correlation);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    activeCorrelationRef.current = correlation;
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, [correlation]);

  const handleClose = () => {
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current);
      copyTimerRef.current = null;
    }
    setCopiedState(null);
    onClose();
  };

  const handleCopy = (
    target: AlertFlowCorrelationResponse,
    fieldKey: string,
    text: string
  ) => {
    if (!navigator.clipboard?.writeText) {
      return;
    }
    navigator.clipboard
      .writeText(text)
      .then(() => {
        if (!isMountedRef.current || activeCorrelationRef.current !== target) {
          return;
        }
        setCopiedState({ target, field: fieldKey });
        if (copyTimerRef.current !== null) {
          window.clearTimeout(copyTimerRef.current);
        }
        copyTimerRef.current = window.setTimeout(() => {
          if (!isMountedRef.current) {
            return;
          }
          setCopiedState(null);
          copyTimerRef.current = null;
        }, 2000);
      })
      .catch(() => {
        // Ignore clipboard permission errors cleanly
      });
  };

  if (!correlation) {
    return null;
  }

  const isFieldCopied = (fieldKey: string) =>
    copiedState?.target === correlation && copiedState.field === fieldKey;

  const isKnownStatus =
    correlation.verification_status === 'verified' ||
    correlation.verification_status === 'unverified_incomplete';

  return (
    <Modal
      isOpen={true}
      onClose={handleClose}
      title="Persisted Correlation Evidence Inspector"
      maxWidth="780px"
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '0.75rem',
          }}
        >
          <VerificationStatusBadge status={correlation.verification_status} />
          <span
            className="font-mono"
            style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}
          >
            RoutingDomain: {correlation.routing_domain_id}
          </span>
        </div>

        {correlation.verification_status === 'unverified_incomplete' && (
          <div className="warning-banner" role="note">
            <strong>Unverified Incomplete Status:</strong> The previous correlation evidence was
            preserved, but the latest reevaluation could not establish completeness. This does
            not prove the original correlation remains valid.
          </div>
        )}

        {!isKnownStatus && (
          <div
            role="note"
            style={{
              backgroundColor: 'var(--accent-rose-dim)',
              border: '1px solid var(--accent-rose-border)',
              color: 'var(--accent-rose-hover)',
              padding: '0.55rem 0.8rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.82rem',
            }}
          >
            <strong>Unrecognized Verification Status:</strong> This record carries an unexpected
            verification status value and must not be treated as verified.
          </div>
        )}

        <div className="info-banner" style={{ alignItems: 'flex-start' }}>
          <ShieldAlert size={16} aria-hidden="true" style={{ flexShrink: 0, marginTop: '0.1rem' }} />
          <div>
            <strong>Observational Evidence Boundary:</strong> Persisted evidence records a
            conservative observational association from the last stored correlation evaluation.
            It is not real-time revalidation and does not prove causation, system compromise, or
            attacker/victim attribution.
          </div>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 240px), 1fr))',
            gap: '0.7rem',
          }}
        >
          <EvidenceFieldRow
            label="AlertEvent ID"
            value={correlation.event_id}
            mono
            copyAriaLabel="Copy full AlertEvent ID"
            copied={isFieldCopied('event_id')}
            onCopy={(val) => handleCopy(correlation, 'event_id', val)}
          />
          <EvidenceFieldRow
            label="FlowObservation ID"
            value={correlation.observation_id}
            mono
            copyAriaLabel="Copy full FlowObservation ID"
            copied={isFieldCopied('observation_id')}
            onCopy={(val) => handleCopy(correlation, 'observation_id', val)}
          />
          <EvidenceFieldRow
            label="Zeek UID"
            value={correlation.zeek_uid}
            mono
          />
          <EvidenceFieldRow
            label="RoutingDomain"
            value={correlation.routing_domain_id}
            mono
          />
          <EvidenceFieldRow
            label="Correlation Method"
            value={correlation.correlation_method}
            mono
          />
          <EvidenceFieldRow
            label="Tuple Orientation"
            value={correlation.tuple_orientation}
            mono
          />
          <EvidenceFieldRow
            label="Community ID Agreement"
            value={correlation.community_id_agreement}
            mono
          />
          <EvidenceFieldRow
            label="Temporal Relation"
            value={correlation.temporal_relation}
            mono
          />
          <EvidenceFieldRow
            label="Exact Temporal Delta (seconds)"
            value={correlation.temporal_delta_decimal}
            mono
            helperText="Verbatim arbitrary-precision Decimal string (not converted to floating-point)."
          />
          <EvidenceFieldRow
            label="Decimal Fallback Used"
            value={correlation.used_decimal_fallback}
            mono
          />
          <EvidenceFieldRow
            label="Sensor Context"
            value={correlation.sensor_context}
            mono
          />
          <EvidenceFieldRow
            label="Evidence Version"
            value={correlation.evidence_version}
            mono
          />
          <EvidenceFieldRow
            label="Policy Fingerprint"
            value={correlation.policy_fingerprint}
            mono
            copyAriaLabel="Copy full Policy Fingerprint"
            copied={isFieldCopied('policy_fingerprint')}
            onCopy={(val) => handleCopy(correlation, 'policy_fingerprint', val)}
          />
          <EvidenceFieldRow
            label="Evidence Digest"
            value={correlation.evidence_digest}
            mono
            helperText="Integrity / identity artifact of persisted evidence and policy — not a confidence score."
            copyAriaLabel="Copy full Evidence Digest"
            copied={isFieldCopied('evidence_digest')}
            onCopy={(val) => handleCopy(correlation, 'evidence_digest', val)}
          />
          <EvidenceFieldRow
            label="Decision Timestamp"
            value={correlation.decided_at_utc}
            mono
          />
          <EvidenceFieldRow
            label="Verification Status"
            value={correlation.verification_status}
            mono
          />
          <EvidenceFieldRow
            label="Last Incomplete Reason"
            value={correlation.last_incomplete_reason}
            mono
          />
          <EvidenceFieldRow
            label="Last Incomplete Timestamp"
            value={correlation.last_incomplete_at_utc}
            mono
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: '0.25rem' }}>
          <button type="button" className="btn-secondary" onClick={handleClose}>
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
};
