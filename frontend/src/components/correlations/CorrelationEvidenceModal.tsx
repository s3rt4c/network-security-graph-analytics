import React, { useCallback, useEffect, useRef, useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import { getAlertEvent, getFlowObservation } from '../../api/observations';
import type {
  AlertEventDetailResponse,
  AlertFlowCorrelationResponse,
  FlowObservationDetailResponse,
} from '../../api/types';
import {
  describeObservationDetailApiError,
  type CorrelationErrorSummary,
} from '../../utils/correlationHelpers';
import { Modal } from '../common/Modal';
import { AlertEventDetailPanel } from './AlertEventDetailPanel';
import { EvidenceFieldRow } from './EvidenceFieldRow';
import { FlowObservationDetailPanel } from './FlowObservationDetailPanel';
import { VerificationStatusBadge } from './VerificationStatusBadge';

export type InspectorTab = 'evidence' | 'alert' | 'flow';

interface CorrelationEvidenceModalProps {
  correlation: AlertFlowCorrelationResponse | null;
  initialTab?: InspectorTab;
  onClose: () => void;
}

interface DetailSlotState<T> {
  correlationKey: string;
  status: 'idle' | 'success' | 'error';
  data: T | null;
  error: CorrelationErrorSummary | null;
}

const INSPECTOR_TABS: ReadonlyArray<{ id: InspectorTab; label: string }> = [
  { id: 'evidence', label: 'Correlation Evidence' },
  { id: 'alert', label: 'Suricata AlertEvent' },
  { id: 'flow', label: 'Zeek FlowObservation' },
];

function buildCorrelationKey(
  correlation: AlertFlowCorrelationResponse | null,
  initialTab: InspectorTab
): string {
  if (!correlation) {
    return '';
  }
  return `${correlation.routing_domain_id}|${correlation.event_id}|${correlation.observation_id}|${initialTab}`;
}

function buildDataCacheKey(correlation: AlertFlowCorrelationResponse | null): string {
  if (!correlation) {
    return '';
  }
  return `${correlation.routing_domain_id}|${correlation.event_id}|${correlation.observation_id}`;
}

function createIdleSlot<T>(correlationKey: string): DetailSlotState<T> {
  return {
    correlationKey,
    status: 'idle',
    data: null,
    error: null,
  };
}

/**
 * Read-only three-tab correlation inspector modal displaying:
 * 1. Persisted Correlation Evidence (default)
 * 2. Lazily fetched Suricata AlertEvent & AlertDefinition details
 * 3. Lazily fetched Zeek FlowObservation details
 */
export const CorrelationEvidenceModal: React.FC<CorrelationEvidenceModalProps> = ({
  correlation,
  initialTab = 'evidence',
  onClose,
}) => {
  const dataKey = buildDataCacheKey(correlation);
  const tabScopeKey = buildCorrelationKey(correlation, initialTab);

  const [tabState, setTabState] = useState<{ scopeKey: string; tab: InspectorTab }>(() => ({
    scopeKey: tabScopeKey,
    tab: initialTab,
  }));
  const [alertSlot, setAlertSlot] = useState<DetailSlotState<AlertEventDetailResponse>>(() =>
    createIdleSlot<AlertEventDetailResponse>(dataKey)
  );
  const [flowSlot, setFlowSlot] = useState<DetailSlotState<FlowObservationDetailResponse>>(() =>
    createIdleSlot<FlowObservationDetailResponse>(dataKey)
  );
  const [alertRetryNonce, setAlertRetryNonce] = useState<number>(0);
  const [flowRetryNonce, setFlowRetryNonce] = useState<number>(0);
  const [copiedState, setCopiedState] = useState<{
    target: AlertFlowCorrelationResponse;
    field: string;
  } | null>(null);

  const activeTab: InspectorTab = tabState.scopeKey === tabScopeKey ? tabState.tab : initialTab;

  const effectiveAlertSlot =
    alertSlot.correlationKey === dataKey
      ? alertSlot
      : createIdleSlot<AlertEventDetailResponse>(dataKey);

  const effectiveFlowSlot =
    flowSlot.correlationKey === dataKey
      ? flowSlot
      : createIdleSlot<FlowObservationDetailResponse>(dataKey);

  const copyTimerRef = useRef<number | null>(null);
  const isMountedRef = useRef<boolean>(true);
  const activeCorrelationRef = useRef<AlertFlowCorrelationResponse | null>(correlation);
  const activeDataKeyRef = useRef<string>(dataKey);

  const alertReqIdRef = useRef<number>(0);
  const flowReqIdRef = useRef<number>(0);
  const alertControllerRef = useRef<AbortController | null>(null);
  const flowControllerRef = useRef<AbortController | null>(null);
  const tabRefs = useRef<Record<InspectorTab, HTMLButtonElement | null>>({
    evidence: null,
    alert: null,
    flow: null,
  });

  const abortPendingDetailRequests = useCallback(() => {
    alertReqIdRef.current += 1;
    flowReqIdRef.current += 1;
    if (alertControllerRef.current) {
      alertControllerRef.current.abort();
      alertControllerRef.current = null;
    }
    if (flowControllerRef.current) {
      flowControllerRef.current.abort();
      flowControllerRef.current = null;
    }
  }, []);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      abortPendingDetailRequests();
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, [abortPendingDetailRequests]);

  useEffect(() => {
    activeCorrelationRef.current = correlation;
    activeDataKeyRef.current = dataKey;
    return () => {
      abortPendingDetailRequests();
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, [correlation, dataKey, abortPendingDetailRequests]);

  // Lazy AlertEvent fetch (only when Suricata tab is active and slot is idle)
  useEffect(() => {
    if (!correlation || !dataKey || activeTab !== 'alert' || effectiveAlertSlot.status !== 'idle') {
      return;
    }

    if (alertControllerRef.current) {
      alertControllerRef.current.abort();
    }
    const controller = new AbortController();
    alertControllerRef.current = controller;
    const reqId = ++alertReqIdRef.current;
    const target = correlation;
    const targetKey = dataKey;

    getAlertEvent(target.event_id, target.routing_domain_id, controller.signal)
      .then((data) => {
        if (
          controller.signal.aborted ||
          !isMountedRef.current ||
          activeDataKeyRef.current !== targetKey ||
          activeCorrelationRef.current !== target ||
          alertReqIdRef.current !== reqId
        ) {
          return;
        }
        setAlertSlot({
          correlationKey: targetKey,
          status: 'success',
          data,
          error: null,
        });
      })
      .catch((err: unknown) => {
        if (
          controller.signal.aborted ||
          !isMountedRef.current ||
          activeDataKeyRef.current !== targetKey ||
          activeCorrelationRef.current !== target ||
          alertReqIdRef.current !== reqId
        ) {
          return;
        }
        setAlertSlot({
          correlationKey: targetKey,
          status: 'error',
          data: null,
          error: describeObservationDetailApiError(err, {
            entityKind: 'AlertEvent',
            entityId: target.event_id,
            routingDomainId: target.routing_domain_id,
          }),
        });
      });

    return () => {
      alertReqIdRef.current += 1;
      controller.abort();
    };
  }, [correlation, dataKey, activeTab, effectiveAlertSlot.status, alertRetryNonce]);

  // Lazy FlowObservation fetch (only when Zeek tab is active and slot is idle)
  useEffect(() => {
    if (!correlation || !dataKey || activeTab !== 'flow' || effectiveFlowSlot.status !== 'idle') {
      return;
    }

    if (flowControllerRef.current) {
      flowControllerRef.current.abort();
    }
    const controller = new AbortController();
    flowControllerRef.current = controller;
    const reqId = ++flowReqIdRef.current;
    const target = correlation;
    const targetKey = dataKey;

    getFlowObservation(target.observation_id, target.routing_domain_id, controller.signal)
      .then((data) => {
        if (
          controller.signal.aborted ||
          !isMountedRef.current ||
          activeDataKeyRef.current !== targetKey ||
          activeCorrelationRef.current !== target ||
          flowReqIdRef.current !== reqId
        ) {
          return;
        }
        setFlowSlot({
          correlationKey: targetKey,
          status: 'success',
          data,
          error: null,
        });
      })
      .catch((err: unknown) => {
        if (
          controller.signal.aborted ||
          !isMountedRef.current ||
          activeDataKeyRef.current !== targetKey ||
          activeCorrelationRef.current !== target ||
          flowReqIdRef.current !== reqId
        ) {
          return;
        }
        setFlowSlot({
          correlationKey: targetKey,
          status: 'error',
          data: null,
          error: describeObservationDetailApiError(err, {
            entityKind: 'FlowObservation',
            entityId: target.observation_id,
            routingDomainId: target.routing_domain_id,
          }),
        });
      });

    return () => {
      flowReqIdRef.current += 1;
      controller.abort();
    };
  }, [correlation, dataKey, activeTab, effectiveFlowSlot.status, flowRetryNonce]);

  const handleClose = () => {
    abortPendingDetailRequests();
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current);
      copyTimerRef.current = null;
    }
    setCopiedState(null);
    onClose();
  };

  const handleRetryAlert = () => {
    setAlertSlot(createIdleSlot<AlertEventDetailResponse>(dataKey));
    setAlertRetryNonce((n) => n + 1);
  };

  const handleRetryFlow = () => {
    setFlowSlot(createIdleSlot<FlowObservationDetailResponse>(dataKey));
    setFlowRetryNonce((n) => n + 1);
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

  const handleTabKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>, currentIndex: number) => {
    let nextIndex: number | null = null;
    if (e.key === 'ArrowRight') {
      nextIndex = (currentIndex + 1) % INSPECTOR_TABS.length;
    } else if (e.key === 'ArrowLeft') {
      nextIndex = (currentIndex - 1 + INSPECTOR_TABS.length) % INSPECTOR_TABS.length;
    } else if (e.key === 'Home') {
      nextIndex = 0;
    } else if (e.key === 'End') {
      nextIndex = INSPECTOR_TABS.length - 1;
    }

    if (nextIndex !== null) {
      e.preventDefault();
      const nextTab = INSPECTOR_TABS[nextIndex].id;
      setTabState({ scopeKey: tabScopeKey, tab: nextTab });
      tabRefs.current[nextTab]?.focus();
    }
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
      maxWidth="840px"
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

        {/* Accessible Three-Tab Switcher */}
        <div
          role="tablist"
          aria-label="Correlation inspection views"
          style={{
            display: 'flex',
            gap: '0.35rem',
            flexWrap: 'wrap',
            borderBottom: '1px solid var(--border-subtle)',
            paddingBottom: '0.5rem',
          }}
        >
          {INSPECTOR_TABS.map((tab, idx) => {
            const isSelected = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                ref={(el) => {
                  tabRefs.current[tab.id] = el;
                }}
                id={`inspector-tab-${tab.id}`}
                type="button"
                role="tab"
                aria-selected={isSelected}
                aria-controls={`inspector-panel-${tab.id}`}
                tabIndex={isSelected ? 0 : -1}
                className={isSelected ? 'btn-primary' : 'btn-secondary'}
                onClick={() => setTabState({ scopeKey: tabScopeKey, tab: tab.id })}
                onKeyDown={(e) => handleTabKeyDown(e, idx)}
                style={{ fontSize: '0.8rem', padding: '0.4rem 0.75rem' }}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Active Tab Panel */}
        <div
          id={`inspector-panel-${activeTab}`}
          role="tabpanel"
          aria-labelledby={`inspector-tab-${activeTab}`}
          tabIndex={0}
        >
          {activeTab === 'evidence' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
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
                  <strong>Unrecognized Verification Status:</strong> This record carries an
                  unexpected verification status value and must not be treated as verified.
                </div>
              )}

              <div className="info-banner" style={{ alignItems: 'flex-start' }}>
                <ShieldAlert
                  size={16}
                  aria-hidden="true"
                  style={{ flexShrink: 0, marginTop: '0.1rem' }}
                />
                <div>
                  <strong>Observational Evidence Boundary:</strong> Persisted evidence records a
                  conservative observational association from the last stored correlation evaluation.
                  It is not real-time revalidation and does not prove causation, system compromise,
                  or attacker/victim attribution.
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
                <EvidenceFieldRow label="Zeek UID" value={correlation.zeek_uid} mono />
                <EvidenceFieldRow label="RoutingDomain" value={correlation.routing_domain_id} mono />
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
                <EvidenceFieldRow label="Sensor Context" value={correlation.sensor_context} mono />
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
            </div>
          )}

          {activeTab === 'alert' && (
            <AlertEventDetailPanel
              data={effectiveAlertSlot.data}
              loading={effectiveAlertSlot.status === 'idle'}
              error={effectiveAlertSlot.error}
              onRetry={handleRetryAlert}
              isFieldCopied={isFieldCopied}
              onCopyField={(fieldKey, val) => handleCopy(correlation, fieldKey, val)}
            />
          )}

          {activeTab === 'flow' && (
            <FlowObservationDetailPanel
              data={effectiveFlowSlot.data}
              loading={effectiveFlowSlot.status === 'idle'}
              error={effectiveFlowSlot.error}
              onRetry={handleRetryFlow}
              isFieldCopied={isFieldCopied}
              onCopyField={(fieldKey, val) => handleCopy(correlation, fieldKey, val)}
            />
          )}
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
