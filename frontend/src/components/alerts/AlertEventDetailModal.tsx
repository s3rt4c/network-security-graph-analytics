import React, { useCallback, useEffect, useRef, useState } from 'react';
import { getAlertEvent } from '../../api/observations';
import type { AlertEventDetailResponse, AlertEventTriageItemResponse } from '../../api/types';
import {
  describeObservationDetailApiError,
  type CorrelationErrorSummary,
} from '../../utils/correlationHelpers';
import { Tag } from '../common/Badge';
import { Modal } from '../common/Modal';
import { AlertEventDetailPanel } from '../correlations/AlertEventDetailPanel';

interface AlertEventDetailModalProps {
  target: AlertEventTriageItemResponse | null;
  onClose: () => void;
}

interface AlertEventDetailModalContentProps {
  target: AlertEventTriageItemResponse;
  onClose: () => void;
}

interface DetailSlotState {
  target: AlertEventTriageItemResponse;
  status: 'idle' | 'success' | 'error';
  data: AlertEventDetailResponse | null;
  error: CorrelationErrorSummary | null;
}

function createIdleSlot(target: AlertEventTriageItemResponse): DetailSlotState {
  return {
    target,
    status: 'idle',
    data: null,
    error: null,
  };
}

const AlertEventDetailModalContent: React.FC<AlertEventDetailModalContentProps> = ({
  target,
  onClose,
}) => {
  const [slot, setSlot] = useState<DetailSlotState>(() => createIdleSlot(target));
  const [retryNonce, setRetryNonce] = useState<number>(0);
  const [copiedState, setCopiedState] = useState<{
    target: AlertEventTriageItemResponse;
    field: string;
  } | null>(null);

  const effectiveSlot = slot.target === target ? slot : createIdleSlot(target);

  const isMountedRef = useRef<boolean>(true);
  const activeTargetRef = useRef<AlertEventTriageItemResponse>(target);
  const reqIdRef = useRef<number>(0);
  const controllerRef = useRef<AbortController | null>(null);
  const copyTimerRef = useRef<number | null>(null);

  const abortPendingRequest = useCallback(() => {
    reqIdRef.current += 1;
    if (controllerRef.current) {
      controllerRef.current.abort();
      controllerRef.current = null;
    }
  }, []);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      abortPendingRequest();
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, [abortPendingRequest]);

  useEffect(() => {
    activeTargetRef.current = target;
    return () => {
      abortPendingRequest();
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, [target, abortPendingRequest]);

  useEffect(() => {
    if (effectiveSlot.status !== 'idle') {
      return;
    }

    if (controllerRef.current) {
      controllerRef.current.abort();
    }
    const controller = new AbortController();
    controllerRef.current = controller;
    const reqId = ++reqIdRef.current;
    const currentTarget = target;

    getAlertEvent(currentTarget.event_id, currentTarget.routing_domain_id, controller.signal)
      .then((data) => {
        if (
          controller.signal.aborted ||
          !isMountedRef.current ||
          activeTargetRef.current !== currentTarget ||
          reqIdRef.current !== reqId
        ) {
          return;
        }
        setSlot({
          target: currentTarget,
          status: 'success',
          data,
          error: null,
        });
      })
      .catch((err: unknown) => {
        if (
          controller.signal.aborted ||
          !isMountedRef.current ||
          activeTargetRef.current !== currentTarget ||
          reqIdRef.current !== reqId
        ) {
          return;
        }
        setSlot({
          target: currentTarget,
          status: 'error',
          data: null,
          error: describeObservationDetailApiError(err, {
            entityKind: 'AlertEvent',
            entityId: currentTarget.event_id,
            routingDomainId: currentTarget.routing_domain_id,
          }),
        });
      });

    return () => {
      reqIdRef.current += 1;
      controller.abort();
      if (controllerRef.current === controller) {
        controllerRef.current = null;
      }
    };
  }, [target, effectiveSlot.status, retryNonce]);

  const handleClose = () => {
    abortPendingRequest();
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current);
      copyTimerRef.current = null;
    }
    setCopiedState(null);
    onClose();
  };

  const handleRetry = () => {
    setSlot(createIdleSlot(target));
    setRetryNonce((n) => n + 1);
  };

  const handleCopyField = (fieldKey: string, text: string) => {
    if (!navigator.clipboard?.writeText) {
      return;
    }
    const currentTarget = target;
    navigator.clipboard
      .writeText(text)
      .then(() => {
        if (!isMountedRef.current || activeTargetRef.current !== currentTarget) {
          return;
        }
        setCopiedState({ target: currentTarget, field: fieldKey });
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

  const isFieldCopied = (fieldKey: string) =>
    copiedState?.target === target && copiedState.field === fieldKey;

  return (
    <Modal
      isOpen={true}
      onClose={handleClose}
      title="Suricata AlertEvent Forensic Detail"
      maxWidth="840px"
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '0.6rem',
          }}
        >
          <Tag
            label={
              target.has_persisted_correlation
                ? 'Persisted link present'
                : 'No persisted link recorded'
            }
            variant={target.has_persisted_correlation ? 'emerald' : 'slate'}
          />
          <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            RoutingDomain: {target.routing_domain_id}
          </span>
        </div>

        {!target.has_persisted_correlation && (
          <div className="info-banner" role="note">
            <span>ℹ</span>
            <div>
              <strong>No Persisted Correlation Edge Recorded:</strong> This AlertEvent can be
              investigated independently using Phase 4F.1 telemetry. The absence of a persisted{' '}
              <code>CORRELATED_WITH</code> relationship does not establish a correlation decision
              (<code>REJECTED</code>, <code>AMBIGUOUS</code>, <code>INSUFFICIENT</code>) or a
              benign security verdict.
            </div>
          </div>
        )}

        <AlertEventDetailPanel
          data={effectiveSlot.data}
          loading={effectiveSlot.status === 'idle'}
          error={effectiveSlot.error}
          onRetry={handleRetry}
          isFieldCopied={isFieldCopied}
          onCopyField={handleCopyField}
        />

        <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: '0.25rem' }}>
          <button type="button" className="btn-secondary" onClick={handleClose}>
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
};

/**
 * Independent Suricata AlertEvent detail inspector modal reusing Phase 4F.1 AlertEventDetailPanel.
 * Operates without requiring an observation_id or persisted CORRELATED_WITH relationship.
 */
export const AlertEventDetailModal: React.FC<AlertEventDetailModalProps> = ({
  target,
  onClose,
}) => {
  if (!target) {
    return null;
  }
  return <AlertEventDetailModalContent target={target} onClose={onClose} />;
};
