import React from 'react';
import { ShieldAlert } from 'lucide-react';
import type { FlowObservationDetailResponse } from '../../api/types';
import type { CorrelationErrorSummary } from '../../utils/correlationHelpers';
import { EvidenceFieldRow, ObservationDetailAsyncState } from './EvidenceFieldRow';

interface FlowObservationDetailPanelProps {
  data: FlowObservationDetailResponse | null;
  loading: boolean;
  error: CorrelationErrorSummary | null;
  onRetry: () => void;
  isFieldCopied: (fieldKey: string) => boolean;
  onCopyField: (fieldKey: string, value: string) => void;
}

const GRID_STYLE: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 220px), 1fr))',
  gap: '0.7rem',
};

const SECTION_HEADING_STYLE: React.CSSProperties = {
  fontSize: '0.76rem',
  fontWeight: 700,
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  color: 'var(--text-secondary)',
  marginBottom: '0.45rem',
};

/**
 * Forensic inspection view for a persisted V2 Zeek FlowObservation.
 */
export const FlowObservationDetailPanel: React.FC<FlowObservationDetailPanelProps> = ({
  data,
  loading,
  error,
  onRetry,
  isFieldCopied,
  onCopyField,
}) => {
  if (loading || error) {
    return (
      <ObservationDetailAsyncState
        loadingLabel="Loading Zeek FlowObservation details"
        loading={loading}
        error={error}
        onRetry={onRetry}
      />
    );
  }

  if (!data) {
    return null;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="info-banner" style={{ alignItems: 'flex-start' }}>
        <ShieldAlert size={16} aria-hidden="true" style={{ flexShrink: 0, marginTop: '0.1rem' }} />
        <div>
          <strong>Zeek Observation Notice:</strong> Originator and responder fields reflect Zeek
          connection tracking only and do <strong>not</strong> attribute attacker or victim roles.{' '}
          <code>end_ts</code> is derived from <code>start_epoch + duration</code> as a
          last-observed timestamp and is <strong>not</strong> proof of TCP session closure.{' '}
          <code>conn_state=&quot;SF&quot;</code> does <strong>not</strong> universally prove benign
          traffic or successful application activity.
        </div>
      </div>

      <section aria-label="Zeek connection identity and endpoints">
        <h3 style={SECTION_HEADING_STYLE}>Connection Summary &amp; Endpoints</h3>
        <div style={GRID_STYLE}>
          <EvidenceFieldRow
            label="Zeek UID"
            value={data.zeek_uid}
            mono
            copyAriaLabel="Copy Zeek UID"
            copied={isFieldCopied('detail_zeek_uid')}
            onCopy={(val) => onCopyField('detail_zeek_uid', val)}
          />
          <EvidenceFieldRow label="Protocol" value={data.protocol} mono />
          <EvidenceFieldRow label="Service" value={data.service} mono />
          <EvidenceFieldRow
            label="Connection State (conn_state)"
            value={data.conn_state}
            mono
            helperText="Recorded Zeek state summary; SF alone does not establish benign activity."
          />
          <EvidenceFieldRow label="History" value={data.history} mono />
          <EvidenceFieldRow label="RoutingDomain" value={data.routing_domain_id} mono />
          <EvidenceFieldRow
            label="Source IP"
            value={data.src_ip}
            mono
            helperText="Zeek originator IP (not attacker attribution)."
          />
          <EvidenceFieldRow label="Source Port" value={data.src_port} mono />
          <EvidenceFieldRow
            label="Destination IP"
            value={data.dst_ip}
            mono
            helperText="Zeek responder IP (not victim attribution)."
          />
          <EvidenceFieldRow label="Destination Port" value={data.dst_port} mono />
          <EvidenceFieldRow label="Community ID" value={data.community_id} mono />
        </div>
      </section>

      <section aria-label="Zeek observation timestamps">
        <h3 style={SECTION_HEADING_STYLE}>Time Evidence</h3>
        <div style={GRID_STYLE}>
          <EvidenceFieldRow label="Start Timestamp (start_ts)" value={data.start_ts} mono />
          <EvidenceFieldRow
            label="Derived Last-Observed Timestamp (end_ts)"
            value={data.end_ts}
            mono
            helperText="Derived (start_epoch + duration); not confirmed TCP session closure."
          />
          <EvidenceFieldRow
            label="Start Epoch (Decimal s)"
            value={data.start_epoch_decimal}
            mono
            helperText="Verbatim arbitrary-precision Decimal epoch string."
          />
          <EvidenceFieldRow
            label="Derived End Epoch (Decimal s)"
            value={data.end_epoch_decimal}
            mono
            helperText="Verbatim arbitrary-precision Decimal epoch string."
          />
          <EvidenceFieldRow
            label="Duration (Decimal s)"
            value={data.duration_decimal}
            mono
            helperText="Verbatim arbitrary-precision Decimal string."
          />
        </div>
      </section>

      <section aria-label="Traffic volume metrics">
        <h3 style={SECTION_HEADING_STYLE}>Traffic Metrics (Payload vs IP Bytes vs Packets)</h3>
        <div style={GRID_STYLE}>
          <EvidenceFieldRow label="Originator Payload Bytes (orig_bytes)" value={data.orig_bytes} mono />
          <EvidenceFieldRow label="Responder Payload Bytes (resp_bytes)" value={data.resp_bytes} mono />
          <EvidenceFieldRow label="Originator IP Bytes (orig_ip_bytes)" value={data.orig_ip_bytes} mono />
          <EvidenceFieldRow label="Responder IP Bytes (resp_ip_bytes)" value={data.resp_ip_bytes} mono />
          <EvidenceFieldRow label="Originator Packets (orig_pkts)" value={data.orig_pkts} mono />
          <EvidenceFieldRow label="Responder Packets (resp_pkts)" value={data.resp_pkts} mono />
          <EvidenceFieldRow label="Missed Bytes (missed_bytes)" value={data.missed_bytes} mono />
        </div>
      </section>

      <section aria-label="Sensor and locality metadata">
        <h3 style={SECTION_HEADING_STYLE}>Sensor &amp; Locality Metadata</h3>
        <div style={GRID_STYLE}>
          <EvidenceFieldRow label="Sensor" value={data.sensor_id} mono />
          <EvidenceFieldRow label="Source Type" value={data.source_type} mono />
          <EvidenceFieldRow label="Local Originator (local_orig)" value={data.local_orig} mono />
          <EvidenceFieldRow label="Local Responder (local_resp)" value={data.local_resp} mono />
        </div>
      </section>

      <details
        style={{
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-sm)',
          padding: '0.7rem 0.85rem',
          backgroundColor: 'var(--bg-surface-secondary)',
        }}
      >
        <summary
          style={{
            cursor: 'pointer',
            fontSize: '0.8rem',
            fontWeight: 600,
            color: 'var(--text-primary)',
          }}
        >
          Provenance &amp; Identity
        </summary>
        <div style={{ ...GRID_STYLE, marginTop: '0.75rem' }}>
          <EvidenceFieldRow
            label="FlowObservation ID"
            value={data.observation_id}
            mono
            copyAriaLabel="Copy Zeek FlowObservation ID"
            copied={isFieldCopied('detail_observation_id')}
            onCopy={(val) => onCopyField('detail_observation_id', val)}
          />
          <EvidenceFieldRow
            label="Flow Key"
            value={data.flow_key}
            mono
            copyAriaLabel="Copy Flow Key"
            copied={isFieldCopied('detail_flow_key')}
            onCopy={(val) => onCopyField('detail_flow_key', val)}
          />
          <EvidenceFieldRow label="Source Scoped ID" value={data.src_scoped_id} mono />
          <EvidenceFieldRow label="Destination Scoped ID" value={data.dst_scoped_id} mono />
          <EvidenceFieldRow label="Source Provenance" value={data.source_provenance} mono />
        </div>
      </details>
    </div>
  );
};
