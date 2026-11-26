import React from 'react';
import { ShieldAlert } from 'lucide-react';
import type { AlertEventDetailResponse } from '../../api/types';
import type { CorrelationErrorSummary } from '../../utils/correlationHelpers';
import { EvidenceFieldRow, ObservationDetailAsyncState } from './EvidenceFieldRow';

interface AlertEventDetailPanelProps {
  data: AlertEventDetailResponse | null;
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
 * Forensic inspection view for a persisted V2 Suricata AlertEvent and linked AlertDefinition.
 */
export const AlertEventDetailPanel: React.FC<AlertEventDetailPanelProps> = ({
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
        loadingLabel="Loading Suricata AlertEvent details"
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
          <strong>Suricata Telemetry Notice:</strong> Source and destination fields reflect observed
          packet direction and do <strong>not</strong> prove attacker or victim roles. Recorded{' '}
          <code>action</code> reflects rule/alert metadata only and does <strong>not</strong>{' '}
          independently establish end-to-end network enforcement. No confidence score or
          compromise verdict is asserted.
        </div>
      </div>

      <section aria-label="Rule and alert metadata">
        <h3 style={SECTION_HEADING_STYLE}>Rule &amp; Alert Metadata</h3>
        <div style={GRID_STYLE}>
          <EvidenceFieldRow label="Signature" value={data.signature} />
          <EvidenceFieldRow label="SID" value={data.sid} mono />
          <EvidenceFieldRow label="GID" value={data.gid} mono />
          <EvidenceFieldRow label="REV" value={data.rev} mono />
          <EvidenceFieldRow label="Severity" value={data.severity} mono />
          <EvidenceFieldRow label="Category" value={data.category} />
          <EvidenceFieldRow
            label="Engine"
            value={data.engine}
            mono
            helperText="Resolved factually from linked AlertDefinition (Not recorded if unlinked)."
          />
          <EvidenceFieldRow label="Ruleset Namespace" value={data.ruleset_namespace} mono />
          <EvidenceFieldRow
            label="Action"
            value={data.action}
            mono
            helperText="Recorded rule/alert action metadata; not proof of end-to-end enforcement."
          />
          <EvidenceFieldRow label="App Protocol" value={data.app_proto} mono />
          <EvidenceFieldRow label="Direction" value={data.direction} mono />
          <EvidenceFieldRow
            label="Flow ID"
            value={data.flow_id}
            mono
            helperText="Lossless uint64 decimal identifier string."
          />
          <EvidenceFieldRow label="TX ID" value={data.tx_id} mono />
          <EvidenceFieldRow label="Packet Count (pcap_cnt)" value={data.pcap_cnt} mono />
        </div>
      </section>

      <section aria-label="Network evidence">
        <h3 style={SECTION_HEADING_STYLE}>Network Evidence (Observed Direction)</h3>
        <div style={GRID_STYLE}>
          <EvidenceFieldRow
            label="Source IP"
            value={data.src_ip}
            mono
            helperText="Observed packet source (not attacker proof)."
          />
          <EvidenceFieldRow label="Source Port" value={data.src_port} mono />
          <EvidenceFieldRow
            label="Destination IP"
            value={data.dst_ip}
            mono
            helperText="Observed packet destination (not victim proof)."
          />
          <EvidenceFieldRow label="Destination Port" value={data.dst_port} mono />
          <EvidenceFieldRow label="Protocol" value={data.protocol} mono />
          <EvidenceFieldRow label="Community ID" value={data.community_id} mono />
          <EvidenceFieldRow label="RoutingDomain" value={data.routing_domain_id} mono />
          <EvidenceFieldRow label="Flow Key" value={data.flow_key} mono />
        </div>
      </section>

      <section aria-label="Timestamp and sensor context">
        <h3 style={SECTION_HEADING_STYLE}>Time &amp; Sensor Context</h3>
        <div style={GRID_STYLE}>
          <EvidenceFieldRow label="Timestamp (Source)" value={data.timestamp_source} mono />
          <EvidenceFieldRow
            label="Exact Timestamp Epoch (Decimal s)"
            value={data.timestamp_epoch_decimal}
            mono
            helperText="Verbatim arbitrary-precision Decimal epoch string."
          />
          <EvidenceFieldRow label="Sensor" value={data.sensor_id} mono />
          <EvidenceFieldRow label="Source Type" value={data.source_type} mono />
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
            label="AlertEvent ID"
            value={data.event_id}
            mono
            copyAriaLabel="Copy Suricata AlertEvent ID"
            copied={isFieldCopied('detail_event_id')}
            onCopy={(val) => onCopyField('detail_event_id', val)}
          />
          <EvidenceFieldRow
            label="AlertDefinition ID"
            value={data.alert_definition_id}
            mono
            copyAriaLabel="Copy AlertDefinition ID"
            copied={isFieldCopied('detail_alert_definition_id')}
            onCopy={(val) => onCopyField('detail_alert_definition_id', val)}
          />
          <EvidenceFieldRow label="Source Record ID" value={data.source_record_id} mono />
          <EvidenceFieldRow label="Log Source ID" value={data.log_source_id} mono />
          <EvidenceFieldRow label="Source Scoped ID" value={data.src_scoped_id} mono />
          <EvidenceFieldRow label="Destination Scoped ID" value={data.dst_scoped_id} mono />
          <EvidenceFieldRow label="Source Provenance" value={data.source_provenance} mono />
        </div>
      </details>
    </div>
  );
};
