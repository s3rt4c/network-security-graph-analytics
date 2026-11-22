import React, { useEffect, useRef, useState } from 'react';
import { Network, Route } from 'lucide-react';
import { listTrafficAlertCorrelations } from '../api/correlations';
import type { TrafficAlertCorrelationResponse } from '../api/types';
import { PriorityBadge, Tag } from '../components/common/Badge';
import { Pagination } from '../components/common/Pagination';
import { Skeleton } from '../components/common/Skeleton';
import { AlertFlowCorrelationsView } from '../components/correlations/AlertFlowCorrelationsView';
import type { ActiveView } from '../components/layout/Header';

type CorrelationTab = 'legacy' | 'v2';

interface CorrelationsPageProps {
  onNavigate?: (
    view: ActiveView,
    context?: { centerIp?: string; sourceIp?: string; targetIp?: string }
  ) => void;
}

export const CorrelationsPage: React.FC<CorrelationsPageProps> = ({ onNavigate }) => {
  const [activeTab, setActiveTab] = useState<CorrelationTab>('legacy');

  // Legacy V1 traffic–alert correlation state (isolated from V2 view)
  const [correlations, setCorrelations] = useState<TrafficAlertCorrelationResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [offset, setOffset] = useState<number>(0);
  const [limit] = useState<number>(50);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const legacyTabRef = useRef<HTMLButtonElement>(null);
  const v2TabRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (activeTab !== 'legacy') {
      return;
    }

    const controller = new AbortController();

    listTrafficAlertCorrelations(limit, offset, controller.signal)
      .then((res) => {
        if (!controller.signal.aborted) {
          setCorrelations(res.items);
          setTotal(res.total);
          setError(null);
          setLoading(false);
        }
      })
      .catch((err: Error) => {
        if (!controller.signal.aborted) {
          setError(err.message);
          setCorrelations([]);
          setTotal(0);
          setLoading(false);
        }
      });

    return () => {
      controller.abort();
    };
  }, [activeTab, limit, offset]);

  const handleSelectTab = (nextTab: CorrelationTab) => {
    if (nextTab === activeTab) {
      return;
    }
    if (nextTab === 'legacy') {
      setError(null);
      setLoading(true);
    }
    setActiveTab(nextTab);
  };

  const handleTabKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft' || e.key === 'Home' || e.key === 'End') {
      e.preventDefault();
      const targetTab: CorrelationTab =
        e.key === 'Home'
          ? 'legacy'
          : e.key === 'End'
            ? 'v2'
            : activeTab === 'legacy'
              ? 'v2'
              : 'legacy';
      handleSelectTab(targetTab);
      if (targetTab === 'legacy') {
        legacyTabRef.current?.focus();
      } else {
        v2TabRef.current?.focus();
      }
    }
  };

  const handleLegacyPageChange = (newOffset: number) => {
    setError(null);
    setLoading(true);
    setOffset(newOffset);
  };

  return (
    <div
      style={{
        maxWidth: '1440px',
        width: '100%',
        margin: '0 auto',
        padding: '2rem 2.5rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.75rem',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-end',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div>
          <h2
            style={{
              fontSize: '1.45rem',
              fontWeight: 600,
              letterSpacing: '-0.02em',
              color: 'var(--text-primary)',
            }}
          >
            {activeTab === 'legacy'
              ? 'Traffic & Security Alert Correlations'
              : 'Persisted Zeek–Suricata Alert–Flow Correlations'}
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginTop: '0.25rem' }}>
            {activeTab === 'legacy'
              ? 'Observed Layer 3 communications whose source-target endpoints match generated security alert facts.'
              : 'Read-only persisted V2 observation-level correlations between Suricata AlertEvents and Zeek FlowObservations.'}
          </p>
        </div>

        {/* Accessible Sub-View Switcher (Legacy V1 vs V2 Alert–Flow Correlations) */}
        <div
          role="tablist"
          aria-label="Correlation views"
          style={{
            display: 'inline-flex',
            gap: '0.25rem',
            padding: '0.25rem',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-card)',
            borderRadius: 'var(--radius-md)',
            boxShadow: 'var(--shadow-sm)',
          }}
        >
          <button
            ref={legacyTabRef}
            id="correlations-tab-legacy"
            type="button"
            role="tab"
            aria-selected={activeTab === 'legacy'}
            aria-controls="correlations-panel-legacy"
            tabIndex={activeTab === 'legacy' ? 0 : -1}
            onClick={() => handleSelectTab('legacy')}
            onKeyDown={handleTabKeyDown}
            style={{
              padding: '0.42rem 0.85rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.84rem',
              fontWeight: 600,
              backgroundColor: activeTab === 'legacy' ? 'var(--accent-primary)' : 'transparent',
              color: activeTab === 'legacy' ? '#ffffff' : 'var(--text-secondary)',
            }}
          >
            Legacy Correlations
          </button>
          <button
            ref={v2TabRef}
            id="correlations-tab-v2"
            type="button"
            role="tab"
            aria-selected={activeTab === 'v2'}
            aria-controls="correlations-panel-v2"
            tabIndex={activeTab === 'v2' ? 0 : -1}
            onClick={() => handleSelectTab('v2')}
            onKeyDown={handleTabKeyDown}
            style={{
              padding: '0.42rem 0.85rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.84rem',
              fontWeight: 600,
              backgroundColor: activeTab === 'v2' ? 'var(--accent-primary)' : 'transparent',
              color: activeTab === 'v2' ? '#ffffff' : 'var(--text-secondary)',
            }}
          >
            Alert–Flow Correlations
          </button>
        </div>
      </div>

      {activeTab === 'legacy' ? (
        <div
          id="correlations-panel-legacy"
          role="tabpanel"
          aria-labelledby="correlations-tab-legacy"
          style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}
        >
          <div className="info-banner">
            <span>ℹ</span>
            <div>
              <strong>Legacy V1 Correlation Notice:</strong> Rows represent co-occurring Layer 3
              traffic aggregates and normalized alert facts sharing identical source-target
              endpoint evidence (legacy V1 heuristic, distinct from V2 observation-level
              correlations). Co-occurrence indicates relationship overlap in the graph, not proven
              causality.
            </div>
          </div>

          {error && <div className="warning-banner">{error}</div>}

          {/* Legacy V1 Correlation Records Table */}
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Priority</th>
                  <th>Source IP</th>
                  <th>Target IP</th>
                  <th>Traffic Protocol</th>
                  <th>Traffic Ports</th>
                  <th>Alert Protocol</th>
                  <th>SID</th>
                  <th>Alert Message</th>
                  <th>Flow Key</th>
                  <th style={{ width: '150px' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  Array.from({ length: 5 }).map((_, i) => (
                    <tr key={i}>
                      <td><Skeleton height="20px" width="70px" /></td>
                      <td><Skeleton height="20px" width="90px" /></td>
                      <td><Skeleton height="20px" width="90px" /></td>
                      <td><Skeleton height="20px" width="50px" /></td>
                      <td><Skeleton height="20px" width="70px" /></td>
                      <td><Skeleton height="20px" width="50px" /></td>
                      <td><Skeleton height="20px" width="60px" /></td>
                      <td><Skeleton height="20px" width="80%" /></td>
                      <td><Skeleton height="20px" width="60px" /></td>
                      <td><Skeleton height="20px" width="110px" /></td>
                    </tr>
                  ))
                ) : correlations.length === 0 ? (
                  <tr>
                    <td
                      colSpan={10}
                      style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}
                    >
                      No correlated traffic-alert records found in the graph.
                    </td>
                  </tr>
                ) : (
                  correlations.map((corr, idx) => (
                    <tr
                      key={
                        corr.traffic_flow_key
                          ? `${corr.fact_key}-${corr.traffic_flow_key}`
                          : `${corr.fact_key}-${corr.traffic_protocol}-${idx}`
                      }
                    >
                      <td>
                        <PriorityBadge priority={corr.priority} />
                      </td>
                      <td>
                        <span
                          className="font-mono"
                          style={{ color: 'var(--text-primary)', fontWeight: 500 }}
                        >
                          {corr.source_ip}
                        </span>
                      </td>
                      <td>
                        <span
                          className="font-mono"
                          style={{ color: 'var(--text-primary)', fontWeight: 500 }}
                        >
                          {corr.target_ip}
                        </span>
                      </td>
                      <td>
                        <Tag label={corr.traffic_protocol} variant="slate" />
                      </td>
                      <td className="font-mono" style={{ fontSize: '0.8rem' }}>
                        {corr.traffic_src_port != null || corr.traffic_dst_port != null
                          ? `${corr.traffic_src_port ?? '—'} → ${corr.traffic_dst_port ?? '—'}`
                          : '—'}
                      </td>
                      <td>
                        {corr.alert_protocol ? (
                          <Tag label={corr.alert_protocol} variant="slate" />
                        ) : (
                          '—'
                        )}
                      </td>
                      <td className="font-mono" style={{ fontSize: '0.8rem' }}>
                        {corr.sid !== null ? corr.sid : '—'}
                      </td>
                      <td style={{ fontWeight: 500 }}>{corr.message || '—'}</td>
                      <td
                        className="font-mono"
                        style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}
                        title={corr.traffic_flow_key || undefined}
                      >
                        {corr.traffic_flow_key ? `${corr.traffic_flow_key.slice(0, 8)}…` : '—'}
                      </td>
                      <td>
                        {onNavigate && (
                          <div style={{ display: 'flex', gap: '0.35rem' }}>
                            <button
                              type="button"
                              className="btn-secondary"
                              onClick={() => onNavigate('network', { centerIp: corr.source_ip })}
                              style={{
                                fontSize: '0.75rem',
                                padding: '0.2rem 0.45rem',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.2rem',
                              }}
                              title="Explore Source IP in Graph"
                            >
                              <Network size={12} aria-hidden="true" />
                              <span>Graph</span>
                            </button>
                            <button
                              type="button"
                              className="btn-secondary"
                              onClick={() =>
                                onNavigate('path', {
                                  sourceIp: corr.source_ip,
                                  targetIp: corr.target_ip,
                                })
                              }
                              style={{
                                fontSize: '0.75rem',
                                padding: '0.2rem 0.45rem',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.2rem',
                              }}
                              title="Find Path"
                            >
                              <Route size={12} aria-hidden="true" />
                              <span>Path</span>
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          {!loading && total > 0 && (
            <Pagination
              offset={offset}
              limit={limit}
              total={total}
              onPageChange={handleLegacyPageChange}
              itemLabel="correlation records"
            />
          )}
        </div>
      ) : (
        <div
          id="correlations-panel-v2"
          role="tabpanel"
          aria-labelledby="correlations-tab-v2"
        >
          <AlertFlowCorrelationsView />
        </div>
      )}
    </div>
  );
};
