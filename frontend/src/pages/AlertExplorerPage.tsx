import React, { useId, useRef, useState } from 'react';
import { LegacyAlertFactsView } from '../components/alerts/LegacyAlertFactsView';
import { SuricataEventsView } from '../components/alerts/SuricataEventsView';
import type { ActiveView } from '../components/layout/Header';

type AlertExplorerTab = 'legacy' | 'suricata';

interface AlertExplorerPageProps {
  onNavigate?: (
    view: ActiveView,
    context?: { centerIp?: string; sourceIp?: string; targetIp?: string }
  ) => void;
}

/**
 * Top-level Alert Explorer wrapper cleanly separating Legacy V1 AlertFacts (default)
 * from V2 discrete Suricata AlertEvent triage & forensic inspection.
 */
export const AlertExplorerPage: React.FC<AlertExplorerPageProps> = ({ onNavigate }) => {
  const [activeTab, setActiveTab] = useState<AlertExplorerTab>('legacy');
  const idPrefix = useId();
  const legacyTabRef = useRef<HTMLButtonElement>(null);
  const suricataTabRef = useRef<HTMLButtonElement>(null);

  const handleTabKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft' || e.key === 'Home' || e.key === 'End') {
      e.preventDefault();
      const targetTab: AlertExplorerTab =
        e.key === 'Home'
          ? 'legacy'
          : e.key === 'End'
            ? 'suricata'
            : activeTab === 'legacy'
              ? 'suricata'
              : 'legacy';
      setActiveTab(targetTab);
      if (targetTab === 'legacy') {
        legacyTabRef.current?.focus();
      } else {
        suricataTabRef.current?.focus();
      }
    }
  };

  return (
    <div
      style={{
        maxWidth: '1440px',
        width: '100%',
        margin: '0 auto',
        padding: 'clamp(1rem, 2.5vw, 2rem) clamp(0.85rem, 3vw, 2.5rem)',
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
              ? 'Security Alert Fact Explorer'
              : 'Suricata AlertEvent Triage Explorer'}
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginTop: '0.25rem' }}>
            {activeTab === 'legacy'
              ? 'Filter and inspect unique normalized security alert facts.'
              : 'Read-only V2 discrete Suricata AlertEvent occurrences and forensic details.'}
          </p>
        </div>

        {/* Accessible Sub-View Switcher (Legacy V1 Alert Facts vs V2 Suricata Events) */}
        <div
          role="tablist"
          aria-label="Alert explorer views"
          style={{
            display: 'inline-flex',
            flexWrap: 'wrap',
            maxWidth: '100%',
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
            id={`${idPrefix}-tab-legacy`}
            type="button"
            role="tab"
            aria-selected={activeTab === 'legacy'}
            aria-controls={`${idPrefix}-panel-legacy`}
            tabIndex={activeTab === 'legacy' ? 0 : -1}
            onClick={() => setActiveTab('legacy')}
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
            Legacy Alert Facts
          </button>
          <button
            ref={suricataTabRef}
            id={`${idPrefix}-tab-suricata`}
            type="button"
            role="tab"
            aria-selected={activeTab === 'suricata'}
            aria-controls={`${idPrefix}-panel-suricata`}
            tabIndex={activeTab === 'suricata' ? 0 : -1}
            onClick={() => setActiveTab('suricata')}
            onKeyDown={handleTabKeyDown}
            style={{
              padding: '0.42rem 0.85rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.84rem',
              fontWeight: 600,
              backgroundColor: activeTab === 'suricata' ? 'var(--accent-primary)' : 'transparent',
              color: activeTab === 'suricata' ? '#ffffff' : 'var(--text-secondary)',
            }}
          >
            Suricata Events
          </button>
        </div>
      </div>

      {/* Persistent Tabpanel Containers (valid aria-controls targets; unmounts inactive inner view) */}
      <div
        id={`${idPrefix}-panel-legacy`}
        role="tabpanel"
        aria-labelledby={`${idPrefix}-tab-legacy`}
        hidden={activeTab !== 'legacy'}
        tabIndex={activeTab === 'legacy' ? 0 : undefined}
      >
        {activeTab === 'legacy' && <LegacyAlertFactsView onNavigate={onNavigate} />}
      </div>

      <div
        id={`${idPrefix}-panel-suricata`}
        role="tabpanel"
        aria-labelledby={`${idPrefix}-tab-suricata`}
        hidden={activeTab !== 'suricata'}
        tabIndex={activeTab === 'suricata' ? 0 : undefined}
      >
        {activeTab === 'suricata' && <SuricataEventsView />}
      </div>
    </div>
  );
};
