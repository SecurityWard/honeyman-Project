import { useState, useEffect } from 'react';
import DashboardOverview from '../components/dashboard/DashboardOverview';
import DateRangeSelector, { type DateRange } from '../components/dashboard/DateRangeSelector';
import ThreatMap from '../components/map/ThreatMap';
import ThreatTrendsChart from '../components/analytics/ThreatTrendsChart';
import TopThreatsChart from '../components/analytics/TopThreatsChart';
import TopSensorsChart from '../components/analytics/TopSensorsChart';
import { useDashboardOverview, useThreatTrends, useTopThreats, useTopSensors, useGeoMap } from '../hooks/useAnalytics';
import { useThreats } from '../hooks/useThreats';
import type { Threat } from '../types';
import websocketService from '../services/websocket';
import './DashboardPage.css';

// Helper function to convert date range to hours
function getHoursFromRange(range: DateRange): number | undefined {
  if (range.preset === 'all') return undefined;
  if (range.preset === '24h') return 24;
  if (range.preset === '7d') return 24 * 7;
  if (range.preset === '30d') return 24 * 30;
  if (range.preset === '90d') return 24 * 90;

  if (range.preset === 'custom' && range.startDate && range.endDate) {
    const diff = range.endDate.getTime() - range.startDate.getTime();
    return Math.ceil(diff / (1000 * 60 * 60)); // Convert ms to hours
  }

  return 24; // Default to 24 hours
}

const FEED_MAX = 20;

export default function DashboardPage() {
  const [recentThreats, setRecentThreats] = useState<Threat[]>([]);
  const [dateRange, setDateRange] = useState<DateRange>({ preset: '7d' });

  const hours = getHoursFromRange(dateRange);

  const { data: overview, isLoading: overviewLoading } = useDashboardOverview();
  const { data: trends, isLoading: trendsLoading } = useThreatTrends('hourly', hours || 8760); // 8760 = 1 year
  const { data: topThreats, isLoading: topThreatsLoading } = useTopThreats(7, hours || undefined);
  const { data: topSensors, isLoading: topSensorsLoading } = useTopSensors(5, hours || undefined);
  const { data: geoData, isLoading: geoLoading } = useGeoMap(hours || undefined);
  const { data: threatsData } = useThreats({ page: 1, page_size: FEED_MAX });

  // Seed the feed from REST so it isn't empty until the next WebSocket frame.
  // Once a WS-delivered threat arrives the feed switches to "live" mode and
  // new threats prepend; we keep the most recent FEED_MAX overall.
  useEffect(() => {
    if (recentThreats.length === 0 && threatsData?.items?.length) {
      setRecentThreats(threatsData.items.slice(0, FEED_MAX));
    }
  }, [threatsData, recentThreats.length]);

  // WebSocket real-time updates — dedupe by id in case a REST seed and the
  // WS broadcast race each other for the same threat.
  useEffect(() => {
    const unsubscribe = websocketService.onThreat((threat: Threat) => {
      setRecentThreats(prev => {
        if (prev.some(t => t.id === threat.id)) return prev;
        return [threat, ...prev].slice(0, FEED_MAX);
      });
    });
    return () => unsubscribe();
  }, []);

  if (overviewLoading) {
    return <div className="loading">Loading dashboard...</div>;
  }

  return (
    <div className="dashboard-page">
      <DateRangeSelector value={dateRange} onChange={setDateRange} />

      {overview && <DashboardOverview overview={overview} />}

      <div className="dashboard-grid">
        <div className="dashboard-section full-width">
          {!geoLoading && geoData && (
            <ThreatMap
              geoThreats={geoData}
              recentThreats={recentThreats.length > 0 ? recentThreats : threatsData?.items || []}
            />
          )}
        </div>

        <div className="dashboard-section">
          {!trendsLoading && trends && <ThreatTrendsChart data={trends} height={350} />}
        </div>

        <div className="dashboard-section">
          {!topThreatsLoading && topThreats && <TopThreatsChart data={topThreats} height={350} />}
        </div>

        <div className="dashboard-section">
          {!topSensorsLoading && topSensors && <TopSensorsChart data={topSensors} height={350} />}
        </div>
      </div>

      <div className="real-time-feed">
        <h3>Real-Time Threat Feed</h3>
        <div className="threat-feed">
          {recentThreats.length === 0 ? (
            <p className="no-threats">No recent threats. Monitoring&hellip;</p>
          ) : (
            recentThreats.map(threat => {
              const rule = threat.matched_rules?.[0];
              const mitre = [
                ...(threat.mitre_tactics ?? []),
                ...(threat.mitre_techniques ?? []),
              ];
              const confidencePct =
                threat.confidence != null ? Math.round(threat.confidence * 100) : null;
              const scorePct =
                threat.threat_score != null ? Math.round(threat.threat_score * 100) : null;
              const rawEntries = threat.raw_event
                ? Object.entries(threat.raw_event)
                : [];
              const hasDetail =
                rule || mitre.length || rawEntries.length || threat.device_mac || threat.device_ip;

              return (
                <details
                  key={threat.id}
                  className={`threat-item severity-${threat.severity}`}
                >
                  <summary>
                    <span className="threat-time">
                      {new Date(threat.timestamp).toLocaleTimeString()}
                    </span>
                    <span className={`severity-badge severity-${threat.severity}`}>
                      {threat.severity}
                    </span>
                    <span className="threat-type">{threat.threat_type}</span>
                    <span className="threat-detector">{threat.detector_type}</span>
                    {threat.device_name && (
                      <span className="threat-device">{threat.device_name}</span>
                    )}
                    <span className="threat-sensor">
                      {threat.sensor_name || threat.sensor_id}
                    </span>
                  </summary>

                  {hasDetail && (
                    <div className="threat-detail-body">
                      {rule && (
                        <div className="detail-row">
                          <span className="detail-label">Rule</span>
                          <span className="detail-value">
                            {rule.name}
                            <code className="rule-id"> ({rule.rule_id})</code>
                          </span>
                        </div>
                      )}
                      {(confidencePct != null || scorePct != null) && (
                        <div className="detail-row">
                          <span className="detail-label">Confidence / Score</span>
                          <span className="detail-value">
                            {confidencePct != null ? `${confidencePct}%` : '—'}
                            {' / '}
                            {scorePct != null ? `${scorePct}%` : '—'}
                          </span>
                        </div>
                      )}
                      {threat.device_mac && (
                        <div className="detail-row">
                          <span className="detail-label">MAC</span>
                          <code className="detail-value">{threat.device_mac}</code>
                        </div>
                      )}
                      {threat.device_ip && (
                        <div className="detail-row">
                          <span className="detail-label">IP</span>
                          <code className="detail-value">{threat.device_ip}</code>
                        </div>
                      )}
                      {mitre.length > 0 && (
                        <div className="detail-row">
                          <span className="detail-label">MITRE ATT&amp;CK</span>
                          <span className="detail-value">
                            {mitre.map(m => (
                              <a
                                key={m}
                                className="mitre-tag"
                                href={
                                  m.startsWith('TA')
                                    ? `https://attack.mitre.org/tactics/${m}/`
                                    : `https://attack.mitre.org/techniques/${m.replace('.', '/')}/`
                                }
                                target="_blank"
                                rel="noreferrer noopener"
                              >
                                {m}
                              </a>
                            ))}
                          </span>
                        </div>
                      )}
                      {rawEntries.length > 0 && (
                        <div className="detail-row">
                          <span className="detail-label">Raw event</span>
                          <pre className="raw-event">
                            {JSON.stringify(threat.raw_event, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </details>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
