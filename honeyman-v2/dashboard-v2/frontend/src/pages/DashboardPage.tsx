import { useState, useEffect } from 'react';
import DashboardOverview from '../components/dashboard/DashboardOverview';
import ThreatMap from '../components/map/ThreatMap';
import ThreatTrendsChart from '../components/analytics/ThreatTrendsChart';
import TopThreatsChart from '../components/analytics/TopThreatsChart';
import TopSensorsChart from '../components/analytics/TopSensorsChart';
import { useDashboardOverview, useThreatTrends, useTopThreats, useTopSensors, useGeoMap } from '../hooks/useAnalytics';
import { useThreats } from '../hooks/useThreats';
import type { Threat } from '../types';
import websocketService from '../services/websocket';
import './DashboardPage.css';

export default function DashboardPage() {
  const [recentThreats, setRecentThreats] = useState<Threat[]>([]);

  const { data: overview, isLoading: overviewLoading } = useDashboardOverview();
  const { data: trends, isLoading: trendsLoading } = useThreatTrends('hourly', 24);
  const { data: topThreats, isLoading: topThreatsLoading } = useTopThreats(7);
  const { data: topSensors, isLoading: topSensorsLoading } = useTopSensors(5);
  const { data: geoData, isLoading: geoLoading } = useGeoMap(24);
  const { data: threatsData } = useThreats({ page: 1, page_size: 20 });

  // WebSocket real-time updates
  useEffect(() => {
    const unsubscribe = websocketService.onThreat((threat: Threat) => {
      setRecentThreats(prev => [threat, ...prev.slice(0, 19)]); // Keep last 20
    });

    return () => unsubscribe();
  }, []);

  if (overviewLoading) {
    return <div className="loading">Loading dashboard...</div>;
  }

  return (
    <div className="dashboard-page">
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
            <p className="no-threats">No recent threats. Monitoring...</p>
          ) : (
            recentThreats.map((threat, idx) => (
              <div key={`${threat.id}-${idx}`} className={`threat-item severity-${threat.severity}`}>
                <div className="threat-time">{new Date(threat.timestamp).toLocaleTimeString()}</div>
                <div className="threat-details">
                  <strong>{threat.threat_type}</strong> - {threat.detector_type}
                  {threat.device_name && <span> ({threat.device_name})</span>}
                </div>
                <div className="threat-sensor">{threat.sensor_name || threat.sensor_id}</div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
