import { DashboardOverview as DashboardOverviewType } from '../../types';
import './DashboardOverview.css';

interface DashboardOverviewProps {
  overview: DashboardOverviewType;
}

export default function DashboardOverview({ overview }: DashboardOverviewProps) {
  const stats = [
    {
      label: 'Total Threats (24h)',
      value: overview.total_threats_24h.toLocaleString(),
      icon: '🚨',
      color: 'red',
    },
    {
      label: 'Critical Threats',
      value: overview.critical_threats_24h.toLocaleString(),
      icon: '⚠️',
      color: 'orange',
    },
    {
      label: 'Active Sensors',
      value: `${overview.active_sensors} / ${overview.total_sensors}`,
      icon: '📡',
      color: 'blue',
    },
    {
      label: 'Threat Rate',
      value: `${overview.threat_rate_per_hour.toFixed(1)}/hr`,
      icon: '📊',
      color: 'purple',
    },
    {
      label: 'Top Threat Type',
      value: overview.top_threat_type || 'None',
      icon: '🎯',
      color: 'green',
    },
    {
      label: 'Top Detector',
      value: overview.top_detector || 'None',
      icon: '🔍',
      color: 'teal',
    },
    {
      label: 'Avg Confidence',
      value: `${(overview.avg_confidence_score * 100).toFixed(1)}%`,
      icon: '📈',
      color: 'indigo',
    },
  ];

  return (
    <div className="dashboard-overview">
      <h2>Dashboard Overview</h2>
      <div className="stats-grid">
        {stats.map((stat, index) => (
          <div key={index} className={`stat-card stat-${stat.color}`}>
            <div className="stat-icon">{stat.icon}</div>
            <div className="stat-content">
              <div className="stat-value">{stat.value}</div>
              <div className="stat-label">{stat.label}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
