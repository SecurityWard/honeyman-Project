import type { DashboardOverview as DashboardOverviewType } from '../../types';
import TooltipIcon from '../common/TooltipIcon';
import './DashboardOverview.css';

interface DashboardOverviewProps {
  overview: DashboardOverviewType;
}

export default function DashboardOverview({ overview }: DashboardOverviewProps) {
  const stats = [
    {
      label: 'Total Threats',
      value: overview.total_threats.toLocaleString(),
      color: 'red',
      tooltip: 'Total number of security threats detected across all sensors',
    },
    {
      label: 'Threats (24h)',
      value: overview.threats_last_24h.toLocaleString(),
      color: 'orange',
      tooltip: 'Number of threats detected in the last 24 hours',
    },
    {
      label: 'Critical Threats',
      value: overview.critical_threats.toLocaleString(),
      color: 'purple',
      tooltip: 'Threats with critical severity requiring immediate attention',
    },
    {
      label: 'High Threats',
      value: overview.high_threats.toLocaleString(),
      color: 'pink',
      tooltip: 'Threats with high severity that should be investigated',
    },
    {
      label: 'Active Sensors',
      value: `${overview.active_sensors} / ${overview.total_sensors}`,
      color: 'blue',
      tooltip: 'Number of sensors currently enabled and configured',
    },
    {
      label: 'Online Sensors',
      value: overview.online_sensors.toLocaleString(),
      color: 'green',
      tooltip: 'Number of sensors currently connected and reporting data',
    },
    {
      label: 'Threat Velocity',
      value: `${overview.threat_velocity.toFixed(1)}/hr`,
      color: 'teal',
      tooltip: 'Average rate of threat detection (threats per hour)',
    },
    {
      label: 'Avg Threat Score',
      value: overview.avg_threat_score ? `${(overview.avg_threat_score * 100).toFixed(1)}%` : 'N/A',
      color: 'indigo',
      tooltip: 'Average confidence score of detected threats (0-100%)',
    },
  ];

  return (
    <div className="dashboard-overview">
      <h2>Dashboard Overview</h2>
      <div className="stats-grid">
        {stats.map((stat, index) => (
          <div key={index} className={`stat-card stat-${stat.color}`}>
            <div className="stat-content">
              <div className="stat-value">{stat.value}</div>
              <div className="stat-label">
                {stat.label}
                <TooltipIcon text={stat.tooltip} />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
