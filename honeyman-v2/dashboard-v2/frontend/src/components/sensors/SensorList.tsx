import { useState } from 'react';
import type { Sensor } from '../../types';
import { format, formatDistanceToNow } from 'date-fns';
import './SensorList.css';

interface SensorListProps {
  sensors: Sensor[];
  onSelectSensor?: (sensor: Sensor) => void;
}

type StatusFilter = 'all' | 'online' | 'offline' | 'pending';

function statusOf(sensor: Sensor): StatusFilter {
  if (sensor.is_online) return 'online';
  if (!sensor.last_heartbeat) return 'pending';
  return 'offline';
}

function StatusBadge({ status }: { status: StatusFilter }) {
  const label = status === 'pending' ? 'pending' : status;
  return <span className={`status-badge status-${status}`}>{label}</span>;
}

function locationOf(sensor: Sensor): string | null {
  if (sensor.description) return sensor.description;
  const parts = [sensor.city, sensor.country].filter(Boolean);
  return parts.length ? parts.join(', ') : null;
}

export default function SensorList({ sensors, onSelectSensor }: SensorListProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');

  const filteredSensors = sensors.filter(sensor => {
    const term = searchTerm.toLowerCase();
    const matchesSearch =
      sensor.name.toLowerCase().includes(term) ||
      sensor.sensor_id.toLowerCase().includes(term);
    const matchesStatus = statusFilter === 'all' || statusOf(sensor) === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const handleSelect = (sensor: Sensor) => {
    setSelectedId(sensor.id);
    onSelectSensor?.(sensor);
  };

  return (
    <div className="sensor-list-container">
      <div className="sensor-list-header">
        <h2>Sensors ({filteredSensors.length})</h2>

        <div className="sensor-controls">
          <input
            type="text"
            placeholder="Search by name or sensor ID&hellip;"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
            className="status-filter"
          >
            <option value="all">All</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="pending">Pending (no heartbeat)</option>
          </select>
        </div>
      </div>

      <div className="sensor-list">
        {filteredSensors.length === 0 ? (
          <div className="empty-state">
            <p>{sensors.length === 0 ? 'No sensors registered yet.' : 'No sensors match the filter.'}</p>
          </div>
        ) : (
          filteredSensors.map(sensor => {
            const status = statusOf(sensor);
            const location = locationOf(sensor);
            return (
              <div
                key={sensor.id}
                className={`sensor-card ${selectedId === sensor.id ? 'selected' : ''}`}
                onClick={() => handleSelect(sensor)}
              >
                <div className="sensor-card-header">
                  <div>
                    <h3>{sensor.name}</h3>
                    <p className="sensor-id">{sensor.sensor_id}</p>
                  </div>
                  <StatusBadge status={status} />
                </div>

                <div className="sensor-card-body">
                  {location && (
                    <div className="sensor-info">
                      <span className="info-label">Location:</span>
                      <span className="info-value">{location}</span>
                    </div>
                  )}

                  {sensor.latitude != null && sensor.longitude != null && (
                    <div className="sensor-info">
                      <span className="info-label">Coordinates:</span>
                      <span className="info-value">
                        {sensor.latitude.toFixed(4)}, {sensor.longitude.toFixed(4)}
                        {sensor.location_method ? ` (${sensor.location_method})` : ''}
                      </span>
                    </div>
                  )}

                  {sensor.platform && (
                    <div className="sensor-info">
                      <span className="info-label">Platform:</span>
                      <span className="info-value">
                        {sensor.platform}
                        {sensor.agent_version ? ` · agent ${sensor.agent_version}` : ''}
                      </span>
                    </div>
                  )}

                  <div className="sensor-info">
                    <span className="info-label">Detectors:</span>
                    <span className="info-value">
                      {sensor.enabled_detectors.length
                        ? sensor.enabled_detectors.join(', ')
                        : 'None'}
                    </span>
                  </div>

                  <div className="sensor-info">
                    <span className="info-label">Threats (24h / total):</span>
                    <span className="info-value threat-count">
                      {sensor.threats_last_24h ?? 0} / {sensor.total_threats_detected ?? 0}
                    </span>
                  </div>

                  <div className="sensor-info">
                    <span className="info-label">Last heartbeat:</span>
                    <span className="info-value">
                      {sensor.last_heartbeat
                        ? `${formatDistanceToNow(new Date(sensor.last_heartbeat))} ago` +
                          ` (${format(new Date(sensor.last_heartbeat), 'MMM dd HH:mm:ss')})`
                        : sensor.registered_at
                          ? `never — registered ${formatDistanceToNow(new Date(sensor.registered_at))} ago`
                          : 'never'}
                    </span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
