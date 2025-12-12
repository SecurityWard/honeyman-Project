import { useState } from 'react';
import type { Sensor } from '../../types';
import { format } from 'date-fns';
import './SensorList.css';

interface SensorListProps {
  sensors: Sensor[];
  onSelectSensor?: (sensor: Sensor) => void;
  onDeleteSensor?: (sensorId: string) => void;
  onUpdateSensor?: (sensor: Sensor) => void;
}

export default function SensorList({
  sensors,
  onSelectSensor,
  onDeleteSensor,
  onUpdateSensor,
}: SensorListProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  const filteredSensors = sensors.filter(sensor => {
    const matchesSearch = sensor.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         sensor.sensor_id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || sensor.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const handleSelect = (sensor: Sensor) => {
    setSelectedId(sensor.id);
    onSelectSensor?.(sensor);
  };

  const getStatusBadge = (status: string) => {
    const statusClasses: Record<string, string> = {
      active: 'status-active',
      inactive: 'status-inactive',
      error: 'status-error',
    };
    return <span className={`status-badge ${statusClasses[status]}`}>{status}</span>;
  };

  return (
    <div className="sensor-list-container">
      <div className="sensor-list-header">
        <h2>Sensors ({filteredSensors.length})</h2>

        <div className="sensor-controls">
          <input
            type="text"
            placeholder="Search sensors..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="status-filter"
          >
            <option value="all">All Status</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
            <option value="error">Error</option>
          </select>
        </div>
      </div>

      <div className="sensor-list">
        {filteredSensors.length === 0 ? (
          <div className="empty-state">
            <p>No sensors found</p>
          </div>
        ) : (
          filteredSensors.map(sensor => (
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
                {getStatusBadge(sensor.status)}
              </div>

              <div className="sensor-card-body">
                {sensor.location && (
                  <div className="sensor-info">
                    <span className="info-label">Location:</span>
                    <span className="info-value">{sensor.location}</span>
                  </div>
                )}

                {sensor.latitude && sensor.longitude && (
                  <div className="sensor-info">
                    <span className="info-label">Coordinates:</span>
                    <span className="info-value">
                      {sensor.latitude.toFixed(4)}, {sensor.longitude.toFixed(4)}
                    </span>
                  </div>
                )}

                <div className="sensor-info">
                  <span className="info-label">Total Threats:</span>
                  <span className="info-value threat-count">{sensor.total_threats}</span>
                </div>

                <div className="sensor-info">
                  <span className="info-label">Detectors:</span>
                  <span className="info-value">
                    {sensor.enabled_detectors.join(', ') || 'None'}
                  </span>
                </div>

                {sensor.last_seen && (
                  <div className="sensor-info">
                    <span className="info-label">Last Seen:</span>
                    <span className="info-value">
                      {format(new Date(sensor.last_seen), 'MMM dd, yyyy HH:mm:ss')}
                    </span>
                  </div>
                )}
              </div>

              <div className="sensor-card-footer">
                <button
                  className="btn-secondary"
                  onClick={(e) => {
                    e.stopPropagation();
                    onUpdateSensor?.(sensor);
                  }}
                >
                  Edit
                </button>
                <button
                  className="btn-danger"
                  onClick={(e) => {
                    e.stopPropagation();
                    if (confirm(`Delete sensor ${sensor.name}?`)) {
                      onDeleteSensor?.(sensor.id);
                    }
                  }}
                >
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
