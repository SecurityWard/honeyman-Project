import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import SensorList from '../components/sensors/SensorList';
import { useSensors } from '../hooks/useSensors';
import type { Sensor } from '../types';
import './SensorsPage.css';

const PAGE_SIZE = 50;

export default function SensorsPage() {
  const [page, setPage] = useState(1);
  const navigate = useNavigate();
  const { data, isLoading, error } = useSensors(page, PAGE_SIZE);

  const handleSelectSensor = (sensor: Sensor) => {
    // Drop into the dashboard filtered to just this sensor's events. The
    // dashboard reads sensor_id from the query string and scopes the threat
    // feed + map view to it.
    navigate(`/dashboard?sensor_id=${encodeURIComponent(sensor.sensor_id)}`);
  };

  if (isLoading) {
    return <div className="loading">Loading sensors&hellip;</div>;
  }

  if (error) {
    return <div className="loading">Failed to load sensors: {String(error)}</div>;
  }

  const sensors = data?.sensors ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="sensors-page">
      <div className="page-header">
        <h1>Sensors</h1>
        <p className="page-description">
          {total === 0
            ? 'No sensors have registered yet. Deploy one from the Add Sensor page.'
            : `${total} sensor${total === 1 ? '' : 's'} registered with the dashboard.`}
        </p>
      </div>

      <SensorList sensors={sensors} onSelectSensor={handleSelectSensor} />

      {totalPages > 1 && (
        <div className="pagination">
          <button
            disabled={page === 1}
            onClick={() => setPage(p => p - 1)}
            className="pagination-btn"
          >
            Previous
          </button>
          <span className="pagination-info">
            Page {page} of {totalPages}
          </span>
          <button
            disabled={page === totalPages}
            onClick={() => setPage(p => p + 1)}
            className="pagination-btn"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
