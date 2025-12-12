import { useState } from 'react';
import SensorList from '../components/sensors/SensorList';
import { useSensors, useDeleteSensor } from '../hooks/useSensors';
import type { Sensor } from '../types';
import './SensorsPage.css';

export default function SensorsPage() {
  const [page, setPage] = useState(1);
  const { data: sensorsData, isLoading } = useSensors(page, 50);
  const deleteSensor = useDeleteSensor();

  const handleDeleteSensor = async (sensorId: string) => {
    try {
      await deleteSensor.mutateAsync(sensorId);
    } catch (error) {
      console.error('Failed to delete sensor:', error);
      alert('Failed to delete sensor');
    }
  };

  const handleUpdateSensor = (sensor: Sensor) => {
    // TODO: Open edit modal
    console.log('Edit sensor:', sensor);
  };

  const handleSelectSensor = (sensor: Sensor) => {
    console.log('Selected sensor:', sensor);
  };

  if (isLoading) {
    return <div className="loading">Loading sensors...</div>;
  }

  return (
    <div className="sensors-page">
      <div className="page-header">
        <h1>Sensors</h1>
        <p className="page-description">
          Manage and monitor your deployed Honeyman sensors
        </p>
      </div>

      {sensorsData && (
        <>
          <SensorList
            sensors={sensorsData.items}
            onSelectSensor={handleSelectSensor}
            onDeleteSensor={handleDeleteSensor}
            onUpdateSensor={handleUpdateSensor}
          />

          {sensorsData.total_pages > 1 && (
            <div className="pagination">
              <button
                disabled={page === 1}
                onClick={() => setPage(p => p - 1)}
                className="pagination-btn"
              >
                Previous
              </button>
              <span className="pagination-info">
                Page {page} of {sensorsData.total_pages}
              </span>
              <button
                disabled={page === sensorsData.total_pages}
                onClick={() => setPage(p => p + 1)}
                className="pagination-btn"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
