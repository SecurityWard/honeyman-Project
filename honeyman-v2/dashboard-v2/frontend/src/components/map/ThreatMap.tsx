import { useState } from 'react';
import { MapContainer, TileLayer, Popup, CircleMarker } from 'react-leaflet';
import type { LatLngExpression } from 'leaflet';
import type { GeoThreat, Threat } from '../../types';
import 'leaflet/dist/leaflet.css';
import './ThreatMap.css';

interface ThreatMapProps {
  geoThreats: GeoThreat[];
  recentThreats?: Threat[];
  center?: LatLngExpression;
  zoom?: number;
}

const severityColors: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#f59e0b',
  low: '#3b82f6',
  info: '#6b7280',
};

export default function ThreatMap({
  geoThreats,
  recentThreats = [],
  center = [37.7749, -122.4194], // Default to San Francisco
  zoom = 10
}: ThreatMapProps) {
  const [selectedThreat, setSelectedThreat] = useState<GeoThreat | null>(null);

  // Calculate radius based on threat count (log scale for better visualization)
  const getRadius = (count: number) => {
    return Math.max(5, Math.min(50, Math.log10(count + 1) * 15));
  };

  return (
    <div className="threat-map-container">
      <MapContainer
        center={center}
        zoom={zoom}
        style={{ height: '100%', width: '100%' }}
        scrollWheelZoom={true}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />

        {/* Heat circles for aggregated threat data */}
        {geoThreats.map((threat, idx) => (
          <CircleMarker
            key={`geo-${idx}`}
            center={[threat.latitude, threat.longitude]}
            radius={getRadius(threat.threat_count)}
            pathOptions={{
              fillColor: '#ef4444',
              fillOpacity: 0.4,
              color: '#dc2626',
              weight: 2,
            }}
            eventHandlers={{
              click: () => setSelectedThreat(threat),
            }}
          >
            <Popup>
              <div className="threat-popup">
                <h3>{threat.sensor_name || threat.sensor_id}</h3>
                <p><strong>Threat Count:</strong> {threat.threat_count}</p>
                <p><strong>Location:</strong> {threat.latitude.toFixed(4)}, {threat.longitude.toFixed(4)}</p>
              </div>
            </Popup>
          </CircleMarker>
        ))}

        {/* Real-time threat markers */}
        {recentThreats
          .filter(threat => threat.latitude && threat.longitude)
          .map((threat, idx) => (
            <CircleMarker
              key={`threat-${threat.id}-${idx}`}
              center={[threat.latitude!, threat.longitude!]}
              radius={8}
              pathOptions={{
                fillColor: severityColors[threat.severity] || severityColors.info,
                fillOpacity: 0.7,
                color: '#ffffff',
                weight: 2,
              }}
            >
              <Popup>
                <div className="threat-popup">
                  <h3>{threat.threat_type}</h3>
                  <p><strong>Severity:</strong> <span className={`severity-${threat.severity}`}>{threat.severity}</span></p>
                  <p><strong>Detector:</strong> {threat.detector_type}</p>
                  <p><strong>Sensor:</strong> {threat.sensor_name || threat.sensor_id}</p>
                  {threat.device_name && <p><strong>Device:</strong> {threat.device_name}</p>}
                  {threat.mac_address && <p><strong>MAC:</strong> {threat.mac_address}</p>}
                  <p><strong>Time:</strong> {new Date(threat.timestamp).toLocaleString()}</p>
                  <p><strong>Confidence:</strong> {(threat.confidence_score * 100).toFixed(0)}%</p>
                </div>
              </Popup>
            </CircleMarker>
          ))}
      </MapContainer>

      {/* Map legend */}
      <div className="map-legend">
        <h4>Severity Levels</h4>
        {Object.entries(severityColors).map(([severity, color]) => (
          <div key={severity} className="legend-item">
            <span className="legend-color" style={{ backgroundColor: color }}></span>
            <span className="legend-label">{severity}</span>
          </div>
        ))}
      </div>

      {/* Threat stats overlay */}
      {selectedThreat && (
        <div className="threat-stats-overlay">
          <button className="close-btn" onClick={() => setSelectedThreat(null)}>×</button>
          <h3>Sensor: {selectedThreat.sensor_name || selectedThreat.sensor_id}</h3>
          <div className="stat">
            <span className="stat-value">{selectedThreat.threat_count}</span>
            <span className="stat-label">Total Threats</span>
          </div>
          <div className="stat">
            <span className="stat-value">{selectedThreat.latitude.toFixed(4)}, {selectedThreat.longitude.toFixed(4)}</span>
            <span className="stat-label">Coordinates</span>
          </div>
        </div>
      )}
    </div>
  );
}
