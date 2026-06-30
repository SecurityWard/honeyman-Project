import { useState } from 'react';
import { MapContainer, TileLayer, Popup, CircleMarker, Circle } from 'react-leaflet';
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

// Colour the accuracy circle by location method so operators can see
// at a glance whether a marker is GPS-precise or IP-coarse. The hex
// values intentionally pair with the severity palette.
const locationMethodColors: Record<string, string> = {
  gps:    '#16a34a',   // green   — most precise
  wifi:   '#0ea5e9',   // sky     — typically ~30–150m
  ip:     '#9ca3af',   // gray    — city-level, ~5km
  manual: '#7c3aed',   // violet  — operator-pinned
};

// Cap the radius we draw so a 5km IP-geolocation circle doesn't fill the
// whole viewport at country-level zoom. Real precision is in the popup.
const MAX_ACCURACY_DISPLAY_METERS = 2000;

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

        {/* Accuracy ring underneath each real-time threat marker.
            Drawn first so the marker dot sits on top. Only rendered when
            the agent reported a confidence radius. */}
        {recentThreats
          .filter(t => t.latitude && t.longitude && (t.accuracy_meters ?? 0) > 0)
          .map((t, idx) => {
            const method = (t.location_method ?? 'ip') as keyof typeof locationMethodColors;
            const ring = locationMethodColors[method] ?? locationMethodColors.ip;
            const radius = Math.min(
              t.accuracy_meters ?? 0,
              MAX_ACCURACY_DISPLAY_METERS,
            );
            return (
              <Circle
                key={`acc-${t.id}-${idx}`}
                center={[t.latitude!, t.longitude!]}
                radius={radius}
                pathOptions={{
                  fillColor: ring,
                  fillOpacity: 0.08,
                  color: ring,
                  weight: 1,
                  opacity: 0.5,
                  dashArray: method === 'ip' ? '4 4' : undefined,
                }}
                interactive={false}     // clicks go through to the marker
              />
            );
          })}

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
              <Popup maxWidth={360}>
                <div className="threat-popup">
                  <h3>{threat.threat_type}</h3>
                  <p>
                    <strong>Severity:</strong>{' '}
                    <span className={`severity-${threat.severity}`}>{threat.severity}</span>
                    {' · '}
                    {threat.detector_type}
                  </p>
                  {threat.matched_rules?.[0] && (
                    <p>
                      <strong>Rule:</strong> {threat.matched_rules[0].name}
                      <br />
                      <code className="rule-id">{threat.matched_rules[0].rule_id}</code>
                    </p>
                  )}
                  <p>
                    <strong>Sensor:</strong> {threat.sensor_name || threat.sensor_id}
                  </p>
                  {threat.device_name && (
                    <p><strong>Device:</strong> {threat.device_name}</p>
                  )}
                  {threat.device_mac && (
                    <p><strong>MAC:</strong> <code>{threat.device_mac}</code></p>
                  )}
                  {threat.device_ip && (
                    <p><strong>IP:</strong> <code>{threat.device_ip}</code></p>
                  )}
                  <p>
                    <strong>Time:</strong> {new Date(threat.timestamp).toLocaleString()}
                  </p>
                  {(threat.confidence != null || threat.threat_score != null) && (
                    <p>
                      <strong>Confidence / Score:</strong>{' '}
                      {threat.confidence != null
                        ? `${Math.round(threat.confidence * 100)}%`
                        : '—'}
                      {' / '}
                      {threat.threat_score != null
                        ? `${Math.round(threat.threat_score * 100)}%`
                        : '—'}
                    </p>
                  )}
                  {threat.location_method && (
                    <p>
                      <strong>Location:</strong>{' '}
                      <span className={`loc-${threat.location_method}`}>
                        {threat.location_method.toUpperCase()}
                      </span>
                      {threat.accuracy_meters != null && (
                        <> &middot; ±{Math.round(threat.accuracy_meters)} m</>
                      )}
                    </p>
                  )}
                  {threat.raw_event && Object.keys(threat.raw_event).length > 0 && (
                    <details className="raw-event-details">
                      <summary>Raw event</summary>
                      <pre>{JSON.stringify(threat.raw_event, null, 2)}</pre>
                    </details>
                  )}
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
        <h4 style={{ marginTop: '0.75rem' }}>Location accuracy</h4>
        {Object.entries(locationMethodColors).map(([method, color]) => (
          <div key={method} className="legend-item">
            <span
              className="legend-color"
              style={{
                backgroundColor: 'transparent',
                border: `2px solid ${color}`,
                borderStyle: method === 'ip' ? 'dashed' : 'solid',
              }}
            ></span>
            <span className="legend-label">{method}</span>
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
