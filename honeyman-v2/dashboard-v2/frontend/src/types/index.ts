// V2 type definitions
//
// No User / Login types — V2 has no accounts.
// No acknowledged fields on Threat — V2 dashboard is read-only.

// Sensor types
export interface Sensor {
  id: string;
  sensor_id: string;
  name: string;
  location?: string;
  latitude?: number;
  longitude?: number;
  status: 'active' | 'inactive' | 'error';
  last_seen?: string;
  total_threats: number;
  enabled_detectors: string[];
  created_at: string;
  updated_at: string;
}

// Threat types
export interface Threat {
  id: string;
  timestamp: string;
  sensor_id: string;
  sensor_name?: string;
  detector_type: string;
  threat_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence_score: number;
  device_identifier?: string;
  device_name?: string;
  manufacturer?: string;
  ssid?: string;
  mac_address?: string;
  ip_address?: string;
  latitude?: number;
  longitude?: number;
  metadata?: Record<string, any>;
}

// Analytics types
export interface DashboardOverview {
  total_sensors: number;
  active_sensors: number;
  online_sensors: number;
  total_threats: number;
  threats_last_24h: number;
  threats_last_7d: number;
  critical_threats: number;
  high_threats: number;
  threat_velocity: number;
  avg_threat_score: number | null;
}

export interface ThreatTrend {
  timestamp: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface TopThreat {
  threat_type: string;
  count: number;
  percentage: number;
}

export interface TopSensor {
  sensor_id: string;
  sensor_name: string;
  threat_count: number;
  percentage: number;
}

export interface GeoThreat {
  latitude: number;
  longitude: number;
  threat_count: number;
  sensor_id: string;
  sensor_name?: string;
}

export interface VelocityMetrics {
  current_rate: number;
  avg_rate_1h: number;
  avg_rate_24h: number;
  peak_rate_24h: number;
  trend: 'increasing' | 'decreasing' | 'stable';
}

// WebSocket message types
export interface WebSocketMessage {
  type: 'threat' | 'heartbeat' | 'welcome' | 'echo';
  data?: any;
  timestamp?: string;
}

// Pagination
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// Query params
export interface ThreatQueryParams {
  sensor_id?: string;
  detector_type?: string;
  threat_type?: string;
  severity?: string;
  start_time?: string;
  end_time?: string;
  page?: number;
  page_size?: number;
}
