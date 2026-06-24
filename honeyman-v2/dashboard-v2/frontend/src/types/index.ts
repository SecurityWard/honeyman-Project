export interface Sensor {
  id: string;
  sensor_id: string;
  name: string;
  description?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  city?: string | null;
  country?: string | null;
  is_active: boolean;
  is_online: boolean;
  last_heartbeat?: string | null;
  location_method?: string | null;
  location_accuracy?: number | null;
  enabled_detectors: string[];
  transport_protocol?: string;
  capabilities?: Record<string, boolean>;
  platform?: string | null;
  architecture?: string | null;
  agent_version?: string | null;
  python_version?: string | null;
  total_threats_detected: number;
  threats_last_24h: number;
  created_at: string;
  updated_at?: string | null;
  registered_at?: string;
}

// The /api/v2/sensors endpoint wraps the list as { sensors, total, page, page_size }.
// Threats use a different envelope (`items`) — see PaginatedResponse below.
export interface SensorListResponse {
  sensors: Sensor[];
  total: number;
  page: number;
  page_size: number;
}

// Matches a single entry in ThreatResponse.matched_rules (see backend
// schemas/threat.py). Whichever rule's evaluator fires for an event gets
// summarised here so the dashboard can show *what* triggered, not just *that*
// something triggered.
export interface MatchedRule {
  rule_id: string;
  name: string;
  severity: string;
  confidence: number;
}

// Threat types — fields here mirror app/schemas/threat.py::ThreatResponse on
// the backend. Don't add fields that aren't actually in the API response.
export interface Threat {
  id: string;
  timestamp: string;
  sensor_id: string;
  sensor_name?: string | null;
  detector_type: string;
  threat_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence?: number | null;
  threat_score?: number | null;

  // Device / network fingerprint
  device_name?: string | null;
  device_mac?: string | null;
  device_ip?: string | null;
  src_host?: string | null;
  src_port?: number | null;
  dst_host?: string | null;
  dst_port?: number | null;

  // Rules + raw event payload (the meat — what actually fired)
  matched_rules?: MatchedRule[];
  raw_event?: Record<string, any> | null;
  mitre_tactics?: string[];
  mitre_techniques?: string[];

  // Location chain
  latitude?: number | null;
  longitude?: number | null;
  city?: string | null;
  country?: string | null;
  accuracy_meters?: number | null;
  location_method?: 'gps' | 'wifi' | 'ip' | 'manual' | null;

  created_at?: string;
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
