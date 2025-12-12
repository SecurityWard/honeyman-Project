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
  acknowledged: boolean;
  acknowledged_at?: string;
  acknowledged_by?: string;
}

// Analytics types
export interface DashboardOverview {
  total_threats_24h: number;
  total_sensors: number;
  active_sensors: number;
  critical_threats_24h: number;
  threat_rate_per_hour: number;
  top_threat_type: string;
  top_detector: string;
  avg_confidence_score: number;
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

// User types
export interface User {
  id: string;
  username: string;
  email: string;
  full_name?: string;
  role: 'admin' | 'analyst' | 'viewer';
  is_active: boolean;
  created_at: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  user: User;
  access_token: string;
  refresh_token: string;
  token_type: string;
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
  acknowledged?: boolean;
  page?: number;
  page_size?: number;
}
