import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import type {
  DashboardOverview,
  ThreatTrend,
  TopThreat,
  TopSensor,
  GeoThreat,
  VelocityMetrics
} from '../types';

export function useDashboardOverview(sensorId?: string) {
  return useQuery({
    queryKey: ['dashboard', 'overview', sensorId],
    queryFn: async () => {
      const params: Record<string, any> = {};
      if (sensorId) params.sensor_id = sensorId;
      const response = await api.get<DashboardOverview>('/analytics/overview', { params });
      return response.data;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

export function useThreatTrends(period: 'hourly' | 'daily' = 'hourly', hours: number = 24, sensorId?: string) {
  return useQuery({
    queryKey: ['analytics', 'trends', period, hours, sensorId],
    queryFn: async () => {
      const params: Record<string, any> = { period, hours };
      if (sensorId) params.sensor_id = sensorId;
      const response = await api.get<{ data_points: ThreatTrend[] }>('/analytics/trends', { params });
      return response.data.data_points;
    },
    refetchInterval: 60000, // Refresh every minute
  });
}

export function useTopThreats(limit: number = 10, hours?: number, sensorId?: string) {
  return useQuery({
    queryKey: ['analytics', 'top-threats', limit, hours, sensorId],
    queryFn: async () => {
      const params: Record<string, any> = { limit };
      if (hours !== undefined) {
        params.hours = hours;
      }
      if (sensorId) params.sensor_id = sensorId;
      const response = await api.get<TopThreat[]>('/analytics/top-threats', { params });
      return response.data;
    },
    refetchInterval: 60000,
  });
}

export function useTopSensors(limit: number = 10, hours?: number) {
  return useQuery({
    queryKey: ['analytics', 'top-sensors', limit, hours],
    queryFn: async () => {
      const params: Record<string, any> = { limit };
      if (hours !== undefined) {
        params.hours = hours;
      }
      const response = await api.get<TopSensor[]>('/analytics/top-sensors', { params });
      return response.data;
    },
    refetchInterval: 60000,
  });
}

export function useGeoMap(hours?: number, sensorId?: string) {
  return useQuery({
    queryKey: ['analytics', 'map', hours, sensorId],
    queryFn: async () => {
      const params: Record<string, any> = {};
      if (hours !== undefined) {
        params.hours = hours;
      }
      if (sensorId) params.sensor_id = sensorId;
      const response = await api.get<GeoThreat[]>('/analytics/map', { params });
      return response.data;
    },
    refetchInterval: 60000,
  });
}

export function useVelocity() {
  return useQuery({
    queryKey: ['analytics', 'velocity'],
    queryFn: async () => {
      const response = await api.get<VelocityMetrics>('/analytics/velocity');
      return response.data;
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  });
}
