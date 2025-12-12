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

export function useDashboardOverview() {
  return useQuery({
    queryKey: ['dashboard', 'overview'],
    queryFn: async () => {
      const response = await api.get<DashboardOverview>('/analytics/overview');
      return response.data;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

export function useThreatTrends(period: 'hourly' | 'daily' = 'hourly', hours: number = 24) {
  return useQuery({
    queryKey: ['analytics', 'trends', period, hours],
    queryFn: async () => {
      const response = await api.get<ThreatTrend[]>('/analytics/trends', {
        params: { period, hours }
      });
      return response.data;
    },
    refetchInterval: 60000, // Refresh every minute
  });
}

export function useTopThreats(limit: number = 10, hours: number = 24) {
  return useQuery({
    queryKey: ['analytics', 'top-threats', limit, hours],
    queryFn: async () => {
      const response = await api.get<TopThreat[]>('/analytics/top-threats', {
        params: { limit, hours }
      });
      return response.data;
    },
    refetchInterval: 60000,
  });
}

export function useTopSensors(limit: number = 10, hours: number = 24) {
  return useQuery({
    queryKey: ['analytics', 'top-sensors', limit, hours],
    queryFn: async () => {
      const response = await api.get<TopSensor[]>('/analytics/top-sensors', {
        params: { limit, hours }
      });
      return response.data;
    },
    refetchInterval: 60000,
  });
}

export function useGeoMap(hours: number = 24) {
  return useQuery({
    queryKey: ['analytics', 'map', hours],
    queryFn: async () => {
      const response = await api.get<GeoThreat[]>('/analytics/map', {
        params: { hours }
      });
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
