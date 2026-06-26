import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import type { Sensor, SensorListResponse } from '../types';

export function useSensors(page: number = 1, pageSize: number = 50) {
  return useQuery({
    queryKey: ['sensors', page, pageSize],
    queryFn: async () => {
      const response = await api.get<SensorListResponse>('/sensors', {
        params: { page, page_size: pageSize }
      });
      return response.data;
    },
  });
}

export function useSensor(sensorId: string) {
  return useQuery({
    queryKey: ['sensors', sensorId],
    queryFn: async () => {
      const response = await api.get<Sensor>(`/sensors/${sensorId}`);
      return response.data;
    },
    enabled: !!sensorId,
  });
}

export function useSensorStats(sensorId: string, hours: number = 24) {
  return useQuery({
    queryKey: ['sensors', sensorId, 'stats', hours],
    queryFn: async () => {
      const response = await api.get(`/sensors/${sensorId}/stats`, {
        params: { hours }
      });
      return response.data;
    },
    enabled: !!sensorId,
  });
}
