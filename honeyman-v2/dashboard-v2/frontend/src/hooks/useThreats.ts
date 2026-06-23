import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import type { Threat, PaginatedResponse, ThreatQueryParams } from '../types';

export function useThreats(params: ThreatQueryParams = {}) {
  return useQuery({
    queryKey: ['threats', params],
    queryFn: async () => {
      const response = await api.get<PaginatedResponse<Threat>>('/threats', { params });
      return response.data;
    },
  });
}

export function useThreat(threatId: string) {
  return useQuery({
    queryKey: ['threats', threatId],
    queryFn: async () => {
      const response = await api.get<Threat>(`/threats/${threatId}`);
      return response.data;
    },
    enabled: !!threatId,
  });
}
