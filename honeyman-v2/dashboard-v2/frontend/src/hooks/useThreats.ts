import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
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

export function useAcknowledgeThreat() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (threatId: string) => {
      const response = await api.put<Threat>(`/threats/${threatId}/acknowledge`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threats'] });
    },
  });
}

export function useDeleteThreat() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (threatId: string) => {
      await api.delete(`/threats/${threatId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threats'] });
    },
  });
}
