import axios from 'axios';

// V2: dashboard reads are public — no Authorization header required.
// Sensor → backend writes use per-sensor API keys, but the dashboard
// never makes those calls.

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v2';

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export default api;
