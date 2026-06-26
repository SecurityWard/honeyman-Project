import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import type { ThreatTrend } from '../../types';
import { format } from 'date-fns';

interface ThreatTrendsChartProps {
  data: ThreatTrend[];
  height?: number;
}

export default function ThreatTrendsChart({ data, height = 300 }: ThreatTrendsChartProps) {
  const formattedData = data.map(item => ({
    ...item,
    time: format(new Date(item.timestamp), 'MMM dd HH:mm'),
  }));

  return (
    <div className="chart-container">
      <h3>Threat Trends Over Time</h3>
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={formattedData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
          <XAxis
            dataKey="time"
            stroke="#6b7280"
            style={{ fontSize: '12px' }}
          />
          <YAxis
            stroke="#6b7280"
            style={{ fontSize: '12px' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#ffffff',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
            }}
          />
          <Legend
            wrapperStyle={{ fontSize: '14px' }}
          />
          <Line
            type="monotone"
            dataKey="critical"
            stroke="#dc2626"
            strokeWidth={2}
            dot={{ fill: '#dc2626', r: 4 }}
            activeDot={{ r: 6 }}
            name="Critical"
          />
          <Line
            type="monotone"
            dataKey="high"
            stroke="#ea580c"
            strokeWidth={2}
            dot={{ fill: '#ea580c', r: 4 }}
            activeDot={{ r: 6 }}
            name="High"
          />
          <Line
            type="monotone"
            dataKey="medium"
            stroke="#f59e0b"
            strokeWidth={2}
            dot={{ fill: '#f59e0b', r: 4 }}
            activeDot={{ r: 6 }}
            name="Medium"
          />
          <Line
            type="monotone"
            dataKey="low"
            stroke="#3b82f6"
            strokeWidth={2}
            dot={{ fill: '#3b82f6', r: 4 }}
            activeDot={{ r: 6 }}
            name="Low"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
