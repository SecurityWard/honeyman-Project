import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import type { TopThreat } from '../../types';

interface TopThreatsChartProps {
  data: TopThreat[];
  height?: number;
}

const COLORS = ['#dc2626', '#ea580c', '#f59e0b', '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981'];

export default function TopThreatsChart({ data, height = 300 }: TopThreatsChartProps) {
  return (
    <div className="chart-container">
      <h3>Top Threat Types</h3>
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
          <XAxis
            dataKey="threat_type"
            stroke="#6b7280"
            style={{ fontSize: '12px' }}
            angle={-45}
            textAnchor="end"
            height={80}
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
            formatter={(value: number, _name: string, props: any) => [
              `${value} (${props.payload.percentage.toFixed(1)}%)`,
              'Count'
            ]}
          />
          <Bar dataKey="count" radius={[8, 8, 0, 0]}>
            {data.map((_entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
