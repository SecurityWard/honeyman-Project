import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { TopSensor } from '../../types';

interface TopSensorsChartProps {
  data: TopSensor[];
  height?: number;
}

const COLORS = ['#dc2626', '#ea580c', '#f59e0b', '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981'];

export default function TopSensorsChart({ data, height = 300 }: TopSensorsChartProps) {
  const chartData = data.map(sensor => ({
    name: sensor.sensor_name || sensor.sensor_id,
    value: sensor.threat_count,
    percentage: sensor.percentage,
  }));

  return (
    <div className="chart-container">
      <h3>Top Sensors by Activity</h3>
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={({ name, percentage }) => `${name}: ${percentage.toFixed(1)}%`}
            outerRadius={80}
            fill="#8884d8"
            dataKey="value"
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#ffffff',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
            }}
            formatter={(value: number, name: string, props: any) => [
              `${value} (${props.payload.percentage.toFixed(1)}%)`,
              'Threats'
            ]}
          />
          <Legend
            wrapperStyle={{ fontSize: '12px' }}
            layout="vertical"
            align="right"
            verticalAlign="middle"
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
