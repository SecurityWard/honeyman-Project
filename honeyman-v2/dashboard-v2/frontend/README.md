# Honeyman V2 Dashboard Frontend

Real-time threat detection dashboard built with React 18, TypeScript, and Vite.

## Features

- **Real-time Threat Map**: Interactive Leaflet map showing threat locations with severity indicators
- **Live Data Feed**: WebSocket integration for real-time threat updates
- **Analytics Dashboard**: Recharts-powered visualizations for threat trends and statistics
- **Sensor Management**: Monitor and manage deployed Honeyman sensors
- **Responsive Design**: Mobile-friendly interface

## Tech Stack

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool
- **React Router** - Client-side routing
- **TanStack Query** - Server state management
- **Axios** - HTTP client
- **Leaflet** - Interactive maps
- **Recharts** - Chart library
- **date-fns** - Date utilities

## Prerequisites

- Node.js 18+
- npm or yarn
- Honeyman V2 Backend running (see [../backend/README.md](../backend/README.md))

## Quick Start

```bash
# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your backend URL

# Start development server
npm run dev

# Visit http://localhost:5173
```

## Environment Variables

Create a `.env` file in the root directory:

```env
# Backend API URL
VITE_API_BASE_URL=http://localhost:8000/api/v2

# WebSocket URL
VITE_WS_URL=ws://localhost:8000/api/v2/ws
```

## Development

```bash
# Start dev server with hot reload
npm run dev

# Type check
npm run build

# Lint code
npm run lint

# Preview production build
npm run preview
```

## Project Structure

```
src/
├── components/
│   ├── analytics/         # Chart components
│   │   ├── ThreatTrendsChart.tsx
│   │   ├── TopThreatsChart.tsx
│   │   └── TopSensorsChart.tsx
│   ├── dashboard/         # Dashboard components
│   │   └── DashboardOverview.tsx
│   ├── layout/            # Layout components
│   │   └── Layout.tsx
│   ├── map/               # Map components
│   │   └── ThreatMap.tsx
│   └── sensors/           # Sensor components
│       └── SensorList.tsx
├── hooks/                 # Custom React hooks
│   ├── useAnalytics.ts
│   ├── useSensors.ts
│   └── useThreats.ts
├── pages/                 # Page components
│   ├── DashboardPage.tsx
│   └── SensorsPage.tsx
├── services/              # API and services
│   ├── api.ts
│   └── websocket.ts
├── types/                 # TypeScript types
│   └── index.ts
├── utils/                 # Utility functions
├── App.tsx                # Root component
└── main.tsx               # Entry point
```

## API Integration

The dashboard integrates with the Honeyman V2 Backend API:

### REST API
- **Authentication**: JWT-based auth with auto-refresh
- **Sensors**: CRUD operations for sensor management
- **Threats**: Query and acknowledge threats
- **Analytics**: Dashboard statistics and trends

### WebSocket
- Real-time threat notifications
- Live sensor updates
- Automatic reconnection with exponential backoff

## Features

### Dashboard Page
- Overview statistics (threats, sensors, rates)
- Interactive threat map with clustering
- Threat trends chart (24h)
- Top threat types bar chart
- Top sensors pie chart
- Real-time threat feed

### Sensors Page
- List all sensors with status
- Search and filter sensors
- View sensor details
- Edit sensor configuration
- Delete sensors

## Building for Production

```bash
# Build production bundle
npm run build

# Output: dist/
```

### Deployment

The built files can be served with any static file server:

```bash
# Using Python
python -m http.server -d dist 8080

# Using Node serve
npx serve -s dist -p 8080

# Using nginx
# Copy dist/ to /var/www/honeyman-dashboard/
```

### Docker Deployment

```dockerfile
FROM nginx:alpine
COPY dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

## Performance

- **Code Splitting**: Automatic route-based splitting
- **Lazy Loading**: Components loaded on demand
- **Asset Optimization**: Minified JS/CSS, optimized images
- **Caching**: Service worker for offline support

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Troubleshooting

### WebSocket Connection Fails
- Check backend is running: `http://localhost:8000/health`
- Verify WebSocket URL in `.env`
- Check browser console for errors

### API Requests Fail
- Ensure backend is accessible
- Check CORS settings in backend
- Verify API base URL in `.env`

### Map Not Loading
- Check Leaflet CSS is imported
- Verify internet connection (map tiles)
- Check browser console for errors

## Contributing

1. Follow TypeScript strict mode
2. Use functional components with hooks
3. Implement proper error handling
4. Add loading states for async operations
5. Write clean, readable code

## License

MIT License - See [LICENSE](../LICENSE)

---

**Version**: 2.0.0
**Last Updated**: 2025-12-07
