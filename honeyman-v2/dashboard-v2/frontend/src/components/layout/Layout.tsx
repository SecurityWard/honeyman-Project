import { Outlet, NavLink } from 'react-router-dom';
import './Layout.css';

export default function Layout() {
  return (
    <div className="layout">
      <header className="header">
        <div className="header-content">
          <div className="brand">
            <h1>🍯 Honeyman V2</h1>
            <span className="version">Dashboard</span>
          </div>

          <nav className="nav">
            <NavLink
              to="/dashboard"
              className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}
            >
              Dashboard
            </NavLink>
            <NavLink
              to="/sensors"
              className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}
            >
              Sensors
            </NavLink>
          </nav>

          <div className="header-actions">
            <div className="connection-status">
              <span className="status-indicator online"></span>
              <span className="status-text">Connected</span>
            </div>
          </div>
        </div>
      </header>

      <main className="main-content">
        <Outlet />
      </main>

      <footer className="footer">
        <p>&copy; 2025 Honeyman V2 - Real-time Threat Detection Platform</p>
      </footer>
    </div>
  );
}
