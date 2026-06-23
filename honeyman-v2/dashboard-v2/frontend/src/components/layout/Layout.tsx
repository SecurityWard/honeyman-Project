import { Outlet, NavLink } from 'react-router-dom';
import './Layout.css';

export default function Layout() {
  return (
    <div className="layout">
      <header className="header">
        <div className="header-content">
          <div className="brand">
            <img src="/honeyman-logo.svg" alt="Honeyman Logo" className="brand-logo" />
            <div className="brand-text">
              <h1>Honeyman</h1>
              <span className="version">Dashboard</span>
            </div>
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
            <NavLink
              to="/add-sensor"
              className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}
            >
              Add Sensor
            </NavLink>
            <NavLink
              to="/about"
              className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}
            >
              About
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
        <p>Honeyman &mdash; multi-vector threat detection for physical events.</p>
      </footer>
    </div>
  );
}
