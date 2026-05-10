import './AboutPage.css';

export default function AboutPage() {
  return (
    <div className="about-page">
      <div className="about-hero">
        <h1>Honeyman V2</h1>
        <p className="tagline">Physical Security Threat Detection Platform</p>
      </div>

      <div className="about-content">
        <section className="about-section">
          <h2>What is Honeyman V2?</h2>
          <p>
            Honeyman V2 is an advanced physical security threat detection platform designed to identify and monitor
            potential security risks in real-time. The system deploys network of sensors that continuously monitor
            for suspicious activity across WiFi, USB, and Bluetooth interfaces.
          </p>
          <p>
            Built with modern technologies including React, FastAPI, PostgreSQL, and MQTT, Honeyman V2 provides
            real-time threat visualization, historical analysis, and comprehensive security insights.
          </p>
        </section>

        <section className="about-section">
          <h2>Detection Capabilities</h2>
          <div className="capabilities-grid">
            <div className="capability-card">
              <h3>WiFi Threat Detection</h3>
              <ul>
                <li><strong>Evil Twin Detection:</strong> Identifies rogue access points impersonating legitimate networks</li>
                <li><strong>Deauthentication Attacks:</strong> Detects WiFi jamming and forced disconnections</li>
                <li><strong>Rogue Access Points:</strong> Discovers unauthorized wireless networks</li>
                <li><strong>Weak Security:</strong> Flags networks using outdated encryption (WEP, WPA)</li>
              </ul>
            </div>

            <div className="capability-card">
              <h3>USB Threat Detection</h3>
              <ul>
                <li><strong>Malicious Devices:</strong> Identifies known bad USB devices via hash database (360+ signatures)</li>
                <li><strong>HID Attacks:</strong> Detects USB devices posing as keyboards/mice (BadUSB, Rubber Ducky)</li>
                <li><strong>Mass Storage Threats:</strong> Monitors suspicious file operations and autorun attempts</li>
                <li><strong>Device Fingerprinting:</strong> Tracks unusual device characteristics</li>
              </ul>
            </div>

            <div className="capability-card">
              <h3>Bluetooth Detection</h3>
              <ul>
                <li><strong>Unauthorized Devices:</strong> Discovers unknown Bluetooth devices in range</li>
                <li><strong>Active Scanning:</strong> Monitors for surveillance and tracking attempts</li>
                <li><strong>Device Profiling:</strong> Identifies suspicious device behaviors</li>
              </ul>
            </div>
          </div>
        </section>

        <section className="about-section">
          <h2>How Metrics Are Calculated</h2>

          <div className="metric-explanation">
            <h3>Threat Score</h3>
            <p>Each threat is assigned a confidence score (0-100%) based on multiple factors:</p>
            <div className="formula">
              <code>ThreatScore = BaseScore × ConfidenceMultiplier × ContextWeight</code>
            </div>
            <ul>
              <li><strong>Base Score:</strong> Determined by threat type and detection method</li>
              <li><strong>Confidence Multiplier:</strong> Based on signature matches, behavior analysis, and known indicators</li>
              <li><strong>Context Weight:</strong> Historical patterns, location, and time-of-day factors</li>
            </ul>
          </div>

          <div className="metric-explanation">
            <h3>Severity Classification</h3>
            <div className="severity-levels">
              <div className="severity-item critical">
                <span className="severity-badge">Critical</span>
                <p>Confirmed malicious activity requiring immediate response (known malware, active attacks)</p>
              </div>
              <div className="severity-item high">
                <span className="severity-badge">High</span>
                <p>Highly suspicious activity that should be investigated promptly (policy violations, weak security)</p>
              </div>
              <div className="severity-item medium">
                <span className="severity-badge">Medium</span>
                <p>Potentially suspicious behavior warranting review (anomalous patterns, unusual devices)</p>
              </div>
              <div className="severity-item low">
                <span className="severity-badge">Low</span>
                <p>Informational alerts and baseline monitoring (unusual but not necessarily malicious)</p>
              </div>
            </div>
          </div>

          <div className="metric-explanation">
            <h3>Threat Velocity</h3>
            <p>Measures the rate of threat detection over time:</p>
            <div className="formula">
              <code>Velocity = TotalThreats / TimeWindow (hours)</code>
            </div>
            <p>
              This metric helps identify threat spikes and patterns. A sudden increase in velocity may indicate
              an ongoing attack or elevated risk period.
            </p>
          </div>
        </section>

        <section className="about-section">
          <h2>System Architecture</h2>
          <div className="architecture-flow">
            <div className="arch-step">
              <div className="arch-number">1</div>
              <h4>Sensors</h4>
              <p>Raspberry Pi-based detection nodes running custom monitoring software</p>
            </div>
            <div className="arch-arrow">→</div>
            <div className="arch-step">
              <div className="arch-number">2</div>
              <h4>MQTT Broker</h4>
              <p>Message queue for real-time threat data transmission</p>
            </div>
            <div className="arch-arrow">→</div>
            <div className="arch-step">
              <div className="arch-number">3</div>
              <h4>Backend API</h4>
              <p>FastAPI server processing and storing threat data</p>
            </div>
            <div className="arch-arrow">→</div>
            <div className="arch-step">
              <div className="arch-number">4</div>
              <h4>PostgreSQL</h4>
              <p>Time-series database for historical analysis</p>
            </div>
            <div className="arch-arrow">→</div>
            <div className="arch-step">
              <div className="arch-number">5</div>
              <h4>Dashboard</h4>
              <p>Real-time visualization via WebSocket</p>
            </div>
          </div>

          <div className="tech-stack">
            <h4>Technology Stack</h4>
            <div className="tech-grid">
              <div className="tech-item">
                <strong>Frontend:</strong> React, TypeScript, Recharts, Leaflet
              </div>
              <div className="tech-item">
                <strong>Backend:</strong> Python, FastAPI, SQLAlchemy, Pydantic
              </div>
              <div className="tech-item">
                <strong>Database:</strong> PostgreSQL with time-series optimizations
              </div>
              <div className="tech-item">
                <strong>Messaging:</strong> MQTT (Eclipse Mosquitto)
              </div>
              <div className="tech-item">
                <strong>Sensors:</strong> Raspberry Pi 4, Python detection scripts
              </div>
              <div className="tech-item">
                <strong>Deployment:</strong> Nginx, systemd, Docker-ready
              </div>
            </div>
          </div>
        </section>

        <section className="about-section">
          <h2>Data Retention & Privacy</h2>
          <p>
            By default, Honeyman V2 retains threat data for <strong>90 days</strong>. This retention period is
            configurable per installation to meet specific compliance or storage requirements.
          </p>
          <p>
            The system is designed for internal security monitoring and does not collect personally identifiable
            information (PII). All detected data relates to device characteristics and network behavior patterns.
          </p>
        </section>

        <section className="about-section">
          <h2>Getting Started</h2>
          <div className="getting-started">
            <p>To deploy a Honeyman V2 sensor:</p>
            <ol>
              <li>Configure a Raspberry Pi 4 with the sensor software</li>
              <li>Connect to your MQTT broker</li>
              <li>Enable desired detection modules (WiFi, USB, Bluetooth)</li>
              <li>Monitor threats in real-time on this dashboard</li>
            </ol>
            <p className="note">
              For detailed installation instructions, refer to the deployment documentation in the project repository.
            </p>
          </div>
        </section>

        <footer className="about-footer">
          <p>&copy; 2025 Honeyman V2 - Open Source Physical Security Platform</p>
          <p className="version">Dashboard Version 2.0.0</p>
        </footer>
      </div>
    </div>
  );
}
