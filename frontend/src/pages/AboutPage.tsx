import './AboutPage.css';

export default function AboutPage() {
  return (
    <div className="about-page">
      <div className="about-hero">
        <h1>Honeyman</h1>
        <p className="tagline">Mobile, multi-vector threat collection for physical events.</p>
      </div>

      <div className="about-content">
        <section className="about-section">
          <h2>What it is</h2>
          <p>
            Honeyman puts a Raspberry Pi-class sensor in a backpack, on a hotel-room desk, or
            in a conference hall, and reports malicious USB, WiFi, BLE, and AirDrop activity
            to this dashboard in real time. When a sensor is on a network, it can also expose
            SSH and HTTP honeypots and report intrusion attempts as events.
          </p>
          <p>
            This page is a viewing surface. There are no accounts, no actions, no edits.
            Anyone with the URL can see the map, filter threats, and watch the live feed.
          </p>
        </section>

        <section className="about-section">
          <h2>What it detects</h2>
          <div className="capabilities-grid">
            <div className="capability-card">
              <h3>USB</h3>
              <ul>
                <li><strong>BadUSB / HID injection:</strong> Rubber Ducky, Bash Bunny, OMG Cable, Flipper Zero acting as HID, Teensy, Digispark</li>
                <li><strong>Mass storage scanning:</strong> recursive SHA-256/MD5 hashing against 600+ real malware signatures from abuse.ch MalwareBazaar (Mirai, AgentTesla, Formbook, RemcosRAT, Vidar, WannaCry, &hellip;) plus the EICAR test file</li>
                <li><strong>VID/PID fingerprinting</strong> of known attack devices</li>
                <li><strong>Suspicious volume labels</strong> and autorun.inf inspection</li>
              </ul>
            </div>

            <div className="capability-card">
              <h3>WiFi</h3>
              <ul>
                <li><strong>Evil Twin APs</strong> (same SSID, different BSSIDs)</li>
                <li><strong>Deauth and beacon flooding</strong></li>
                <li><strong>Attack tool fingerprints:</strong> WiFi Pineapple, ESP8266 Deauther, Flipper Zero WiFi</li>
                <li><strong>Weak encryption</strong> (WEP, vulnerable WPA) on scanned networks</li>
              </ul>
            </div>

            <div className="capability-card">
              <h3>BLE</h3>
              <ul>
                <li><strong>Flipper Zero</strong> including Unleashed and Xtreme firmware variants</li>
                <li><strong>BLE spam / beacon flooding</strong></li>
                <li><strong>BLE HID keyloggers and ESP32 attack tools</strong></li>
                <li><strong>Manufacturer-data spoofing</strong></li>
              </ul>
            </div>

            <div className="capability-card">
              <h3>AirDrop / mDNS</h3>
              <ul>
                <li>Suspicious service names and generic device spoofing</li>
                <li>Rapid announcement floods</li>
                <li>TXT-record abuse</li>
              </ul>
            </div>

            <div className="capability-card">
              <h3>Network honeypots <em>(optional)</em></h3>
              <ul>
                <li>SSH brute-force attempts (logged, never authenticated)</li>
                <li>HTTP credential harvesting against a fake admin page</li>
                <li>Port scans and service enumeration</li>
              </ul>
            </div>
          </div>
          <p className="note">
            For accuracy expectations and an honest list of what Honeyman does <em>not</em>
            catch, see <code>CAPABILITIES.md</code> in the repository.
          </p>
        </section>

        <section className="about-section">
          <h2>Severity</h2>
          <p>
            Each rule is tagged with one of four severities. The map color-codes markers
            accordingly.
          </p>
          <div className="severity-levels">
            <div className="severity-item critical">
              <span className="severity-badge">Critical</span>
              <p>Confirmed attack tooling or known-malicious payload &mdash; e.g. a Rubber Ducky VID/PID match, a malware hash hit, an active deauth flood.</p>
            </div>
            <div className="severity-item high">
              <span className="severity-badge">High</span>
              <p>Strong indicator of attacker presence &mdash; e.g. Pineapple beacons, Flipper Zero advertising, repeated SSH brute-force from one source.</p>
            </div>
            <div className="severity-item medium">
              <span className="severity-badge">Medium</span>
              <p>Suspicious but not unambiguous &mdash; unusual device names, rapidly cycling MAC addresses, mDNS oddities.</p>
            </div>
            <div className="severity-item low">
              <span className="severity-badge">Low</span>
              <p>Informational and baseline noise &mdash; weak-but-not-broken encryption, hotspot-style SSIDs, unknown BLE devices.</p>
            </div>
          </div>
        </section>

        <section className="about-section">
          <h2>Confidence and location</h2>
          <p>
            Every threat carries a <strong>confidence</strong> between 0 and 1, set by the
            rule that matched. A VID/PID equality match is high (0.95+); a name-pattern
            match against a generic word like &ldquo;pwn&rdquo; is lower (0.6&ndash;0.7).
            Confidence reflects how certain the rule&rsquo;s author was about the signal,
            not a learned model.
          </p>
          <p>
            Each threat also carries a <strong>location</strong> with an explicit method:
          </p>
          <ul className="plain-list">
            <li><strong>Manual</strong> &mdash; the operator pinned the sensor at install time.</li>
            <li><strong>GPS</strong> &mdash; a GPS receiver attached to the sensor reported a fix.</li>
            <li><strong>WiFi</strong> &mdash; the sensor scanned nearby access points and looked them up against Mozilla&rsquo;s Location Service.</li>
            <li><strong>IP</strong> &mdash; coarse geolocation by public IP, accurate to roughly a city block at best.</li>
          </ul>
          <p>
            The map draws a translucent circle around each marker sized to the reported
            accuracy and colored by method. A tight green circle means GPS-grade; a wide
            dashed gray circle means IP-only.
          </p>
        </section>

        <section className="about-section">
          <h2>How a threat gets here</h2>
          <p>
            The sensor runs a Python agent that loads YAML detection rules and executes
            detector modules in parallel. When a rule matches, the agent attaches a location
            and POSTs the event over HTTPS to the backend, authenticated with a per-sensor
            API key issued at install time. The backend stores threats in Postgres with
            TimescaleDB (one-day chunks, 90-day retention) and pushes new events to this
            dashboard over a WebSocket.
          </p>
          <p>
            If the sensor loses connectivity, threats queue in a local SQLite buffer and
            drain when the link comes back &mdash; no data is dropped during short outages.
          </p>
        </section>

        <section className="about-section">
          <h2>Retention and privacy</h2>
          <p>
            Threats are kept for <strong>90 days</strong> by default, compressed after
            seven. Honeyman does not collect personally identifiable information &mdash;
            the data is device characteristics (MAC addresses, vendor IDs, SSIDs) and the
            location of the <em>sensor</em>, not of anyone observed by it.
          </p>
          <p>
            Capturing wireless traffic, running honeypots, and observing nearby Bluetooth
            devices may be regulated in your jurisdiction. Deploy only where you have the
            legal authority to do so.
          </p>
        </section>

        <section className="about-section">
          <h2>Adding a sensor</h2>
          <p>
            On a fresh Raspberry Pi (Zero 2 W, 4, or 5), one command:
          </p>
          <div className="formula">
            <code>curl -sSL https://honeymanproject.com/install | sudo bash</code>
          </div>
          <p>
            The installer detects available hardware, asks for a sensor name and optional
            location, registers the sensor with the backend, writes the returned API key to{' '}
            <code>/etc/honeyman/api_key</code> (mode 0600), and starts the systemd unit. The sensor
            usually appears on the map within a minute or two.
          </p>
          <p>
            For full instructions and non-interactive installs (e.g. for flashing many SD
            cards), see the <a href="/add-sensor">Add Sensor</a> page.
          </p>
        </section>

        <footer className="about-footer">
          <p>Honeyman &mdash; open source, MIT licensed.</p>
          <p>
            <a href="https://github.com/SecurityWard/honeyman-Project" target="_blank" rel="noopener noreferrer">
              github.com/SecurityWard/honeyman-Project
            </a>
          </p>
        </footer>
      </div>
    </div>
  );
}
