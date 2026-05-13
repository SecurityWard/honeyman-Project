import { useMemo, useState } from 'react';
import './AddSensorPage.css';

// V2 onboarding page. Public, read-only — just shows the install command
// and explains what the sensor will do. No registration UI here; the sensor
// self-registers when install.sh runs.

export default function AddSensorPage() {
  // The base API URL the sensor will register against. Default to the same
  // origin the dashboard talks to; operator can override via env at build time.
  const apiBase = useMemo(() => {
    const fromEnv = (import.meta as any).env?.VITE_API_BASE_URL as string | undefined;
    if (fromEnv) {
      // Strip /api/v2 suffix if present — install.sh wants the bare host.
      return fromEnv.replace(/\/api\/v2\/?$/, '');
    }
    return window.location.origin.replace(/:\d+$/, ':8000');
  }, []);

  const installCommand = `curl -sSL https://honeyman.io/install | sudo HONEYMAN_API='${apiBase}' bash`;

  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(installCommand);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard API blocked — leave the user to select manually */
    }
  };

  return (
    <div className="add-sensor-page">
      <header className="add-sensor-hero">
        <h1>Add a sensor</h1>
        <p className="lede">
          A Honeyman sensor self-registers the first time it runs. Drop the install command
          below onto a Raspberry Pi (or any Linux box), and the dashboard will show it within
          about a minute.
        </p>
      </header>

      <section className="install-card">
        <div className="install-card-header">
          <h2>1. Run on the sensor</h2>
          <span className="hint">
            Pi Zero 2 W, Pi 4, or Pi 5 recommended &middot; Debian/Ubuntu also works
          </span>
        </div>
        <div className="install-command">
          <pre><code>{installCommand}</code></pre>
          <button
            type="button"
            className={`copy-btn ${copied ? 'copied' : ''}`}
            onClick={handleCopy}
            aria-label="Copy install command"
          >
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
        <ul className="install-notes">
          <li>The script will prompt for a sensor name and location label.</li>
          <li>It detects available hardware (USB, WiFi monitor mode, Bluetooth) and enables matching detectors.</li>
          <li>It calls <code>POST /api/v2/sensors/register</code>, captures the one-time API key, and writes it to <code>/etc/honeyman/api_key</code> with mode <code>0600</code>.</li>
          <li>It installs <code>honeyman-agent</code> via pip and starts it under systemd.</li>
        </ul>
      </section>

      <section className="install-card">
        <h2>2. Verify on the dashboard</h2>
        <p>
          Within ~60 seconds, the new sensor appears under <a href="/sensors">Sensors</a>. Heartbeats
          carry the current location, so the sensor's marker shows up on the map even before any threats
          are detected.
        </p>
      </section>

      <section className="install-card">
        <h2>Non-interactive install</h2>
        <p>
          For batch SD-card flashing or cloud-init, pre-set the values:
        </p>
        <pre className="block-code"><code>{`curl -sSL https://honeyman.io/install | sudo \\
  SENSOR_NAME='defcon-hotel' \\
  LOCATION='DefCon 32 hotel lobby' \\
  NON_INTERACTIVE=1 \\
  HONEYMAN_API='${apiBase}' \\
  bash`}</code></pre>
      </section>

      <section className="install-card secondary">
        <h2>What the sensor detects</h2>
        <div className="capabilities-list">
          <span><strong>USB</strong> &mdash; BadUSB, Rubber Ducky, OMG Cable, 360+ malware-hash matches</span>
          <span><strong>WiFi</strong> &mdash; Evil Twin, deauth, Pineapple, beacon flooding</span>
          <span><strong>BLE</strong> &mdash; Flipper Zero, BLE spam, HID keyloggers, manufacturer-data spoofing</span>
          <span><strong>AirDrop / mDNS</strong> &mdash; service flooding, suspicious names, TXT-record abuse</span>
          <span><strong>Network honeypot</strong> &mdash; SSH brute force, HTTP credential harvesting, port scans (toggleable)</span>
        </div>
      </section>

      <section className="install-card secondary">
        <h2>Manual install</h2>
        <p>
          If you'd rather install manually instead of piping into bash, see the agent README:{' '}
          <a
            href="https://github.com/SecurityWard/honeyman-Project/blob/main/honeyman-v2/agent/README.md"
            target="_blank"
            rel="noreferrer noopener"
          >
            github.com/SecurityWard/honeyman-Project &rarr; honeyman-v2/agent/README.md
          </a>.
        </p>
      </section>
    </div>
  );
}
