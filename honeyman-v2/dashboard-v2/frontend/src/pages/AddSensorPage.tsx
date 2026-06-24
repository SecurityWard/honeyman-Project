import { useMemo, useState } from 'react';
import './AddSensorPage.css';

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

  const installCommand = `curl -sSL https://honeymanproject.com/install | sudo HONEYMAN_API='${apiBase}' bash`;

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

      <section className="install-card danger">
        <h2>Read this first &mdash; you are deliberately inviting attacks</h2>
        <p>
          <strong>
            Honeyman sensors exist to attract and observe malicious activity.
            That is the entire point. By installing one, you are knowingly
            putting a device in a position to be probed, attacked, infected,
            and used as a foothold.
          </strong>
        </p>
        <p>Treat the sensor like a single-use tool, not a trusted endpoint:</p>
        <ul>
          <li>
            <strong>Use a device you don&rsquo;t care about.</strong> No personal
            data, no SSH keys for other systems, no cloud credentials, no
            saved WiFi for your real network if you can avoid it.
          </li>
          <li>
            <strong>Segment its network.</strong> Put it on a guest VLAN /
            isolated SSID with no route to anything that matters. If the
            sensor gets compromised, you want the blast radius to end at the
            sensor.
          </li>
          <li>
            <strong>Reimage on a schedule.</strong> Wipe the SD card and
            reinstall every few weeks &mdash; or sooner after any event you
            can&rsquo;t explain. The agent has no built-in integrity check
            for itself.
          </li>
          <li>
            <strong>Plugging hostile USB drives into a sensor is the test
            scenario.</strong> The malware-hash scanner reads files to hash
            them, which is enough to trigger many payloads. Assume the device
            is compromised after every meaningful test and reimage.
          </li>
          <li>
            <strong>Know your local law.</strong> Capturing wireless traffic,
            running honeypots, and observing nearby Bluetooth devices is
            regulated in some jurisdictions. Don&rsquo;t deploy where you
            don&rsquo;t have the authority to.
          </li>
        </ul>
        <p className="footnote">
          Software is MIT-licensed and provided as-is. The maintainers accept
          no liability for any damage to the host device, surrounding network,
          or anything observed by the sensor. If those terms aren&rsquo;t
          acceptable, don&rsquo;t install.
        </p>
      </section>

      <section className="install-card warning">
        <h2>Hardware caveat &mdash; single-adapter Pis</h2>
        <p>
          <strong>If the device has only one wireless adapter, do not enable WiFi
          or AirDrop detection during install.</strong> Both put the adapter into
          monitor mode, which disconnects the device from its network. On a Pi
          Zero W, Pi Zero 2 W, or any single-radio box, that means the installer
          loses its own connection mid-run and onboarding never completes.
        </p>
        <p>To use WiFi/AirDrop detection on a single-radio device, do one of:</p>
        <ul>
          <li>Connect the device via <strong>Ethernet</strong> before running the installer.</li>
          <li>Add a <strong>second USB WiFi adapter</strong> (e.g. ALFA AWUS036ACS) &mdash; one stays in managed mode for connectivity, the other goes into monitor mode for detection.</li>
          <li>Or install first with WiFi off, then enable it later by editing <code>/etc/honeyman/config.yaml</code> on a device that has the right hardware.</li>
        </ul>
        <p className="footnote">
          The installer detects this case automatically and defaults WiFi/AirDrop
          to off when only one WiFi adapter is present. USB, BLE, and the
          optional network honeypot are unaffected.
        </p>
      </section>

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
        <pre className="block-code"><code>{`curl -sSL https://honeymanproject.com/install | sudo \\
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
