// Project: IP Security Analyzer
// Version: 1.0
// Author: TheGreatAzizi
// Social: https://x.com/the_azzi | https://github.com/TheGreatAzizi/IP-Security-Analyzer-Cloudflare-Worker

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cf = request.cf || {};
    
    // Metadata Gathering
    const clientIP = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
    const rayId = request.headers.get('cf-ray') || 'Unknown';
    const userAgent = request.headers.get('user-agent') || 'Unknown';
    
    // Core Metadata Intelligence
    const ispName = cf.asOrganization || 'Unknown ISP';
    
    // Heuristic Classification System (Connection Type Detection)
    let connectionType = 'Fixed/Broadband'; // Default
    if (/(Mobile|LTE|Cellular|Wireless|4G|5G|Telecommunication|Vodafone|Verizon|Orange|T-Mobile)/i.test(ispName)) {
        connectionType = 'Mobile / Cellular';
    } else if (/(Hosting|Cloud|Datacenter|VPN|Proxy|Infrastructure|Amazon|Google|Microsoft|DigitalOcean|Hetzner|OVH|Vultr|Oracle|Akamai|Fastly)/i.test(ispName)) {
        connectionType = 'Hosting / Proxy';
    } else if (/(University|College|Education|School|Research|Academy)/i.test(ispName)) {
        connectionType = 'Educational';
    } else if (/(Business|Enterprise|Corporation|Inc|Limited)/i.test(ispName)) {
        connectionType = 'Corporate / Business';
    }

    const metadata = {
      ip: clientIP,
      type: clientIP.includes(':') ? 'IPv6' : 'IPv4',
      asn: cf.asn || '0',
      isp: ispName,
      connectionType: connectionType,
      country: cf.country || 'Unknown',
      city: cf.city || 'Unknown',
      region: cf.region || 'Unknown',
      lat: cf.latitude || '0',
      lon: cf.longitude || '0',
      colo: cf.colo || 'Unknown',
      timezone: cf.timezone || 'UTC',
      tlsVersion: cf.tlsVersion || 'Unknown',
      httpProtocol: cf.httpProtocol || 'Unknown',
      rayId: rayId
    };

    // JSON API Output
    if (url.pathname === '/json') {
      return new Response(JSON.stringify({ status: 'success', metadata }, null, 2), {
        headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store'
        }
      });
    }

    // Advanced Professional HTML Output
    const html = `<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Security Analyzer | Professional Network Forensic</title>
    
    <!-- Professional SEO Meta -->
    <meta name="description" content="Ver 1.0 IP Security Analyzer by TheGreatAzizi. Professional-grade tool for IP Geolocation, VPN detection, and network forensics.">
    <meta name="author" content="TheGreatAzizi">
    
    <!-- Favicon -->
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512'%3E%3Cpath fill='%236366f1' d='M256 0c4.6 0 9.2 1 13.4 2.9L457.7 82.8c22 9.3 38.4 31 38.3 57.2c-.5 99.2-41.3 280.7-213.6 363.2c-16.7 8-36.1 8-52.8 0C57.3 420.7 16.5 239.2 16 140c-.1-26.2 16.3-47.9 38.3-57.2L242.7 2.9C246.8 1 251.4 0 256 0zm0 66.8V444.8C394 378 431.1 230.1 432 141.4L256 66.8z'/%3E%3C/svg%3E">

    <!-- Fonts & Icons -->
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;500;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    
    <style>
        :root {
            --bg: #030303; --surface: #0e0e11; --primary: #6366f1; --border: #222226;
            --text: #ffffff; --text-muted: #71717a; --success: #10b981; --danger: #ef4444; --warning: #f59e0b;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; outline: none; }
        body { background: var(--bg); color: var(--text); min-height: 100vh; overflow-x: hidden; padding-bottom: 20px; }
        
        /* Modern Glass Effect */
        .glass { background: var(--surface); border: 1px solid var(--border); backdrop-filter: blur(10px); }

        .container { max-width: 1140px; margin: 0 auto; padding: 20px; }

        header { padding: 40px 0; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); margin-bottom: 30px; }
        .logo { display: flex; align-items: center; gap: 15px; }
        .logo i { font-size: 2.2rem; color: var(--primary); }
        .logo-text h1 { font-weight: 800; font-size: 1.4rem; letter-spacing: -0.5px; }
        .v-badge { font-size: 0.6rem; color: #a1a1aa; padding: 3px 8px; border-radius: 6px; border: 1px solid var(--border); text-transform: uppercase; letter-spacing: 1px; }

        /* Dashboard Components */
        .hero-layout { display: grid; grid-template-columns: 1.5fr 1fr; gap: 20px; margin-bottom: 25px; }
        
        .ip-box { padding: 40px; border-radius: 28px; position: relative; overflow: hidden; display: flex; flex-direction: column; justify-content: center; }
        .ip-sub { color: var(--text-muted); font-size: 0.7rem; font-weight: 800; letter-spacing: 3px; margin-bottom: 5px; text-transform: uppercase; }
        .main-address { font-size: clamp(2rem, 6vw, 3.8rem); font-weight: 800; letter-spacing: -2px; margin: 10px 0 25px 0; font-family: monospace; word-break: break-all; }
        
        .trust-score { border-radius: 28px; padding: 40px; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; }
        .gauge { 
            width: 140px; height: 140px; border-radius: 50%; border: 10px solid #1a1a1f; border-top: 10px solid var(--primary);
            display: flex; align-items: center; justify-content: center; position: relative; margin-bottom: 20px;
            transition: all 0.8s ease; 
        }
        .gauge-text { font-size: 2.8rem; font-weight: 800; }

        .bento-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { padding: 25px; border-radius: 24px; transition: 0.3s; border: 1px solid var(--border); }
        .card:hover { border-color: var(--primary); transform: translateY(-3px); }
        .card-header { color: var(--text-muted); font-size: 0.75rem; font-weight: 800; text-transform: uppercase; margin-bottom: 20px; display: flex; align-items: center; gap: 8px; }
        .card-header i { color: var(--primary); }

        .row { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid rgba(255,255,255,0.02); }
        .row:last-child { border: none; }
        .label { color: var(--text-muted); font-size: 0.8rem; }
        .value { font-weight: 600; font-size: 0.8rem; color: #f4f4f5; text-align: right; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 60%; }

        .terminal { 
            background: #000; border: 1px solid var(--border); padding: 18px; font-family: monospace; font-size: 0.7rem; 
            border-radius: 20px; color: var(--success); height: 180px; overflow-y: auto; margin-top: 25px;
        }
        .term-entry { margin-bottom: 6px; }
        .term-entry .timestamp { color: var(--text-muted); margin-right: 10px; }

        .btn { 
            padding: 10px 18px; border-radius: 10px; border: 1px solid var(--border); font-size: 0.75rem; 
            font-weight: 700; background: transparent; color: #fff; cursor: pointer; transition: 0.2s; 
            display: inline-flex; align-items: center; gap: 8px; text-decoration: none;
        }
        .btn:hover { background: var(--primary); border-color: var(--primary); }

        .dot { height: 7px; width: 7px; background-color: var(--success); border-radius: 50%; display: inline-block; margin-right: 5px; animation: blink 1.5s infinite; }
        @keyframes blink { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }

        footer { text-align: center; padding: 50px 0; border-top: 1px solid var(--border); margin-top: 60px; color: var(--text-muted); }
        .socials { display: flex; justify-content: center; gap: 20px; margin-bottom: 15px; font-size: 1.3rem; }
        .socials a { color: var(--text-muted); transition: 0.3s; }
        .socials a:hover { color: #fff; transform: translateY(-3px); }

        @media (max-width: 800px) {
            .hero-layout { grid-template-columns: 1fr; }
            header { flex-direction: column; gap: 20px; text-align: center; }
        }
    </style>
</head>
<body>

    <div class="container">
        <header>
            <div class="logo">
                <i class="fas fa-shield-virus"></i>
                <div class="logo-text">
                    <h1>IP Security Analyzer</h1>
                    <span class="v-badge">Ver 1.0</span>
                </div>
            </div>
            <div style="display: flex; gap: 10px;">
                <div class="btn"><span class="dot"></span> DC: ${metadata.colo}</div>
                <div class="btn">Ray: ${rayId.split('-')[0].toUpperCase()}</div>
            </div>
        </header>

        <main>
            <section class="hero-layout">
                <div class="ip-box glass">
                    <span class="ip-sub">Forensic Node Identified</span>
                    <h2 class="main-address">${metadata.ip}</h2>
                    <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                        <button class="btn" onclick="navigator.clipboard.writeText('${metadata.ip}'); alert('Copied!')"><i class="fas fa-copy"></i> Copy IP</button>
                        <a href="/json" target="_blank" class="btn"><i class="fas fa-terminal"></i> Debug JSON</a>
                    </div>
                </div>

                <div class="trust-score glass">
                    <div class="gauge" id="scoreGauge">
                        <span class="gauge-text" id="scoreText">--</span>
                    </div>
                    <p id="scoreLabel" style="font-weight: 800; font-size: 1rem; color: var(--primary)">Security Audit...</p>
                </div>
            </section>

            <div class="bento-grid">
                <!-- GEO Intelligence -->
                <div class="card glass">
                    <div class="card-header"><i class="fas fa-earth-americas"></i> Geo Intelligence</div>
                    <div class="row"><span class="label">Physical Country</span><span class="value">${metadata.country}</span></div>
                    <div class="row"><span class="label">City & State</span><span class="value">${metadata.city}, ${metadata.region}</span></div>
                    <div class="row"><span class="label">Coordinate Reference</span><span class="value">${metadata.lat}, ${metadata.lon}</span></div>
                    <div class="row"><span class="label">Network Protocol</span><span class="value">${metadata.type} / ${metadata.httpProtocol}</span></div>
                </div>

                <!-- Network Engine -->
                <div class="card glass">
                    <div class="card-header"><i class="fas fa-microchip"></i> ISP Core Identity</div>
                    <div class="row"><span class="label">Organization</span><span class="value">${metadata.isp}</span></div>
                    <div class="row"><span class="label">Autonomous System</span><span class="value">AS${metadata.asn}</span></div>
                    <div class="row"><span class="label">Infrastructure Type</span><span class="value" style="color:var(--primary); font-weight:800;">${metadata.connectionType}</span></div>
                    <div class="row"><span class="label">Timezone Pivot</span><span class="value">${metadata.timezone}</span></div>
                </div>

                <!-- Forensic Shield -->
                <div class="card glass">
                    <div class="card-header"><i class="fas fa-user-secret"></i> Shield Detection</div>
                    <div class="row"><span class="label">Proxy / Tunnel Detected</span><span class="value" id="isDC">Scanning...</span></div>
                    <div class="row"><span class="label">WebRTC Identity Leak</span><span class="value" id="isLeak">Scanning...</span></div>
                    <div class="row"><span class="label">Browser Fingerprint</span><span class="value" id="uaScore">Checking...</span></div>
                    <div class="row"><span class="label">Server Gateway</span><span class="value">${metadata.colo} Center</span></div>
                </div>
            </div>

            <!-- Forensic Log Output -->
            <div class="terminal" id="termOutput">
                <div class="term-entry"><span class="timestamp">[12:00:00]</span> SYSTEM: Network forensic engine v1.0 starting...</div>
                <div class="term-entry"><span class="timestamp">[12:00:00]</span> SCANNER: Fetching metadata for IP ${metadata.ip}</div>
            </div>
        </main>

        <footer>
            <div class="socials">
                <a href="https://github.com/TheGreatAzizi/IP-Security-Analyzer-Cloudflare-Worker" target="_blank"><i class="fab fa-github"></i></a>
                <a href="https://x.com/the_azzi" target="_blank"><i class="fab fa-x-twitter"></i></a>
            </div>
            <p>© 2026 &bull; Dev by <span style="color: #fff; font-weight: 800">TheGreatAzizi</span></p>
        </footer>
    </div>

    <script>
        const info = ${JSON.stringify(metadata)};
        let finalScore = 100;

        function postLog(msg, color) {
            const out = document.getElementById('termOutput');
            const e = document.createElement('div');
            e.className = 'term-entry';
            if(color) e.style.color = color;
            e.innerHTML = \`<span class="timestamp">[\${new Date().toLocaleTimeString()}]</span> SCANNER: \${msg}\`;
            out.appendChild(e);
            out.scrollTop = out.scrollHeight;
        }

        async function audit() {
            postLog('Analyzing Autonomous System structure...');

            // Hosting / Datacenter Validation
            const type = info.connectionType;
            if(type.includes('Hosting')) {
                finalScore -= 45;
                document.getElementById('isDC').innerText = 'IDENTIFIED (HOST)';
                document.getElementById('isDC').style.color = 'var(--danger)';
                postLog('SECURITY: Potential Anonymization via Proxy detected.', 'var(--danger)');
            } else {
                document.getElementById('isDC').innerText = 'CLEAN';
                document.getElementById('isDC').style.color = 'var(--success)';
                postLog('INTEGRITY: Residential connectivity validated.', 'var(--success)');
            }

            // Fingerprint Risk
            if(/headless|bot|crawl/i.test(navigator.userAgent)) {
                finalScore -= 30;
                document.getElementById('uaScore').innerText = 'HIGH RISK';
                postLog('ALERT: User-Agent resembles an automated crawler!', 'var(--warning)');
            } else {
                document.getElementById('uaScore').innerText = 'STANDARD';
            }

            // Timezone Inconsistency
            const localTZ = Intl.DateTimeFormat().resolvedOptions().timeZone;
            if(localTZ !== info.timezone) {
                finalScore -= 20;
                postLog('ANOMALY: Local timezone mismatch vs IP node.', 'var(--warning)');
            }

            // WebRTC Leak Analysis
            const rtc = document.getElementById('isLeak');
            try {
                const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
                pc.createDataChannel('p');
                pc.onicecandidate = e => { if(e.candidate) { rtc.innerText = 'Visible (Unmasked)'; rtc.style.color = 'var(--warning)'; } };
                pc.createOffer().then(o => pc.setLocalDescription(o));
                setTimeout(() => { 
                    if(rtc.innerText === 'Scanning...') { 
                        rtc.innerText = 'Safe (Secured)'; rtc.style.color = 'var(--success)'; 
                    } 
                }, 2000);
            } catch(e) { rtc.innerText = 'N/A (Disabled)'; }

            updateUI();
        }

        function updateUI() {
            const txt = document.getElementById('scoreText');
            const gauge = document.getElementById('scoreGauge');
            const label = document.getElementById('scoreLabel');

            txt.innerText = finalScore;
            
            if(finalScore >= 80) {
                gauge.style.borderTopColor = 'var(--success)';
                label.innerText = 'Connection Safe';
                label.style.color = 'var(--success)';
            } else if (finalScore >= 50) {
                gauge.style.borderTopColor = 'var(--warning)';
                label.innerText = 'Limited Identity Trust';
                label.style.color = 'var(--warning)';
            } else {
                gauge.style.borderTopColor = 'var(--danger)';
                label.innerText = 'Suspicious Infrastructure';
                label.style.color = 'var(--danger)';
            }
            postLog('Analysis complete. Intelligence Report Generated.');
        }

        window.onload = audit;
    </script>
</body>
</html>`;

    return new Response(html, {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'X-XSS-Protection': '1; mode=block',
        'Cache-Control': 'no-cache'
      }
    });
  }
};
