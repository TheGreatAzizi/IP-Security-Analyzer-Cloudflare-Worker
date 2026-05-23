const MANUAL_IPINFO_TOKEN = "";
const MANUAL_ABUSEIPDB_KEY = "";

const APP_VERSION = "9.0.0-professional-no-datacenter-penalty";

const PROJECT_GITHUB = "https://github.com/TheGreatAzizi/IP-Security-Analyzer-Cloudflare-Worker";
const AUTHOR_X = "https://x.com/the_azzi";
const AUTHOR_TELEGRAM = "https://t.me/luluch_code";

const KNOWN_HOSTING_ASNS = new Set([
  13335, 15169, 16509, 14618, 8075, 14061, 16276, 24940, 20473, 63949,
  31898, 45102, 20940, 54113, 60068, 9009, 62240, 53667, 398101, 396982,
  395747, 396356, 212238, 202425, 199524, 51167, 12876, 24961, 20454,
  36352, 55286, 8100, 40676, 18779, 29802, 46652, 35916, 30083, 30633,
  138997
]);

const HOSTING_WORDS = [
  "hosting", "host", "cloud", "datacenter", "data center", "server", "servers",
  "colo", "colocation", "vps", "dedicated", "compute", "infrastructure",
  "cdn", "edge", "backbone", "bare metal", "iaas", "paas", "saas",
  "amazon", "aws", "google cloud", "google llc", "microsoft", "azure",
  "digitalocean", "hetzner", "ovh", "vultr", "linode", "akamai", "fastly",
  "cloudflare", "oracle", "alibaba", "tencent", "contabo", "leaseweb",
  "m247", "choopa", "datacamp", "gcore", "scaleway", "rackspace",
  "upcloud", "clouvider", "serverius", "hivelocity", "limestone", "psychz",
  "netcup", "ionos", "godaddy", "namecheap", "hostinger", "bluehost",
  "transit", "web hosting", "eons.cloud", "edcl.io"
];

const VPN_PROXY_WORDS = [
  "vpn", "proxy", "privacy", "anonymous", "anonymizer", "tor", "exit",
  "relay", "tunnel", "hide", "masked", "residential proxy", "packetstream",
  "bright data", "luminati", "oxylabs", "netnut", "smartproxy", "iproyal",
  "geosurf", "nordvpn", "expressvpn", "surfshark", "mullvad", "proton",
  "windscribe", "private internet access", "pia", "cyberghost", "purevpn",
  "hola", "zenmate", "hide.me", "hidemyass", "hma", "torguard", "airvpn",
  "ipvanish", "vyprvpn", "privatevpn", "perfect privacy"
];

const MOBILE_WORDS = [
  "mobile", "cellular", "wireless", "lte", "4g", "5g", "telecom",
  "telecommunication", "vodafone", "verizon", "t-mobile", "tmobile",
  "orange", "telefonica", "o2", "mtn", "airtel", "jio", "irancell",
  "mci", "hamrah", "rightel", "cellcom", "tele2", "three"
];

const RESIDENTIAL_WORDS = [
  "comcast", "charter", "spectrum", "cox", "bt", "virgin media", "sky",
  "deutsche telekom", "telekom", "vodafone", "orange", "free sas",
  "telefonica", "att", "at&t", "verizon", "frontier", "centurylink",
  "ziply", "shaw", "rogers", "bell", "telus", "talktalk", "plusnet",
  "xfinity", "fios", "ziggo", "kpn", "proximus"
];

const EDUCATION_WORDS = ["university", "college", "school", "academy", "education", "research", "campus"];
const CORPORATE_WORDS = ["business", "enterprise", "corporation", "corp", "inc", "ltd", "limited", "gmbh", "company", "bank", "finance", "insurance", "communications"];

function nowIso() {
  return new Date().toISOString();
}

function lower(value) {
  return String(value || "").toLowerCase();
}

function hasAny(text, words) {
  const t = lower(text);
  return words.some(function (w) {
    return t.includes(w);
  });
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function escapeHtml(value) {
  return String(value === undefined || value === null ? "" : value).replace(/[&<>'"]/g, function (ch) {
    return {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "'": "&#39;",
      "\"": "&quot;"
    }[ch];
  });
}

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data, null, 2), {
    status: status || 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "content-type",
      "cache-control": "no-store, no-cache, must-revalidate, max-age=0",
      "x-content-type-options": "nosniff"
    }
  });
}

function htmlResponse(body) {
  return new Response(body, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store, no-cache, must-revalidate, max-age=0",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "x-frame-options": "DENY",
      "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    }
  });
}

function getToken(env, key, manualValue) {
  return String((env && env[key]) || manualValue || "").trim();
}

function ipVersion(ip) {
  return String(ip || "").includes(":") ? "IPv6" : "IPv4";
}

function isPrivateOrLocalIp(ip) {
  const v = String(ip || "").trim().toLowerCase();

  if (!v) return false;
  if (v === "localhost" || v.endsWith(".local")) return true;

  const m = v.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);

    return (
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a === 0 ||
      a >= 224
    );
  }

  return (
    v === "::1" ||
    v.startsWith("fc") ||
    v.startsWith("fd") ||
    v.startsWith("fe80:") ||
    v.startsWith("::ffff:10.") ||
    v.startsWith("::ffff:192.168.")
  );
}

function getClientIp(request) {
  const h = request.headers;
  const forwarded = h.get("x-forwarded-for");

  return (
    h.get("cf-connecting-ip") ||
    h.get("true-client-ip") ||
    h.get("x-real-ip") ||
    (forwarded ? forwarded.split(",")[0].trim() : "") ||
    "unknown"
  );
}

function getBaseServerData(request) {
  const cf = request.cf || {};
  const h = request.headers;
  const ip = getClientIp(request);

  return {
    ip: ip,
    ipVersion: ipVersion(ip),

    asn: Number(cf.asn || 0),
    isp: cf.asOrganization || "Unknown",

    country: cf.country || "Unknown",
    region: cf.region || "Unknown",
    city: cf.city || "Unknown",
    timezone: cf.timezone || "Unknown",
    latitude: cf.latitude || null,
    longitude: cf.longitude || null,
    colo: cf.colo || "Unknown",

    tlsVersion: cf.tlsVersion || "Unknown",
    tlsCipher: cf.tlsCipher || "Unknown",
    httpProtocol: cf.httpProtocol || "Unknown",
    rayId: h.get("cf-ray") || "Unknown",

    botScore: cf.botManagement && cf.botManagement.score !== undefined ? cf.botManagement.score : null,
    verifiedBot: cf.botManagement && cf.botManagement.verifiedBot !== undefined ? cf.botManagement.verifiedBot : null,
    staticResource: cf.botManagement && cf.botManagement.staticResource !== undefined ? cf.botManagement.staticResource : null,
    corporateProxy: cf.botManagement && cf.botManagement.corporateProxy !== undefined ? cf.botManagement.corporateProxy : null,
    ja3Hash: cf.botManagement && cf.botManagement.ja3Hash ? cf.botManagement.ja3Hash : null,
    ja4: cf.botManagement && cf.botManagement.ja4 ? cf.botManagement.ja4 : null,

    userAgent: h.get("user-agent") || "",
    acceptLanguage: h.get("accept-language") || "",
    accept: h.get("accept") || "",
    secChUa: h.get("sec-ch-ua") || "",
    secChUaMobile: h.get("sec-ch-ua-mobile") || "",
    secChUaPlatform: h.get("sec-ch-ua-platform") || "",
    secFetchSite: h.get("sec-fetch-site") || "",
    secFetchMode: h.get("sec-fetch-mode") || "",
    secFetchDest: h.get("sec-fetch-dest") || "",
    cfIpcountry: h.get("cf-ipcountry") || "",
    referer: h.get("referer") || ""
  };
}

async function safeFetchJson(url, options, timeoutMs) {
  const controller = new AbortController();
  const timeoutId = setTimeout(function () {
    controller.abort("timeout");
  }, timeoutMs || 3500);

  try {
    const res = await fetch(url, Object.assign({}, options || {}, {
      signal: controller.signal
    }));

    const text = await res.text();

    if (!res.ok) {
      return {
        ok: false,
        status: res.status,
        error: "HTTP " + res.status,
        body: text.slice(0, 600)
      };
    }

    try {
      return {
        ok: true,
        status: res.status,
        data: JSON.parse(text)
      };
    } catch (err) {
      return {
        ok: false,
        status: res.status,
        error: "Invalid JSON response",
        body: text.slice(0, 600)
      };
    }
  } catch (err) {
    return {
      ok: false,
      status: 0,
      error: String(err && err.message ? err.message : err)
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function lookupIpinfoLite(ip, env) {
  const token = getToken(env, "IPINFO_TOKEN", MANUAL_IPINFO_TOKEN);

  if (!token || !ip || ip === "unknown") {
    return {
      enabled: false,
      ok: false,
      error: "IPINFO_TOKEN not configured"
    };
  }

  const url = "https://api.ipinfo.io/lite/" + encodeURIComponent(ip) + "?token=" + encodeURIComponent(token);

  const result = await safeFetchJson(url, {
    headers: {
      "accept": "application/json"
    },
    cf: {
      cacheTtl: 300,
      cacheEverything: true
    }
  }, 3500);

  return Object.assign({ enabled: true }, result);
}

async function lookupAbuseIpdb(ip, env) {
  const key = getToken(env, "ABUSEIPDB_KEY", MANUAL_ABUSEIPDB_KEY);

  if (!key || !ip || ip === "unknown") {
    return {
      enabled: false,
      ok: false,
      error: "ABUSEIPDB_KEY not configured"
    };
  }

  const url =
    "https://api.abuseipdb.com/api/v2/check" +
    "?ipAddress=" + encodeURIComponent(ip) +
    "&maxAgeInDays=90" +
    "&verbose=false";

  const result = await safeFetchJson(url, {
    headers: {
      "accept": "application/json",
      "key": key
    },
    cf: {
      cacheTtl: 300,
      cacheEverything: true
    }
  }, 3500);

  return Object.assign({ enabled: true }, result);
}

function parseIpinfoLite(payload) {
  if (!payload || !payload.ok || !payload.data) return null;

  const d = payload.data;

  return {
    ip: d.ip || "",
    asn: d.asn || "",
    asName: d.as_name || "",
    asDomain: d.as_domain || "",
    countryCode: d.country_code || "",
    country: d.country || "",
    continentCode: d.continent_code || "",
    continent: d.continent || "",
    raw: d
  };
}

function parseAbuseIpdb(payload) {
  if (!payload || !payload.ok || !payload.data || !payload.data.data) return null;

  const d = payload.data.data;

  return {
    ipAddress: d.ipAddress || "",
    isPublic: Boolean(d.isPublic),
    ipVersion: d.ipVersion || null,
    isWhitelisted: Boolean(d.isWhitelisted),
    isTor: Boolean(d.isTor),
    abuseConfidenceScore: Number(d.abuseConfidenceScore || 0),
    totalReports: Number(d.totalReports || 0),
    numDistinctUsers: Number(d.numDistinctUsers || 0),
    lastReportedAt: d.lastReportedAt || null,
    countryCode: d.countryCode || "",
    countryName: d.countryName || "",
    usageType: d.usageType || "",
    isp: d.isp || "",
    domain: d.domain || "",
    hostnames: Array.isArray(d.hostnames) ? d.hostnames : [],
    raw: d
  };
}

function classifyLocal(base, ipinfoLite, abuse) {
  const combinedText = [
    base.isp,
    base.asn,
    ipinfoLite && ipinfoLite.asn,
    ipinfoLite && ipinfoLite.asName,
    ipinfoLite && ipinfoLite.asDomain,
    abuse && abuse.usageType,
    abuse && abuse.isp,
    abuse && abuse.domain,
    abuse && abuse.hostnames ? abuse.hostnames.join(" ") : ""
  ].filter(Boolean).join(" ");

  const asnNumber = Number(base.asn || 0);

  const flags = {
    knownHostingAsn: KNOWN_HOSTING_ASNS.has(asnNumber),
    hostingName: hasAny(combinedText, HOSTING_WORDS),
    vpnProxyName: hasAny(combinedText, VPN_PROXY_WORDS),
    mobileName: hasAny(combinedText, MOBILE_WORDS),
    residentialName: hasAny(combinedText, RESIDENTIAL_WORDS),
    educationName: hasAny(combinedText, EDUCATION_WORDS),
    corporateName: hasAny(combinedText, CORPORATE_WORDS),
    abuseDatacenterUsage: /data center|datacenter|hosting|web hosting|transit|cdn|commercial/i.test((abuse && abuse.usageType) || ""),
    abuseTor: Boolean(abuse && abuse.isTor)
  };

  let type = "Unknown";
  if (flags.abuseTor || flags.vpnProxyName) type = "VPN / Proxy / Tor / Privacy Match";
  else if (flags.abuseDatacenterUsage || flags.knownHostingAsn || flags.hostingName) type = "Hosting / Datacenter";
  else if (flags.mobileName) type = "Mobile / Cellular";
  else if (flags.residentialName) type = "Likely Residential ISP";
  else if (flags.educationName) type = "Education / Campus";
  else if (flags.corporateName) type = "Corporate / Business";

  return {
    type: type,
    flags: flags,
    evidenceText: combinedText
  };
}

function analyzeHeaders(base) {
  const findings = [];
  const ua = base.userAgent || "";

  function add(id, severity, points, message, evidence) {
    findings.push({
      id: id,
      severity: severity,
      points: points,
      message: message,
      evidence: evidence || {}
    });
  }

  if (!ua) {
    add("missing_user_agent", "medium", 20, "User-Agent is missing.");
  }

  if (/(curl|wget|python|requests|httpclient|go-http-client|scrapy|bot|spider|headless|phantom|selenium|playwright|puppeteer|httpx|aiohttp)/i.test(ua)) {
    add("automation_user_agent", "medium", 25, "User-Agent looks automated, headless, or scripted.", {
      userAgent: ua
    });
  }

  const looksLikeBrowser = /mozilla|chrome|safari|firefox|edg|opr|brave/i.test(ua);
  const hasModernFetchHeaders = Boolean(base.secFetchMode || base.secFetchSite || base.secFetchDest);
  const hasClientHints = Boolean(base.secChUa || base.secChUaPlatform);

  if (looksLikeBrowser && !hasModernFetchHeaders && !hasClientHints) {
    add("browser_header_mismatch", "low", 10, "User-Agent looks like a browser but common modern browser headers are missing.");
  }

  if (looksLikeBrowser && !base.acceptLanguage) {
    add("missing_accept_language", "low", 8, "Browser-like request has no Accept-Language header.");
  }

  if (base.tlsVersion && base.tlsVersion !== "Unknown" && !String(base.tlsVersion).includes("1.3")) {
    add("not_tls_13", "low", 6, "Connection is not using TLS 1.3.", {
      tlsVersion: base.tlsVersion
    });
  }

  if (base.botScore !== null && Number(base.botScore) < 30) {
    add("cloudflare_low_bot_score", "high", 35, "Cloudflare Bot Management score is low.", {
      botScore: base.botScore
    });
  }

  if (base.verifiedBot === true) {
    add("cloudflare_verified_bot", "info", 0, "Cloudflare says this is a verified bot.", {
      verifiedBot: true
    });
  }

  if (base.corporateProxy === true) {
    add("cloudflare_corporate_proxy", "medium", 15, "Cloudflare Bot Management indicates corporate proxy.", {
      corporateProxy: true
    });
  }

  return findings;
}

function buildRiskAnalysis(base, local, ipinfoLite, abuse) {
  const findings = [];
  let score = 100;

  function add(f) {
    findings.push(f);
    score -= Number(f.points || 0);
  }

  analyzeHeaders(base).forEach(add);

  if (local.flags.abuseTor || (abuse && abuse.isTor)) {
    add({
      id: "abuseipdb_tor",
      severity: "critical",
      points: 60,
      message: "AbuseIPDB says this IP is Tor.",
      evidence: {
        isTor: abuse ? abuse.isTor : null
      }
    });
  }

  if (local.flags.vpnProxyName) {
    add({
      id: "name_based_vpn_proxy_match",
      severity: "high",
      points: 38,
      message: "Network name/domain contains VPN, proxy, privacy, Tor, tunnel, or relay keywords.",
      evidence: {
        isp: base.isp,
        ipinfoAsName: ipinfoLite ? ipinfoLite.asName : null,
        ipinfoAsDomain: ipinfoLite ? ipinfoLite.asDomain : null,
        abuseUsageType: abuse ? abuse.usageType : null,
        abuseDomain: abuse ? abuse.domain : null
      }
    });
  }

  if (local.flags.abuseDatacenterUsage) {
    add({
      id: "abuseipdb_usage_type_datacenter",
      severity: "info",
      points: 0,
      message: "AbuseIPDB usage type says this IP is Data Center/Web Hosting/Transit. This is infrastructure classification only, not a risk penalty.",
      evidence: {
        usageType: abuse ? abuse.usageType : "",
        isp: abuse ? abuse.isp : "",
        domain: abuse ? abuse.domain : ""
      }
    });
  }

  if (local.flags.knownHostingAsn) {
    add({
      id: "known_hosting_asn",
      severity: "info",
      points: 0,
      message: "ASN is in the built-in hosting/cloud/datacenter ASN list. Hosting ASN alone is not treated as risky.",
      evidence: {
        asn: base.asn
      }
    });
  }

  if (local.flags.hostingName && !local.flags.knownHostingAsn && !local.flags.abuseDatacenterUsage) {
    add({
      id: "name_based_hosting_match",
      severity: "info",
      points: 0,
      message: "Network name/domain looks like hosting, cloud, CDN, transit, or datacenter. This is informational only.",
      evidence: {
        isp: base.isp,
        ipinfoAsName: ipinfoLite ? ipinfoLite.asName : null,
        ipinfoAsDomain: ipinfoLite ? ipinfoLite.asDomain : null,
        abuseUsageType: abuse ? abuse.usageType : null
      }
    });
  }

  if (local.flags.mobileName) {
    add({
      id: "mobile_network",
      severity: "info",
      points: 0,
      message: "Mobile/cellular carrier detected. This is informational only.",
      evidence: {
        isp: base.isp
      }
    });
  }

  if (ipinfoLite) {
    add({
      id: "ipinfo_lite_enrichment",
      severity: "info",
      points: 0,
      message: "IPinfo Lite ASN enrichment: " + (ipinfoLite.asn || "Unknown ASN") + " " + (ipinfoLite.asName || ""),
      evidence: {
        asn: ipinfoLite.asn,
        asName: ipinfoLite.asName,
        asDomain: ipinfoLite.asDomain,
        country: ipinfoLite.country,
        countryCode: ipinfoLite.countryCode
      }
    });
  }

  if (abuse) {
    if (
      local.flags.abuseDatacenterUsage &&
      abuse.abuseConfidenceScore === 0 &&
      abuse.totalReports === 0 &&
      abuse.isTor === false
    ) {
      add({
        id: "clean_datacenter_ip",
        severity: "info",
        points: 0,
        message: "This is a datacenter/hosting IP, but AbuseIPDB reports no abuse, no reports, and not Tor. No risk penalty applied.",
        evidence: {
          usageType: abuse.usageType,
          abuseConfidenceScore: abuse.abuseConfidenceScore,
          totalReports: abuse.totalReports,
          isTor: abuse.isTor
        }
      });
    }

    if (abuse.abuseConfidenceScore >= 80) {
      add({
        id: "abuseipdb_very_high_reputation_risk",
        severity: "critical",
        points: 45,
        message: "AbuseIPDB confidence score is very high.",
        evidence: abuse.raw
      });
    } else if (abuse.abuseConfidenceScore >= 50) {
      add({
        id: "abuseipdb_high_reputation_risk",
        severity: "high",
        points: 30,
        message: "AbuseIPDB confidence score is high.",
        evidence: abuse.raw
      });
    } else if (abuse.abuseConfidenceScore >= 20) {
      add({
        id: "abuseipdb_medium_reputation_risk",
        severity: "medium",
        points: 16,
        message: "AbuseIPDB confidence score is elevated.",
        evidence: abuse.raw
      });
    }

    if (abuse.totalReports >= 20) {
      add({
        id: "abuseipdb_many_reports",
        severity: "high",
        points: 18,
        message: "This IP has many abuse reports.",
        evidence: {
          totalReports: abuse.totalReports,
          numDistinctUsers: abuse.numDistinctUsers,
          lastReportedAt: abuse.lastReportedAt
        }
      });
    } else if (abuse.totalReports > 0) {
      add({
        id: "abuseipdb_some_reports",
        severity: "low",
        points: 6,
        message: "This IP has some abuse reports.",
        evidence: {
          totalReports: abuse.totalReports,
          numDistinctUsers: abuse.numDistinctUsers,
          lastReportedAt: abuse.lastReportedAt
        }
      });
    }

    if (abuse.isWhitelisted) {
      add({
        id: "abuseipdb_whitelisted",
        severity: "info",
        points: -8,
        message: "AbuseIPDB says this IP is whitelisted.",
        evidence: {
          isWhitelisted: true
        }
      });
    }

    add({
      id: "abuseipdb_enrichment",
      severity: "info",
      points: 0,
      message: "AbuseIPDB: score " + abuse.abuseConfidenceScore + ", reports " + abuse.totalReports + ", usage " + (abuse.usageType || "Unknown") + ".",
      evidence: {
        abuseConfidenceScore: abuse.abuseConfidenceScore,
        totalReports: abuse.totalReports,
        numDistinctUsers: abuse.numDistinctUsers,
        usageType: abuse.usageType,
        isp: abuse.isp,
        domain: abuse.domain,
        isTor: abuse.isTor,
        hostnames: abuse.hostnames
      }
    });
  }

  score = clamp(score, 0, 100);

  let verdict = "Low Risk";
  if (score < 35) verdict = "Critical Risk";
  else if (score < 60) verdict = "High Risk";
  else if (score < 80) verdict = "Medium Risk";

  const tags = [];

  if (local.flags.abuseTor || (abuse && abuse.isTor)) tags.push("Tor");
  if (local.flags.vpnProxyName) tags.push("VPN/Proxy name match");
  if (local.flags.abuseDatacenterUsage || local.flags.knownHostingAsn || local.flags.hostingName) tags.push("Hosting/Datacenter");
  if (local.flags.mobileName) tags.push("Mobile");
  if (local.flags.residentialName) tags.push("Likely Residential");
  if (local.flags.educationName) tags.push("Education");
  if (local.flags.corporateName) tags.push("Corporate");
  if (abuse && abuse.abuseConfidenceScore >= 50) tags.push("Bad Reputation");
  if (!tags.length) tags.push("No strong tag");

  return {
    score: score,
    verdict: verdict,
    tags: tags,
    findings: findings
  };
}

function parseWebrtcReport(serverIp, report) {
  const candidates = Array.isArray(report && report.candidates) ? report.candidates : [];
  const ips = [];

  candidates.forEach(function (c) {
    const ip = String((c && c.ip) || "").trim();
    if (ip && ips.indexOf(ip) === -1) ips.push(ip);
  });

  const privateOrLocal = ips.filter(isPrivateOrLocalIp);
  const mdns = ips.filter(function (ip) {
    return ip.endsWith(".local");
  });
  const publicIps = ips.filter(function (ip) {
    return !isPrivateOrLocalIp(ip) && !ip.endsWith(".local");
  });
  const leakedPublicIps = publicIps.filter(function (ip) {
    return ip !== serverIp;
  });
  const sameAsHttpIp = publicIps.indexOf(serverIp) !== -1;

  const findings = [];
  let scoreImpact = 0;
  let state = "protected_or_blocked";

  if (leakedPublicIps.length > 0) {
    state = "public_ip_leak_detected";
    scoreImpact += 45;
    findings.push({
      id: "webrtc_public_ip_mismatch",
      severity: "critical",
      points: 45,
      message: "WebRTC exposed public IPs different from the HTTP IP seen by Cloudflare.",
      evidence: {
        httpIp: serverIp,
        leakedPublicIps: leakedPublicIps
      }
    });
  } else if (sameAsHttpIp) {
    state = "webrtc_public_ip_matches_http_ip";
    findings.push({
      id: "webrtc_public_ip_same_as_http",
      severity: "info",
      points: 0,
      message: "WebRTC exposed the same public IP as the HTTP connection. No proxy bypass leak detected from this signal.",
      evidence: {
        httpIp: serverIp
      }
    });
  }

  if (privateOrLocal.length > 0) {
    scoreImpact += 10;
    findings.push({
      id: "webrtc_local_ip_or_hostname_exposed",
      severity: "medium",
      points: 10,
      message: "WebRTC exposed local/private IPs or local hostnames.",
      evidence: {
        privateOrLocal: privateOrLocal
      }
    });
  }

  if (mdns.length > 0) {
    findings.push({
      id: "webrtc_mdns_masking",
      severity: "info",
      points: 0,
      message: "Browser used mDNS masking for local candidates.",
      evidence: {
        mdns: mdns
      }
    });
  }

  if (candidates.length === 0) {
    findings.push({
      id: "webrtc_no_candidates",
      severity: "info",
      points: 0,
      message: "No WebRTC candidates were exposed. WebRTC may be disabled, blocked, or protected by browser/VPN.",
      evidence: {}
    });
  }

  return {
    state: state,
    leakDetected: leakedPublicIps.length > 0 || privateOrLocal.length > 0,
    httpIp: serverIp,
    candidateCount: candidates.length,
    ips: ips,
    publicIps: publicIps,
    privateOrLocal: privateOrLocal,
    mdns: mdns,
    leakedPublicIps: leakedPublicIps,
    sameAsHttpIp: sameAsHttpIp,
    scoreImpact: scoreImpact,
    findings: findings,
    candidates: candidates
  };
}

async function buildFullAnalysis(request, env) {
  const base = getBaseServerData(request);

  const results = await Promise.all([
    lookupIpinfoLite(base.ip, env),
    lookupAbuseIpdb(base.ip, env)
  ]);

  const ipinfoRaw = results[0];
  const abuseRaw = results[1];

  const ipinfoLite = parseIpinfoLite(ipinfoRaw);
  const abuse = parseAbuseIpdb(abuseRaw);
  const local = classifyLocal(base, ipinfoLite, abuse);
  const risk = buildRiskAnalysis(base, local, ipinfoLite, abuse);

  return {
    status: "success",
    version: APP_VERSION,
    generatedAt: nowIso(),

    ip: {
      address: base.ip,
      version: base.ipVersion
    },

    network: {
      asn: base.asn,
      isp: base.isp,
      localClassification: local
    },

    location: {
      country: (ipinfoLite && ipinfoLite.country) || base.country,
      countryCode: (ipinfoLite && ipinfoLite.countryCode) || base.country,
      region: base.region,
      city: base.city,
      timezone: base.timezone,
      latitude: base.latitude,
      longitude: base.longitude,
      colo: base.colo,
      continent: (ipinfoLite && ipinfoLite.continent) || "",
      continentCode: (ipinfoLite && ipinfoLite.continentCode) || ""
    },

    connection: {
      tlsVersion: base.tlsVersion,
      tlsCipher: base.tlsCipher,
      httpProtocol: base.httpProtocol,
      rayId: base.rayId,
      userAgent: base.userAgent,
      acceptLanguage: base.acceptLanguage,
      accept: base.accept,
      secChUa: base.secChUa,
      secChUaMobile: base.secChUaMobile,
      secChUaPlatform: base.secChUaPlatform,
      secFetchSite: base.secFetchSite,
      secFetchMode: base.secFetchMode,
      secFetchDest: base.secFetchDest,
      ja3Hash: base.ja3Hash,
      ja4: base.ja4,
      referer: base.referer
    },

    cloudflareSignals: {
      botScore: base.botScore,
      verifiedBot: base.verifiedBot,
      staticResource: base.staticResource,
      corporateProxy: base.corporateProxy
    },

    externalIntel: {
      ipinfoLite: {
        enabled: Boolean(getToken(env, "IPINFO_TOKEN", MANUAL_IPINFO_TOKEN)),
        ok: Boolean(ipinfoRaw.ok),
        parsed: ipinfoLite,
        raw: ipinfoRaw.ok ? ipinfoRaw.data : null,
        error: ipinfoRaw.ok ? null : ipinfoRaw.error,
        attribution: "IP address data powered by IPinfo Lite"
      },
      abuseipdb: {
        enabled: Boolean(getToken(env, "ABUSEIPDB_KEY", MANUAL_ABUSEIPDB_KEY)),
        ok: Boolean(abuseRaw.ok),
        parsed: abuse,
        raw: abuseRaw.ok ? abuseRaw.data : null,
        error: abuseRaw.ok ? null : abuseRaw.error
      }
    },

    risk: risk,

    limitations: {
      datacenterPolicy: "Datacenter/hosting classification is informational only. It does not reduce score by itself.",
      ipinfoLite: "IPinfo Lite does not provide direct is_vpn/is_proxy/is_tor/is_hosting fields. This Worker uses Lite ASN/name/domain enrichment plus heuristics.",
      abuseipdb: "AbuseIPDB is used for reputation, Tor flag, reports, and usageType. UsageType alone does not reduce score.",
      realIpBehindVpn: "No website can reliably know the real ISP IP behind a properly configured VPN unless the browser leaks it through WebRTC or another client-side channel.",
      dnsLeak: "A normal Cloudflare Worker cannot see the visitor DNS resolver. Real DNS leak detection needs authoritative DNS logging for unique test subdomains."
    }
  };
}

async function handleReport(request, env) {
  const analysis = await buildFullAnalysis(request, env);

  let report = {};
  try {
    report = await request.json();
  } catch (err) {
    return jsonResponse({
      status: "error",
      error: "Invalid JSON body"
    }, 400);
  }

  const webrtc = parseWebrtcReport(analysis.ip.address, report);
  const combinedScore = clamp(analysis.risk.score - webrtc.scoreImpact, 0, 100);

  let verdict = "Low Risk";
  if (combinedScore < 35) verdict = "Critical Risk";
  else if (combinedScore < 60) verdict = "High Risk";
  else if (combinedScore < 80) verdict = "Medium Risk";

  return jsonResponse(Object.assign({}, analysis, {
    browserLeakTest: webrtc,
    combinedRisk: {
      score: combinedScore,
      verdict: verdict,
      findings: analysis.risk.findings.concat(webrtc.findings)
    }
  }));
}

function scoreClass(score) {
  if (score >= 80) return "good";
  if (score >= 60) return "mid";
  if (score >= 35) return "high";
  return "critical";
}

function shortVerdict(score) {
  if (score >= 80) return "Clean / Low Risk";
  if (score >= 60) return "Watch / Medium Risk";
  if (score >= 35) return "Risky / High Risk";
  return "Critical";
}

function severityTitle(severity) {
  const s = String(severity || "info").toLowerCase();
  if (s === "critical") return "Critical";
  if (s === "high") return "High";
  if (s === "medium") return "Medium";
  if (s === "low") return "Low";
  return "Info";
}

function renderFinding(f) {
  const points = Number(f.points || 0);
  const pointText = points > 0 ? "-" + points : "+" + Math.abs(points);

  return ""
    + "<article class=\"finding " + escapeHtml(f.severity) + "\">"
    + "  <div class=\"finding-head\">"
    + "    <span class=\"sev\">" + escapeHtml(severityTitle(f.severity)) + "</span>"
    + "    <code>" + escapeHtml(f.id) + "</code>"
    + "    <strong>" + escapeHtml(pointText) + "</strong>"
    + "  </div>"
    + "  <p>" + escapeHtml(f.message) + "</p>"
    + "</article>";
}

function renderPage(analysis) {
  const risk = analysis.risk;
  const ip = analysis.ip.address;
  const tags = risk.tags && risk.tags.length ? risk.tags : ["No strong tag"];
  const ipinfo = analysis.externalIntel.ipinfoLite;
  const abuse = analysis.externalIntel.abuseipdb;
  const abuseParsed = abuse.parsed || {};
  const ipinfoParsed = ipinfo.parsed || {};
  const rawJson = escapeHtml(JSON.stringify(analysis, null, 2));

  const findingsHtml = risk.findings.length
    ? risk.findings.map(renderFinding).join("")
    : "<p class=\"green\">No strong server-side risk indicators found.</p>";

  const tagHtml = tags.map(function (t) {
    return "<span class=\"tag\">" + escapeHtml(t) + "</span>";
  }).join("");

  const hostnames = abuseParsed.hostnames && abuseParsed.hostnames.length
    ? abuseParsed.hostnames.join(", ")
    : "No hostnames";

  const abuseStatus = abuse.enabled
    ? (abuse.ok ? "Connected" : "Error")
    : "Off";

  const ipinfoStatus = ipinfo.enabled
    ? (ipinfo.ok ? "Connected" : "Error")
    : "Off";

  const scoreCls = scoreClass(risk.score);
  const externalOkCount = (ipinfo.ok ? 1 : 0) + (abuse.ok ? 1 : 0);
  const signalCount = risk.findings ? risk.findings.length : 0;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP Security Analyzer</title>
<meta name="description" content="Cloudflare Worker based IP security analyzer with IPinfo Lite, AbuseIPDB and WebRTC leak testing.">
<style>
:root {
  color-scheme: dark;
  --bg: #08111f;
  --panel: #0f172a;
  --panel2: #111c31;
  --line: #233047;
  --text: #e5edf8;
  --muted: #8da0ba;
  --soft: #c7d4e8;
  --blue: #4f8cff;
  --green: #2dd4bf;
  --yellow: #fbbf24;
  --orange: #fb923c;
  --red: #f87171;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
}
a { color: #9cc4ff; text-decoration: none; }
a:hover { color: #cfe0ff; }
main {
  max-width: 1160px;
  margin: auto;
  padding: 20px 14px 32px;
}
.nav {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  margin-bottom: 14px;
  padding: 12px 14px;
  border: 1px solid var(--line);
  border-radius: 18px;
  background: #0b1424;
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 900;
}
.logo {
  width: 32px;
  height: 32px;
  display: grid;
  place-items: center;
  border-radius: 10px;
  background: var(--blue);
  color: white;
  font-size: 13px;
}
.nav-links {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
}
.nav-links a, .btn, button {
  border: 1px solid var(--line);
  border-radius: 12px;
  background: #101b2f;
  color: white;
  font-weight: 750;
  padding: 9px 12px;
  cursor: pointer;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.btn.primary, button.primary {
  border-color: #3169d8;
  background: #2563eb;
}
button:disabled { opacity: .62; cursor: not-allowed; }

.hero {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 280px;
  gap: 14px;
  align-items: stretch;
  margin-bottom: 14px;
}
.hero-panel, .score-card, .card, .explain, .footer {
  border: 1px solid var(--line);
  background: var(--panel);
}
.hero-panel {
  border-radius: 22px;
  padding: 22px;
}
.eyebrow {
  display: inline-flex;
  gap: 8px;
  align-items: center;
  color: #bfdbfe;
  background: #10213a;
  border: 1px solid #223b60;
  padding: 7px 10px;
  border-radius: 999px;
  font-weight: 750;
  font-size: 12px;
  margin-bottom: 12px;
}
h1 {
  margin: 0 0 10px;
  font-size: clamp(32px, 5vw, 56px);
  line-height: .95;
  letter-spacing: -.045em;
}
.sub {
  max-width: 780px;
  margin: 0;
  color: var(--muted);
  line-height: 1.65;
  font-size: 15px;
}
.ip-display {
  margin: 18px 0 12px;
  font-size: clamp(30px, 5.5vw, 58px);
  font-weight: 900;
  letter-spacing: -.045em;
  word-break: break-all;
}
.row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
}
.pill, .tag, .mini {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 7px 10px;
  border-radius: 999px;
  background: #0a1220;
  border: 1px solid var(--line);
  color: var(--soft);
  font-size: 13px;
}
.tag {
  background: #10213a;
  border-color: #243b5f;
}
.mini { padding: 5px 8px; font-size: 12px; }
.score-card {
  border-radius: 22px;
  padding: 18px;
  display: grid;
  place-items: center;
}
.score-wrap {
  display: grid;
  place-items: center;
  gap: 12px;
  text-align: center;
}
.score {
  --ring: var(--green);
  width: 132px;
  height: 132px;
  border-radius: 999px;
  display: grid;
  place-items: center;
  font-size: 38px;
  font-weight: 900;
  background:
    radial-gradient(circle, var(--panel) 58%, transparent 60%),
    conic-gradient(var(--ring) calc(var(--score) * 1%), #27364f 0);
}
.score.good { --ring: var(--green); }
.score.mid { --ring: var(--yellow); }
.score.high { --ring: var(--orange); }
.score.critical { --ring: var(--red); }
.verdict {
  font-size: 20px;
  font-weight: 900;
  letter-spacing: -.025em;
}
.muted { color: var(--muted); }
.small { font-size: 13px; }
.grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 12px;
}
.card {
  grid-column: span 4;
  border-radius: 18px;
  padding: 16px;
  overflow: hidden;
}
.wide { grid-column: span 8; }
.full { grid-column: 1 / -1; }
@media (max-width: 900px) {
  .hero { grid-template-columns: 1fr; }
  .card, .wide { grid-column: 1 / -1; }
  .nav { align-items: flex-start; flex-direction: column; }
  .nav-links { justify-content: flex-start; }
}
.label {
  color: var(--muted);
  font-size: 13px;
  margin-bottom: 9px;
}
.big {
  font-size: 21px;
  font-weight: 850;
  word-break: break-word;
}
.metric {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 12px;
  padding: 10px 0;
  border-top: 1px solid var(--line);
}
.metric:first-of-type { border-top: 0; }
.metric span { color: var(--muted); }
.metric strong { text-align: right; word-break: break-word; }
.finding {
  padding: 14px 0;
  border-top: 1px solid var(--line);
}
.finding:first-child { border-top: 0; }
.finding-head {
  display: flex;
  align-items: center;
  gap: 9px;
  flex-wrap: wrap;
}
.finding .sev {
  font-size: 12px;
  font-weight: 850;
  border-radius: 999px;
  padding: 4px 8px;
  background: #0a1220;
  border: 1px solid var(--line);
}
.finding code {
  color: var(--soft);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px;
}
.finding strong {
  margin-left: auto;
  color: var(--muted);
}
.finding p { margin: 9px 0 0; color: var(--text); line-height: 1.55; }
.finding.critical .sev, .finding.high .sev { color: #fecaca; border-color: #7f1d1d; }
.finding.medium .sev { color: #fde68a; border-color: #713f12; }
.finding.low .sev, .finding.info .sev { color: #bae6fd; border-color: #164e63; }
pre, .statusbox {
  white-space: pre-wrap;
  overflow: auto;
  background: #07101d;
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 12px;
  color: #cbd5e1;
  max-height: 520px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px;
}
.statusbox { min-height: 116px; }
.green { color: var(--green); }
.section-title {
  grid-column: 1 / -1;
  margin: 18px 0 0;
  font-size: 24px;
  font-weight: 900;
  letter-spacing: -.035em;
}
.explain {
  grid-column: span 6;
  border-radius: 18px;
  padding: 16px;
}
.explain h3 {
  margin: 0 0 8px;
  font-size: 17px;
}
.explain p {
  margin: 0;
  color: var(--muted);
  line-height: 1.65;
}
@media (max-width: 850px) {
  .explain { grid-column: 1 / -1; }
}
.footer {
  margin-top: 14px;
  border-radius: 18px;
  padding: 16px;
  display: flex;
  gap: 14px;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
}
.footer-links {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.footer-links a {
  border: 1px solid var(--line);
  padding: 8px 11px;
  border-radius: 999px;
  background: #101b2f;
}
</style>
</head>
<body>
<main>
  <nav class="nav">
    <div class="brand">
      <span class="logo">IP</span>
      <span>Security Analyzer</span>
    </div>
    <div class="nav-links">
      <a href="/json">JSON API</a>
      <a href="/health">Health</a>
      <a href="#how-it-works">How it works</a>
      <a href="${escapeHtml(PROJECT_GITHUB)}" target="_blank" rel="noopener">GitHub</a>
    </div>
  </nav>

  <section class="hero">
    <div class="hero-panel">
      <span class="eyebrow">Lightweight Cloudflare Worker</span>
      <h1>IP Security Analyzer</h1>
      <p class="sub">
        A privacy-aware IP intelligence dashboard that evaluates the public network path, reputation signals, browser exposure, and connection consistency without treating datacenter usage as risk by itself.
      </p>

      <div class="ip-display">${escapeHtml(ip)}</div>

      <div class="row">
        <span class="pill">${escapeHtml(analysis.ip.version)}</span>
        <span class="pill">AS${escapeHtml(analysis.network.asn)}</span>
        <span class="pill">${escapeHtml(analysis.location.countryCode || analysis.location.country)}</span>
        <span class="pill">${escapeHtml(analysis.connection.httpProtocol)}</span>
        <span class="pill">${escapeHtml(analysis.connection.tlsVersion)}</span>
      </div>

      <p class="row" style="margin-top:18px">
        <button class="primary" onclick="navigator.clipboard.writeText('${escapeHtml(ip)}')">Copy IP</button>
        <button id="runWebrtc">Run WebRTC Leak Test</button>
      </p>
    </div>

    <aside class="score-card">
      <div class="score-wrap">
        <div class="score ${scoreCls}" style="--score:${escapeHtml(risk.score)}">${escapeHtml(risk.score)}</div>
        <div>
          <div class="verdict">${escapeHtml(shortVerdict(risk.score))}</div>
          <p class="muted small">Datacenter/hosting is informational only and does not reduce the score by itself.</p>
        </div>
        <div class="row" style="justify-content:center">${tagHtml}</div>
      </div>
    </aside>
  </section>

  <section class="grid">
    <div class="card">
      <div class="label">Network Identity</div>
      <div class="big">${escapeHtml(analysis.network.isp)}</div>
      <p class="muted small">${escapeHtml(analysis.network.localClassification.type)}</p>
      <div class="metric"><span>ASN</span><strong>AS${escapeHtml(analysis.network.asn)}</strong></div>
      <div class="metric"><span>City</span><strong>${escapeHtml(analysis.location.city || "Unknown")}</strong></div>
      <div class="metric"><span>Cloudflare Edge</span><strong>${escapeHtml(analysis.location.colo)}</strong></div>
    </div>

    <div class="card">
      <div class="label">IPinfo Lite</div>
      <div class="metric"><span>Status</span><strong>${escapeHtml(ipinfoStatus)}</strong></div>
      <div class="metric"><span>ASN</span><strong>${escapeHtml(ipinfoParsed.asn || "N/A")}</strong></div>
      <div class="metric"><span>AS Name</span><strong>${escapeHtml(ipinfoParsed.asName || "N/A")}</strong></div>
      <div class="metric"><span>Domain</span><strong>${escapeHtml(ipinfoParsed.asDomain || "N/A")}</strong></div>
      <div class="metric"><span>Country</span><strong>${escapeHtml(ipinfoParsed.country || analysis.location.country || "N/A")}</strong></div>
    </div>

    <div class="card">
      <div class="label">AbuseIPDB</div>
      <div class="metric"><span>Status</span><strong>${escapeHtml(abuseStatus)}</strong></div>
      <div class="metric"><span>Abuse Score</span><strong>${escapeHtml(abuseParsed.abuseConfidenceScore ?? "N/A")}</strong></div>
      <div class="metric"><span>Reports</span><strong>${escapeHtml(abuseParsed.totalReports ?? "N/A")}</strong></div>
      <div class="metric"><span>Distinct Users</span><strong>${escapeHtml(abuseParsed.numDistinctUsers ?? "N/A")}</strong></div>
      <div class="metric"><span>Tor</span><strong>${escapeHtml(abuseParsed.isTor === true ? "Yes" : abuseParsed.isTor === false ? "No" : "N/A")}</strong></div>
    </div>

    <div class="card wide">
      <div class="label">Network Details</div>
      <div class="metric"><span>Usage Type</span><strong>${escapeHtml(abuseParsed.usageType || "N/A")}</strong></div>
      <div class="metric"><span>AbuseIPDB ISP</span><strong>${escapeHtml(abuseParsed.isp || "N/A")}</strong></div>
      <div class="metric"><span>Domain</span><strong>${escapeHtml(abuseParsed.domain || "N/A")}</strong></div>
      <div class="metric"><span>Hostnames</span><strong>${escapeHtml(hostnames)}</strong></div>
      <div class="metric"><span>Last Reported</span><strong>${escapeHtml(abuseParsed.lastReportedAt || "Never")}</strong></div>
    </div>

    <div class="card">
      <div class="label">Connection Fingerprint</div>
      <div class="metric"><span>Protocol</span><strong>${escapeHtml(analysis.connection.httpProtocol)}</strong></div>
      <div class="metric"><span>TLS</span><strong>${escapeHtml(analysis.connection.tlsVersion)}</strong></div>
      <div class="metric"><span>Ray ID</span><strong>${escapeHtml(analysis.connection.rayId)}</strong></div>
      <div class="metric"><span>Bot Score</span><strong>${escapeHtml(analysis.cloudflareSignals.botScore ?? "N/A")}</strong></div>
      <div class="metric"><span>Verified Bot</span><strong>${escapeHtml(analysis.cloudflareSignals.verifiedBot === true ? "Yes" : analysis.cloudflareSignals.verifiedBot === false ? "No" : "N/A")}</strong></div>
    </div>

    <div class="card full">
      <div class="label">Server-side Findings</div>
      ${findingsHtml}
    </div>

    <div class="card full">
      <div class="label">WebRTC Leak Test</div>
      <div id="webrtcResult" class="statusbox">WebRTC test has not been run yet. Use the test button to collect browser ICE candidates and compare them with the HTTP IP.</div>
    </div>

    <h2 id="how-it-works" class="section-title">Technical Methodology</h2>

    <div class="explain">
      <h3>Purpose of the analysis</h3>
      <p>The dashboard evaluates the public network identity that reaches the service. It does not try to guess hidden private information; it correlates observable signals such as ASN ownership, abuse reputation, request consistency, and optional browser-side WebRTC exposure.</p>
    </div>

    <div class="explain">
      <h3>Network identity layer</h3>
      <p>The first layer identifies the visible IP address, IP version, ASN, network organization, country, region, city, Cloudflare edge location, HTTP protocol, and TLS version. These fields describe the route and network presenting the request to the application.</p>
    </div>

    <div class="explain">
      <h3>ASN and organization classification</h3>
      <p>The classifier groups networks into categories such as hosting/datacenter, mobile carrier, corporate network, education network, residential-like ISP, or VPN/proxy-like naming. This classification is used as context. Hosting, CDN, cloud, and transit networks are not penalized unless stronger risk evidence exists.</p>
    </div>

    <div class="explain">
      <h3>Reputation correlation</h3>
      <p>Abuse reputation is evaluated through confidence score, report count, number of reporting users, Tor indication, last reported time, ISP, domain, usage type, and hostnames. Reputation score and report volume are weighted because they represent historical abuse evidence rather than simple network type.</p>
    </div>

    <div class="explain">
      <h3>IP enrichment context</h3>
      <p>ASN enrichment provides the AS number, AS name, AS domain, country, and continent. This improves attribution and makes the network identity easier to interpret. It is not treated as direct proof of VPN, proxy, or malicious behavior.</p>
    </div>

    <div class="explain">
      <h3>Request consistency checks</h3>
      <p>The Worker checks whether the request looks consistent with a normal browser session. It reviews User-Agent presence, known automation clients, Accept-Language, browser client hints, fetch metadata headers, TLS version, and optional Cloudflare Bot Management signals when available.</p>
    </div>

    <div class="explain">
      <h3>Risk scoring logic</h3>
      <p>The score starts at 100 and decreases only when meaningful risk indicators are present: Tor status, elevated abuse confidence, abuse reports, VPN/proxy/privacy keywords, suspicious automation headers, low bot score, or browser-side leak findings. Datacenter classification alone remains informational.</p>
    </div>

    <div class="explain">
      <h3>WebRTC exposure test</h3>
      <p>The browser test creates a temporary peer connection and collects ICE candidates. If a public candidate IP differs from the HTTP IP observed by the Worker, it is reported as a possible browser-side exposure or proxy bypass signal. Local, private, and mDNS candidates are shown separately.</p>
    </div>

    <div class="explain">
      <h3>Signal interpretation</h3>
      <p>The dashboard separates classification from risk. A clean datacenter IP with no abuse reports remains low risk, while a residential-looking IP can still become risky if it has abuse history, Tor status, automation indicators, or WebRTC mismatch evidence.</p>
    </div>

    <div class="explain">
      <h3>Known limitations</h3>
      <p>The service can only analyze signals visible to the website and browser. A properly configured VPN or proxy may hide the original ISP IP completely. DNS resolver leaks cannot be confirmed by a standard Worker without authoritative DNS logging for unique test domains.</p>
    </div>

    <div class="card full">
      <div class="label">Raw JSON</div>
      <pre>${rawJson}</pre>
    </div>
  </section>

  <footer class="footer">
    <div>
      <strong>IP Security Analyzer</strong>
      <div class="muted small">Transparent IP intelligence and browser exposure analysis. IP address data powered by <a href="https://ipinfo.io" target="_blank" rel="noopener">IPinfo Lite</a>.</div>
    </div>
    <div class="footer-links">
      <a href="${escapeHtml(PROJECT_GITHUB)}" target="_blank" rel="noopener">GitHub</a>
      <a href="${escapeHtml(AUTHOR_X)}" target="_blank" rel="noopener">X / Twitter</a>
      <a href="${escapeHtml(AUTHOR_TELEGRAM)}" target="_blank" rel="noopener">Telegram</a>
    </div>
  </footer>
</main>

<script>
const resultEl = document.getElementById("webrtcResult");
const runBtn = document.getElementById("runWebrtc");

function htmlEscape(value) {
  return String(value).replace(/[&<>]/g, function (ch) {
    return { "&":"&amp;", "<":"&lt;", ">":"&gt;" }[ch];
  });
}

function parseCandidateLine(line) {
  const parts = String(line || "").trim().split(/\\s+/);
  if (!parts[0] || !parts[0].startsWith("candidate:")) return null;

  const typIndex = parts.indexOf("typ");

  return {
    raw: line,
    foundation: parts[0].replace("candidate:", ""),
    component: parts[1] || "",
    protocol: parts[2] || "",
    priority: parts[3] || "",
    ip: parts[4] || "",
    port: parts[5] || "",
    type: typIndex >= 0 ? parts[typIndex + 1] : "unknown"
  };
}

function candidatesFromSdp(sdp) {
  return String(sdp || "")
    .split(/\\r?\\n/)
    .filter(function (line) {
      return line.startsWith("a=candidate:");
    })
    .map(function (line) {
      return parseCandidateLine(line.slice(2));
    })
    .filter(Boolean);
}

function uniqueCandidates(list) {
  const seen = new Set();
  const out = [];

  for (const c of list) {
    if (!c || !c.ip) continue;
    const key = [c.ip, c.port, c.protocol, c.type].join("|");
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
  }

  return out;
}

async function gatherCandidates() {
  if (!window.isSecureContext) {
    throw new Error("WebRTC test requires HTTPS or localhost.");
  }

  if (!("RTCPeerConnection" in window)) {
    throw new Error("RTCPeerConnection is not available. WebRTC may be disabled.");
  }

  const found = [];

  const pc = new RTCPeerConnection({
    iceServers: [
      { urls: "stun:stun.l.google.com:19302" },
      { urls: "stun:global.stun.twilio.com:3478" }
    ],
    iceCandidatePoolSize: 1
  });

  pc.createDataChannel("ip-leak-test");

  pc.onicecandidate = function (event) {
    if (event.candidate && event.candidate.candidate) {
      const parsed = parseCandidateLine(event.candidate.candidate);
      if (parsed) {
        found.push(parsed);
        resultEl.textContent =
          "Collecting ICE candidates...\\n" +
          JSON.stringify(uniqueCandidates(found), null, 2);
      }
    }
  };

  pc.onicegatheringstatechange = function () {
    resultEl.textContent =
      "ICE gathering state: " + pc.iceGatheringState + "\\n" +
      JSON.stringify(uniqueCandidates(found), null, 2);
  };

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);

  await new Promise(function (resolve) {
    const timeout = setTimeout(resolve, 5500);

    pc.addEventListener("icegatheringstatechange", function () {
      if (pc.iceGatheringState === "complete") {
        clearTimeout(timeout);
        resolve();
      }
    });
  });

  const sdpCandidates = candidatesFromSdp(pc.localDescription && pc.localDescription.sdp);
  pc.close();

  return uniqueCandidates(found.concat(sdpCandidates));
}

async function runWebrtcTest() {
  runBtn.disabled = true;
  resultEl.textContent = "Starting WebRTC leak test...";

  try {
    const candidates = await gatherCandidates();

    resultEl.textContent =
      "Sending candidates to Worker...\\n" +
      JSON.stringify(candidates, null, 2);

    const res = await fetch("/report", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        candidates: candidates,
        browser: {
          userAgent: navigator.userAgent,
          language: navigator.language,
          platform: navigator.platform,
          secureContext: window.isSecureContext
        },
        at: new Date().toISOString()
      })
    });

    const data = await res.json();

    const summary = {
      state: data.browserLeakTest.state,
      leakDetected: data.browserLeakTest.leakDetected,
      httpIp: data.browserLeakTest.httpIp,
      publicIps: data.browserLeakTest.publicIps,
      leakedPublicIps: data.browserLeakTest.leakedPublicIps,
      privateOrLocal: data.browserLeakTest.privateOrLocal,
      mdns: data.browserLeakTest.mdns,
      candidateCount: data.browserLeakTest.candidateCount,
      combinedRisk: data.combinedRisk
    };

    resultEl.innerHTML =
      "<pre>" + htmlEscape(JSON.stringify(summary, null, 2)) + "</pre>";
  } catch (err) {
    resultEl.innerHTML =
      "<span style='color:#ef4444;font-weight:900'>WebRTC test failed</span><pre>" +
      htmlEscape(err && err.message ? err.message : String(err)) +
      "</pre>";
  } finally {
    runBtn.disabled = false;
  }
}

runBtn.addEventListener("click", runWebrtcTest);
</script>
</body>
</html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return jsonResponse({ ok: true });
    }

    if (url.pathname === "/health") {
      return jsonResponse({
        ok: true,
        version: APP_VERSION,
        time: nowIso()
      });
    }

    if (url.pathname === "/json" || url.pathname === "/api") {
      return jsonResponse(await buildFullAnalysis(request, env));
    }

    if (url.pathname === "/report" && request.method === "POST") {
      return handleReport(request, env);
    }

    return htmlResponse(renderPage(await buildFullAnalysis(request, env)));
  }
};
