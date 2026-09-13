import { isValidIp, isIpv4, isPrivateOrLocalIp, registerIpGeo, lookupIpGeo, GeoLookup } from './geoService';

export { isValidIp, isIpv4 };

let cachedIp: string | null = null;
let lastDetectionSource: string = '';
let lastDetectedGeo: GeoLookup | null = null;

export function isPrivateIp(ip: string): boolean {
  return isPrivateOrLocalIp(ip);
}

/**
 * Filter out Cloud Run internal proxy IPs (e.g. 34.x.x.x Google Cloud egress)
 */
function isCloudRunProxyIp(ip: string): boolean {
  if (!ip) return true;
  const clean = ip.trim();
  // Check if it matches Google Cloud / Cloud Run internal proxy ranges
  if (clean.startsWith('34.34.') || clean.startsWith('34.118.') || clean.startsWith('34.120.')) {
    return true;
  }
  return false;
}

/**
 * WebRTC STUN client IP discovery.
 * Queries Google's STUN servers over UDP to find the external public NAT address of the browser.
 */
function getIpFromWebRTC(timeoutMs = 2500): Promise<{ ip: string; source: string } | null> {
  return new Promise((resolve) => {
    if (typeof window === 'undefined' || !window.RTCPeerConnection) {
      resolve(null);
      return;
    }

    try {
      const pc = new RTCPeerConnection({
        iceServers: [
          { urls: 'stun:stun.l.google.com:19302' },
          { urls: 'stun:stun1.l.google.com:19302' },
          { urls: 'stun:stun2.l.google.com:19302' },
        ],
      });

      const timer = setTimeout(() => {
        try {
          pc.close();
        } catch {
          // ignore
        }
        resolve(null);
      }, timeoutMs);

      pc.onicecandidate = (e) => {
        if (!e || !e.candidate || !e.candidate.candidate) return;
        const line = e.candidate.candidate;
        // Looking for candidate typ srflx raddr ...
        const match = line.match(
          /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/i
        );
        if (match && match[0]) {
          const detected = match[0].trim();
          if (isValidIp(detected) && !isPrivateIp(detected)) {
            clearTimeout(timer);
            try {
              pc.close();
            } catch {
              // ignore
            }
            resolve({ ip: detected, source: 'WebRTC STUN' });
          }
        }
      };

      pc.createDataChannel('detect-ip');
      pc.createOffer()
        .then((offer) => pc.setLocalDescription(offer))
        .catch(() => {
          clearTimeout(timer);
          try {
            pc.close();
          } catch {
            // ignore
          }
          resolve(null);
        });
    } catch {
      resolve(null);
    }
  });
}

/**
 * Fetch helper with timeout
 */
async function fetchWithTimeout(url: string, timeoutMs = 2500): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

export interface DetectResult {
  ip: string;
  source: string;
  country?: string;
  city?: string;
  flag?: string;
}

/**
 * Detects real client IP by querying reliable direct browser endpoints in parallel.
 * NEVER uses server-side Cloud Run ingress to avoid proxy address confusion.
 * Prefers public IPv4 address.
 */
export async function detectRealIp(forceRefresh = false): Promise<string> {
  if (!forceRefresh && cachedIp && !isPrivateIp(cachedIp) && !isCloudRunProxyIp(cachedIp)) {
    return cachedIp;
  }

  if (!forceRefresh) {
    try {
      const stored = sessionStorage.getItem('detected_client_ip');
      if (stored && isValidIp(stored) && !isPrivateIp(stored) && !isCloudRunProxyIp(stored)) {
        cachedIp = stored;
        return stored;
      }
    } catch {
      // Ignore
    }
  }

  // Create list of provider promises running directly from the client browser
  const queries: Array<Promise<DetectResult | null>> = [
    // 1. WebRTC STUN (most direct, no proxy tampering)
    getIpFromWebRTC(2500),

    // 2. geojs.io (Returns client IP + real city/country from browser)
    (async () => {
      try {
        const res = await fetchWithTimeout('https://get.geojs.io/v1/ip/geo.json', 2500);
        if (res.ok) {
          const data = await res.json();
          const ip = data?.ip ? String(data.ip).trim() : '';
          if (ip && isValidIp(ip) && !isPrivateIp(ip) && !isCloudRunProxyIp(ip)) {
            registerIpGeo(ip, {
              country: data.country,
              city: data.city,
            });
            return {
              ip,
              source: 'GeoJS',
              country: data.country,
              city: data.city,
            };
          }
        }
      } catch {
        // ignore
      }
      return null;
    })(),

    // 3. ipwho.is (Returns client IP + real city/country + flag from browser)
    (async () => {
      try {
        const res = await fetchWithTimeout('https://ipwho.is/', 2500);
        if (res.ok) {
          const data = await res.json();
          const ip = data?.ip ? String(data.ip).trim() : '';
          if (ip && isValidIp(ip) && !isPrivateIp(ip) && !isCloudRunProxyIp(ip)) {
            registerIpGeo(ip, {
              country: data.country,
              city: data.city,
              flag: data.flag?.emoji,
            });
            return {
              ip,
              source: 'ipwho.is',
              country: data.country,
              city: data.city,
              flag: data.flag?.emoji,
            };
          }
        }
      } catch {
        // ignore
      }
      return null;
    })(),

    // 4. AWS CheckIP
    (async () => {
      try {
        const res = await fetchWithTimeout('https://checkip.amazonaws.com', 2000);
        if (res.ok) {
          const text = (await res.text()).trim();
          if (isValidIp(text) && !isPrivateIp(text) && !isCloudRunProxyIp(text)) {
            return { ip: text, source: 'AWS CheckIP' };
          }
        }
      } catch {
        // ignore
      }
      return null;
    })(),

    // 5. ipify IPv4 explicit
    (async () => {
      try {
        const res = await fetchWithTimeout('https://api4.ipify.org?format=json', 2000);
        if (res.ok) {
          const data = await res.json();
          const ip = data?.ip ? String(data.ip).trim() : '';
          if (isValidIp(ip) && !isPrivateIp(ip) && !isCloudRunProxyIp(ip)) {
            return { ip, source: 'ipify IPv4' };
          }
        }
      } catch {
        // ignore
      }
      return null;
    })(),

    // 6. icanhazip (Cloudflare)
    (async () => {
      try {
        const res = await fetchWithTimeout('https://icanhazip.com', 2000);
        if (res.ok) {
          const text = (await res.text()).trim();
          if (isValidIp(text) && !isPrivateIp(text) && !isCloudRunProxyIp(text)) {
            return { ip: text, source: 'icanhazip' };
          }
        }
      } catch {
        // ignore
      }
      return null;
    })(),

    // 7. seeip
    (async () => {
      try {
        const res = await fetchWithTimeout('https://api.seeip.org/jsonip', 2000);
        if (res.ok) {
          const data = await res.json();
          const ip = data?.ip ? String(data.ip).trim() : '';
          if (isValidIp(ip) && !isPrivateIp(ip) && !isCloudRunProxyIp(ip)) {
            return { ip, source: 'seeip' };
          }
        }
      } catch {
        // ignore
      }
      return null;
    })(),
  ];

  const results = await Promise.allSettled(queries);
  const validIps: Array<DetectResult & { isIpv4: boolean }> = [];

  for (const r of results) {
    if (r.status === 'fulfilled' && r.value && r.value.ip) {
      validIps.push({
        ...r.value,
        isIpv4: isIpv4(r.value.ip),
      });
    }
  }

  // Preference order:
  // 1. First valid non-private IPv4 address that is not a Cloud Run proxy
  const ipv4Match = validIps.find((item) => item.isIpv4 && !isCloudRunProxyIp(item.ip));
  if (ipv4Match) {
    cachedIp = ipv4Match.ip;
    lastDetectionSource = ipv4Match.source;
    try {
      sessionStorage.setItem('detected_client_ip', ipv4Match.ip);
    } catch {
      // ignore
    }

    // Trigger async geo resolution so it is immediately cached
    lookupIpGeo(ipv4Match.ip).then((geo) => {
      lastDetectedGeo = geo;
    }).catch(() => {});

    return ipv4Match.ip;
  }

  // 2. If no IPv4, take any valid non-private IP
  const nonPrivate = validIps.find((item) => !isCloudRunProxyIp(item.ip));
  if (nonPrivate) {
    cachedIp = nonPrivate.ip;
    lastDetectionSource = nonPrivate.source;
    try {
      sessionStorage.setItem('detected_client_ip', nonPrivate.ip);
    } catch {
      // ignore
    }
    lookupIpGeo(nonPrivate.ip).then((geo) => {
      lastDetectedGeo = geo;
    }).catch(() => {});
    return nonPrivate.ip;
  }

  // If all external queries failed (e.g. strict offline mode)
  return '';
}

export function getLastDetectionSource(): string {
  return lastDetectionSource;
}

export function getLastDetectedGeo(): GeoLookup | null {
  return lastDetectedGeo;
}
