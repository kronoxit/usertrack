export interface GeoLookup {
  ip: string;
  country: string;
  city: string;
  flag: string;
  isp?: string;
}

export function isIpv4(ip: string): boolean {
  if (!ip) return false;
  const clean = ip.replace(/^::ffff:/, '').trim();
  const parts = clean.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    const num = Number(p);
    return !isNaN(num) && num >= 0 && num <= 255 && String(num) === p;
  });
}

export function isValidIp(ip: string): boolean {
  if (!ip) return false;
  const clean = ip.replace(/^::ffff:/, '').trim();
  if (isIpv4(clean)) return true;
  return clean.includes(':') && /^[0-9a-fA-F:]+$/.test(clean);
}

const COUNTRY_TRANSLATIONS: Record<string, string> = {
  'Russian Federation': 'Россия',
  'Russia': 'Россия',
  'Belarus': 'Беларусь',
  'Kazakhstan': 'Казахстан',
  'Ukraine': 'Украина',
  'United States': 'США',
  'USA': 'США',
  'Germany': 'Германия',
  'France': 'Франция',
  'United Kingdom': 'Великобритания',
  'Great Britain': 'Великобритания',
  'Netherlands': 'Нидерланды',
  'China': 'Китай',
  'Poland': 'Польша',
  'Finland': 'Финляндия',
  'Turkey': 'Турция',
  'Uzbekistan': 'Узбекистан',
  'Armenia': 'Армения',
  'Georgia': 'Грузия',
  'Azerbaijan': 'Азербайджан',
  'Kyrgyzstan': 'Кыргызстан',
  'Tajikistan': 'Таджикистан',
  'Moldova': 'Молдова',
  'Lithuania': 'Литва',
  'Latvia': 'Латвия',
  'Estonia': 'Эстония',
};

const CITY_TRANSLATIONS: Record<string, string> = {
  'Moscow': 'Москва',
  'Moskva': 'Москва',
  'Saint Petersburg': 'Санкт-Петербург',
  'St Petersburg': 'Санкт-Петербург',
  'Novosibirsk': 'Новосибирск',
  'Yekaterinburg': 'Екатеринбург',
  'Nizhny Novgorod': 'Нижний Новгород',
  'Kazan': 'Казань',
  'Chelyabinsk': 'Челябинск',
  'Samara': 'Самара',
  'Omsk': 'Омск',
  'Rostov-on-Don': 'Ростов-на-Дону',
  'Ufa': 'Уфа',
  'Krasnoyarsk': 'Красноярск',
  'Voronezh': 'Воронеж',
  'Perm': 'Пермь',
  'Volgograd': 'Волгоград',
  'Krasnodar': 'Краснодар',
  'Obninsk': 'Обнинск',
  'Kaluga': 'Калуга',
  'Tula': 'Тула',
  'Kyiv': 'Киев',
  'Minsk': 'Минск',
  'Almaty': 'Алматы',
  'Astana': 'Астана',
};

// In-memory cache
const GEO_CACHE: Record<string, GeoLookup> = {
  '127.0.0.1': { ip: '127.0.0.1', country: 'Локальная сеть', city: 'Localhost', flag: '💻' },
  '::1': { ip: '::1', country: 'Локальная сеть', city: 'Localhost', flag: '💻' },
  '192.168.1.10': { ip: '192.168.1.10', country: 'Локальная сеть', city: 'Рабочая станция', flag: '🏢' },
  '192.168.1.45': { ip: '192.168.1.45', country: 'Локальная сеть', city: 'Офис', flag: '🏢' },
  '192.168.1.78': { ip: '192.168.1.78', country: 'Локальная сеть', city: 'Офис', flag: '🏢' },
  '10.10.20.15': { ip: '10.10.20.15', country: 'Корпоративная сеть', city: 'Филиал', flag: '🏢' },
};

// Try restoring cached entries from localStorage
try {
  if (typeof window !== 'undefined') {
    const raw = localStorage.getItem('siem_geo_cache');
    if (raw) {
      const parsed = JSON.parse(raw);
      Object.assign(GEO_CACHE, parsed);
    }
  }
} catch {
  // ignore
}

function persistCache(): void {
  try {
    if (typeof window !== 'undefined') {
      localStorage.setItem('siem_geo_cache', JSON.stringify(GEO_CACHE));
    }
  } catch {
    // ignore
  }
}

export function isPrivateOrLocalIp(ip: string): boolean {
  if (!ip) return true;
  const clean = ip.replace(/^::ffff:/, '').trim();
  if (clean === '127.0.0.1' || clean === '::1' || clean === 'localhost') return true;
  if (clean.startsWith('10.') || clean.startsWith('192.168.') || clean.startsWith('169.254.')) {
    return true;
  }
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(clean)) return true;
  return false;
}

function normalizeCountry(raw: string): string {
  if (!raw) return '';
  const trimmed = raw.trim();
  return COUNTRY_TRANSLATIONS[trimmed] || trimmed;
}

function normalizeCity(raw: string): string {
  if (!raw) return '';
  const trimmed = raw.trim();
  return CITY_TRANSLATIONS[trimmed] || trimmed;
}

/**
 * Register known IP geo into cache (e.g. discovered during client detection)
 */
export function registerIpGeo(ip: string, info: Partial<GeoLookup>): GeoLookup {
  const cleanIp = ip.trim();
  const existing = GEO_CACHE[cleanIp] || {
    ip: cleanIp,
    country: 'Неизвестно',
    city: '',
    flag: '🌐',
  };

  const updated: GeoLookup = {
    ip: cleanIp,
    country: info.country ? normalizeCountry(info.country) : existing.country,
    city: info.city ? normalizeCity(info.city) : existing.city,
    flag: info.flag || existing.flag || '🌐',
    isp: info.isp || existing.isp,
  };

  GEO_CACHE[cleanIp] = updated;
  persistCache();
  return updated;
}

/**
 * Perform real GeoIP lookup for any IPv4 or IPv6 address.
 * Resolves the real country, city, and flag directly from public GeoIP APIs.
 */
export async function lookupIpGeo(ip: string): Promise<GeoLookup> {
  const cleanIp = (ip || '').trim();
  if (!cleanIp) {
    return { ip: '', country: 'Локальная сеть', city: 'LAN', flag: '💻' };
  }

  // Check private IP
  if (isPrivateOrLocalIp(cleanIp)) {
    return { ip: cleanIp, country: 'Локальная сеть', city: 'LAN', flag: '💻' };
  }

  // Check cache
  if (GEO_CACHE[cleanIp] && GEO_CACHE[cleanIp].country !== 'Определение...') {
    return GEO_CACHE[cleanIp];
  }

  // Provider 1: ipwho.is (includes flag emoji, city, country)
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(cleanIp)}`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      if (data && data.success) {
        const country = normalizeCountry(data.country || '');
        const city = normalizeCity(data.city || '');
        const flag = data.flag?.emoji || '🌐';
        const isp = data.connection?.isp || data.connection?.org || '';

        const item: GeoLookup = {
          ip: cleanIp,
          country: country || 'Интернет',
          city,
          flag,
          isp,
        };
        GEO_CACHE[cleanIp] = item;
        persistCache();
        return item;
      }
    }
  } catch {
    // try fallback
  }

  // Provider 2: get.geojs.io
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(`https://get.geojs.io/v1/ip/geo/${encodeURIComponent(cleanIp)}.json`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      if (data && data.country) {
        const country = normalizeCountry(data.country);
        const city = normalizeCity(data.city || '');
        const item: GeoLookup = {
          ip: cleanIp,
          country,
          city,
          flag: '🌐',
          isp: data.organization_name || data.organization || '',
        };
        GEO_CACHE[cleanIp] = item;
        persistCache();
        return item;
      }
    }
  } catch {
    // ignore
  }

  // Final fallback
  const fallback: GeoLookup = {
    ip: cleanIp,
    country: 'Интернет',
    city: '',
    flag: '🌐',
  };
  GEO_CACHE[cleanIp] = fallback;
  return fallback;
}

/**
 * Synchronous access to cached GeoIP lookup.
 * Triggers background resolution if not yet in cache.
 */
export function getQuickGeo(ip: string): GeoLookup {
  const clean = (ip || '').trim();
  if (!clean || isPrivateOrLocalIp(clean)) {
    return {
      ip: clean || '127.0.0.1',
      country: 'Локальная сеть',
      city: 'LAN',
      flag: '💻',
    };
  }

  if (GEO_CACHE[clean]) {
    return GEO_CACHE[clean];
  }

  // Start asynchronous lookup in background
  lookupIpGeo(clean).catch(() => {});

  return {
    ip: clean,
    country: 'Интернет',
    city: '',
    flag: '🌐',
  };
}
