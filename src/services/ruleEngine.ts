/**
 * UserTrack Analytical Core & Rule Engine
 * Implements the algorithms from the specification:
 * 1. Brute Force Detector (5 errors in 5 min -> block 3 min, Critical incident)
 * 2. Time Anomaly Detector (2:00 <= hour <= 5:00 -> Medium incident)
 * 3. GeoIP Anomaly Detector (New IP / foreign country check -> Low/Medium incident)
 * 4. Honeypot Router Trap (/wp-login.php, /.env -> block 10 min, Critical incident, HACKER_BOT)
 * 5. Signature Analysis (Critical ports 22, 23, 3389, 3306, SQLi / attack patterns)
 * 6. IPS Active Prevention Layer (Drops blocked IPs before authentication)
 */

import { db } from './db';
import { NetworkEvent, SecurityIncident } from '../types';

export const HONEYPOT_PATHS = [
  { path: '/wp-login.php', desc: 'Фальшивая панель входа WordPress' },
  { path: '/.env', desc: 'Утечка файлов конфигурации и секретов' },
  { path: '/admin-panel-secret.php', desc: 'Скрытый административный бэкдор' },
  { path: '/phpmyadmin', desc: 'Интерфейс управления базами данных' },
  { path: '/api/v1/debug', desc: 'Неавторизованный отладочный endpoint' },
];

export const HONEYPOT_TRAPS = HONEYPOT_PATHS;

import { getQuickGeo, lookupIpGeo, GeoLookup } from './geoService';

export type { GeoLookup };

export function getIpInfo(ip: string): GeoLookup {
  return getQuickGeo(ip);
}

class RuleEngineService {
  /**
   * 1. Brute Force Protection (Сценарий 1)
   * Counts failures in the last 5 minutes. If >= 5, triggers IPS block for 3 mins.
   */
  public handleAuthAttempt(params: {
    ip: string;
    username: string;
    isSuccess: boolean;
    simulatedHour?: number; // allow testing night anomaly
    geoOverride?: GeoLookup;
  }): { allowed: boolean; blockedReason?: string; event: NetworkEvent; incident?: SecurityIncident } {
    const { ip, username, isSuccess, simulatedHour, geoOverride } = params;
    const geo = geoOverride || getIpInfo(ip);

    // If no geoOverride provided and geo is not yet finalized, resolve in background and patch event
    const patchEventGeoAsync = (eventId: number) => {
      if (!geoOverride && geo.country === 'Интернет') {
        lookupIpGeo(ip).then((realGeo) => {
          if (realGeo && realGeo.country && realGeo.country !== 'Интернет') {
            db.updateEvent(eventId, {
              country: realGeo.country,
              city: realGeo.city,
            });
          }
        }).catch(() => {});
      }
    };

    // Step 0: Check IPS block table first
    if (db.isIpBlocked(ip)) {
      const blockedEvent = db.addEvent({
        username,
        ipAddress: ip,
        eventType: 'SUSPICIOUS_PROBE',
        port: 443,
        country: geo.country,
        city: geo.city,
        details: `[IPS DROP] Запрос отклонён: IP ${ip} находится в черном списке блокировок`,
      });
      patchEventGeoAsync(blockedEvent.id);

      return {
        allowed: false,
        blockedReason: `IP-адрес ${ip} заблокирован системой IPS. Доступ запрещен до истечения таймаута.`,
        event: blockedEvent,
      };
    }

    if (!isSuccess) {
      // Record failure event
      const failEvent = db.addEvent({
        username,
        ipAddress: ip,
        eventType: 'AUTH_FAILURE',
        port: 443,
        country: geo.country,
        city: geo.city,
        details: `Неудачная попытка входа для пользователя '${username}'`,
      });
      patchEventGeoAsync(failEvent.id);

      // Count failures in the last 5 minutes
      const failCount = db.countRecentFailedLogins(ip, 5);

      if (failCount >= 5) {
        // Apply block on 5th failure
        db.applyBlock(ip, `Обнаружена Brute Force атака (${failCount} ошибок за 5 минут)`, 3, 'BRUTE_FORCE_BOT');
        const incident = db.addIncident({
          incidentType: 'BRUTE_FORCE',
          severity: 'Critical',
          description: `Зафиксирована серия из ${failCount} неудачных авторизаций с IP ${ip}. Система IPS заблокировала адрес на 3 минуты.`,
          sourceIp: ip,
          username,
          status: 'Active',
          ruleTriggered: 'RULE-BF-5MIN-THRESHOLD-5',
        });

        return {
          allowed: false,
          blockedReason: `Превышен лимит попыток входа (${failCount} ошибок). Ваш IP ${ip} автоматически заблокирован на 3 минуты модулем IPS!`,
          event: failEvent,
          incident,
        };
      }

      return {
        allowed: false,
        blockedReason: `Неверный пароль. Попытка ${failCount} из 5.`,
        event: failEvent,
      };
    }

    // AUTH SUCCESS
    const successEvent = db.addEvent({
      username,
      ipAddress: ip,
      eventType: 'AUTH_SUCCESS',
      port: 443,
      country: geo.country,
      city: geo.city,
      details: `Успешный вход пользователя '${username}' в систему`,
    });
    patchEventGeoAsync(successEvent.id);

    db.updateLastLogin(username);

    // 2. Check Time Anomaly (2:00 <= hour <= 5:00)
    const hour = simulatedHour !== undefined ? simulatedHour : new Date().getHours();
    let timeIncident: SecurityIncident | undefined;
    if (hour >= 2 && hour <= 5) {
      timeIncident = db.addIncident({
        incidentType: 'TIME_ANOMALY',
        severity: 'Medium',
        description: `Поведенческая аномалия: Вход пользователя '${username}' зафиксирован в аномальное ночное время (${hour}:15 MSK). Возможна работа бота или взлом учетной записи.`,
        sourceIp: ip,
        username,
        status: 'Active',
        ruleTriggered: 'UEBA-TIME-WINDOW-02-05',
      });
    }

    // 3. Check GeoIP Anomaly (New device / new IP)
    const user = db.getUserByUsername(username);
    let geoIncident: SecurityIncident | undefined;
    if (user && !user.knownIps.includes(ip)) {
      geoIncident = db.addIncident({
        incidentType: 'GEO_ANOMALY',
        severity: 'Low',
        description: `Вход с нового IP-адреса: Пользователь '${username}' ранее не авторизовывался с IP ${ip} (${geo.city}, ${geo.country}).`,
        sourceIp: ip,
        username,
        status: 'Active',
        ruleTriggered: 'UEBA-GEO-NEW-IP-DEVICE',
      });
      db.registerKnownIp(username, ip);
    }

    return {
      allowed: true,
      event: successEvent,
      incident: timeIncident || geoIncident,
    };
  }

  /**
   * 4. Honeypot Router Protection (Сценарий 2)
   * Instant 10 min block and Critical incident marked as HACKER_BOT.
   */
  public triggerHoneypot(path: string, ip: string, userAgent: string = 'Automated Scanner / Hydra'): {
    event: NetworkEvent;
    incident: SecurityIncident;
    block: unknown;
  } {
    const geo = getIpInfo(ip);

    const event = db.addEvent({
      username: 'HACKER_BOT',
      ipAddress: ip,
      eventType: 'HONEYPOT_HIT',
      port: 80,
      country: geo.country,
      city: geo.city,
      details: `[HONEYPOT TRAP] Попытка несанкционированного обращения к скрытой ловушке '${path}' (User-Agent: ${userAgent})`,
    });

    const block = db.applyBlock(
      ip,
      `Срабатывание ловушки Honeypot (запрос к фальшивому адресу '${path}')`,
      10,
      'HACKER_BOT'
    );

    const incident = db.addIncident({
      incidentType: 'HONEYPOT_TRIGGER',
      severity: 'Critical',
      description: `Сработал модуль контрразведки Honeypot: сканер уязвимостей попытался открыть '${path}' с IP ${ip} (${geo.country}). IP заблокирован на 10 минут, субъект классифицирован как HACKER_BOT.`,
      sourceIp: ip,
      username: 'HACKER_BOT',
      status: 'Active',
      ruleTriggered: `HONEYPOT-TRAP-${path.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`,
    });

    return { event, incident, block };
  }

  /**
   * 5. Network Port & Signature Inspection (Сценарий 3 & Сканирование портов)
   */
  public inspectNetworkPacket(packet: {
    ip: string;
    port: number;
    protocol: 'TCP' | 'UDP' | 'HTTP' | 'HTTPS';
    payload: string;
    apiKey?: string;
  }): { event: NetworkEvent; incident?: SecurityIncident } {
    const { ip, port, protocol, payload, apiKey } = packet;
    const geo = getIpInfo(ip);

    // Signature checks
    const criticalPorts = [22, 23, 3389, 3306, 5432, 1433];
    const isCriticalPort = criticalPorts.includes(port);

    const isSqlInjection =
      /(\bUNION\b|\bSELECT\b|--|' OR '1'='1'|\bDROP\b|\bEXEC\b)/i.test(payload) ||
      payload.includes("1' OR '1' = '1");

    const isPathTraversal = payload.includes('../') || payload.includes('etc/passwd') || payload.includes('win.ini');

    let eventType: NetworkEvent['eventType'] = 'NETWORK_REQUEST';
    if (apiKey) {
      eventType = 'API_LOG_INGEST';
    } else if (isCriticalPort) {
      eventType = 'PORT_ACCESS';
    } else if (isSqlInjection || isPathTraversal) {
      eventType = 'SUSPICIOUS_PROBE';
    }

    const event = db.addEvent({
      username: apiKey ? 'external_agent.py' : 'anonymous',
      ipAddress: ip,
      eventType,
      port,
      country: geo.country,
      city: geo.city,
      protocol,
      details: apiKey
        ? `Внешний сбор телеметрии: ${payload}`
        : `Сетевой пакет на порт ${port}: ${payload}`,
      payloadSnippet: payload.substring(0, 80),
    });

    let incident: SecurityIncident | undefined;

    if (isCriticalPort) {
      incident = db.addIncident({
        incidentType: 'CRITICAL_PORT_ACCESS',
        severity: 'High',
        description: `Попытка несанкционированного подключения к критическому порту ${port} (${protocol}) с IP ${ip} (${geo.country})`,
        sourceIp: ip,
        status: 'Active',
        ruleTriggered: `SIG-RULE-PORT-${port}`,
      });
    } else if (isSqlInjection || isPathTraversal) {
      incident = db.addIncident({
        incidentType: 'MALICIOUS_PAYLOAD',
        severity: 'Critical',
        description: `Обнаружена сигнатура атаки (${isSqlInjection ? 'SQL Injection' : 'Path Traversal'}) в теле запроса с IP ${ip}`,
        sourceIp: ip,
        status: 'Active',
        ruleTriggered: isSqlInjection ? 'SIG-SQL-INJECTION' : 'SIG-PATH-TRAVERSAL',
      });
    }

    return { event, incident };
  }

  public ingestNetworkEvent(params: {
    ip: string;
    port: number;
    protocol?: 'TCP' | 'UDP' | 'HTTP' | 'HTTPS';
    details: string;
    country?: string;
    city?: string;
    username?: string;
  }): NetworkEvent {
    const res = this.inspectNetworkPacket({
      ip: params.ip,
      port: params.port,
      protocol: params.protocol || 'HTTP',
      payload: params.details,
    });
    return res.event;
  }
}

export const ruleEngine = new RuleEngineService();
