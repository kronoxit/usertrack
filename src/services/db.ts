/**
 * UserTrack SQLite Database Engine (usertrack.db)
 * Models the 4 relational tables specified in schema.sql:
 * - users
 * - events
 * - incidents
 * - blocks
 */

import { User, UserRole, NetworkEvent, SecurityIncident, IPBlock, IncidentStatus, IncidentSeverity, IncidentType, EventType, SecurityAlertNotification } from '../types';

export const SCHEMA_SQL = `-- UserTrack Database Schema (schema.sql)
-- SQLite 3 Database Definition for SIEM / UEBA / IPS Platform

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT CHECK(role IN ('admin', 'user')) NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    username TEXT,
    ip_address TEXT NOT NULL,
    event_type TEXT NOT NULL,
    port INTEGER DEFAULT 80,
    country TEXT DEFAULT 'RU',
    city TEXT DEFAULT 'Москва',
    details TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    incident_type TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')) NOT NULL,
    description TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    status TEXT CHECK(status IN ('Active', 'Investigating', 'Resolved')) DEFAULT 'Active'
);

CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    reason TEXT NOT NULL,
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    unlock_time DATETIME NOT NULL,
    is_active INTEGER DEFAULT 1
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip_address);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_incidents_sev ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks(ip_address);
`;

const STORAGE_KEY = 'usertrack_sqlite_db_v7_single_admin';

interface DBState {
  users: User[];
  events: NetworkEvent[];
  incidents: SecurityIncident[];
  blocks: IPBlock[];
  notifications: SecurityAlertNotification[];
}

const INITIAL_USERS: User[] = [
  {
    id: 1,
    username: 'artem',
    passwordHash: 'pbkdf2:sha256:600000$artem$d8e8fca9b19e2... (Werkzeug Hash)',
    passwordPlain: 'admin123',
    role: 'admin',
    createdAt: new Date().toISOString(),
    lastLogin: undefined,
    knownIps: ['192.168.1.10'],
    fullName: 'Артем',
    isChiefAdmin: true,
  },
];

// PRELIMINARILY EMPTY as explicitly requested by user!
const INITIAL_EVENTS: NetworkEvent[] = [];
const INITIAL_INCIDENTS: SecurityIncident[] = [];
const INITIAL_BLOCKS: IPBlock[] = [];

// Demo seed data that can be loaded on-demand if the user clicks "Заполнить демо-данными"
const DEMO_EVENTS: NetworkEvent[] = [
  {
    id: 1,
    timestamp: new Date(Date.now() - 3600000 * 3).toISOString(),
    username: 'artem',
    ipAddress: '192.168.1.10',
    eventType: 'AUTH_SUCCESS',
    port: 443,
    country: 'Россия',
    city: 'Москва',
    details: 'Успешная авторизация администратора artem в консоли SecOps',
    protocol: 'HTTPS',
  },
  {
    id: 2,
    timestamp: new Date(Date.now() - 3600000 * 2.5).toISOString(),
    username: 'sm1',
    ipAddress: '192.168.1.45',
    eventType: 'AUTH_SUCCESS',
    port: 443,
    country: 'Россия',
    city: 'Санкт-Петербург',
    details: 'Плановый вход пользователя sm1 в рабочий кабинет',
    protocol: 'HTTPS',
  },
  {
    id: 3,
    timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
    username: 'intruder',
    ipAddress: '85.114.120.4',
    eventType: 'PORT_ACCESS',
    port: 22,
    country: 'Нидерланды',
    city: 'Амстердам',
    details: 'Попытка сканирования и подключения к SSH-порту 22',
    protocol: 'TCP',
  },
  {
    id: 4,
    timestamp: new Date(Date.now() - 1800000).toISOString(),
    username: 'artem',
    ipAddress: '192.168.1.10',
    eventType: 'AUTH_SUCCESS',
    port: 443,
    country: 'Россия',
    city: 'Москва',
    details: 'Просмотр журнала событий информационной безопасности',
    protocol: 'HTTPS',
  },
];

const DEMO_INCIDENTS: SecurityIncident[] = [
  {
    id: 1,
    timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
    incidentType: 'CRITICAL_PORT_ACCESS',
    severity: 'High',
    description: 'Попытка несанкционированного доступа к порту 22 (SSH) с внешнего узла',
    sourceIp: '85.114.120.4',
    status: 'Investigating',
    ruleTriggered: 'SIG-RULE-PORT-22-EXTERNAL',
  },
  {
    id: 2,
    timestamp: new Date(Date.now() - 3600000 * 1.5).toISOString(),
    incidentType: 'BRUTE_FORCE',
    severity: 'Critical',
    description: 'Зафиксирована атака подбором пароля (Brute Force): 5 неудачных попыток входа подряд. Модуль IPS применил блокировку',
    sourceIp: '194.26.29.112',
    status: 'Active',
    ruleTriggered: 'RULE-AUTH-BRUTEFORCE',
  },
];

const DEMO_BLOCKS: IPBlock[] = [
  {
    id: 1,
    ipAddress: '194.26.29.112',
    reason: 'Блокировка IPS: превышен лимит неудачных попыток входа (Brute Force)',
    blockedAt: new Date(Date.now() - 3600000 * 1.5).toISOString(),
    unlockTime: new Date(Date.now() + 600000).toISOString(),
    isActive: true,
    blockDurationMinutes: 10,
    threatActor: 'BRUTE_FORCE_BOT',
  },
];

class DatabaseService {
  private state: DBState;
  private listeners: Array<() => void> = [];

  constructor() {
    this.state = this.loadState();
  }

  private loadState(): DBState {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed.users && parsed.events && parsed.incidents && parsed.blocks) {
          parsed.users = parsed.users.filter((u: User) => u.username !== 'sm1');
          const chief = parsed.users.find((u: User) => u.isChiefAdmin || u.id === 1 || u.username === 'artem');
          if (!chief) {
            parsed.users.unshift(INITIAL_USERS[0]);
          } else {
            chief.isChiefAdmin = true;
            chief.id = 1;
            if (chief.fullName === 'Артем (Главный администратор)') {
              chief.fullName = 'Артем';
            }
          }
          if (Array.isArray(parsed.events)) {
            parsed.events.forEach((ev: NetworkEvent) => {
              if (ev.city === 'Париж' || (ev.country === 'Франция' && ev.city === 'Париж')) {
                ev.city = '';
                ev.country = '';
              }
            });
          }
          return parsed;
        }
      }
    } catch {
      // Fallback
    }

    // Default to completely empty database!
    return {
      users: [...INITIAL_USERS],
      events: [],
      incidents: [],
      blocks: [],
      notifications: [],
    };
  }

  private saveState(): void {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.state));
    } catch {
      // ignore
    }
    this.notify();
  }

  public subscribe(listener: () => void): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  private notify(): void {
    this.listeners.forEach((fn) => {
      try {
        fn();
      } catch (e) {
        console.error('DB listener error:', e);
      }
    });
  }

  // Clear all tracked data (Events, Incidents, Blocks, Notifications) -> 100% EMPTY DB
  public clearAllData(): void {
    this.state.events = [];
    this.state.incidents = [];
    this.state.blocks = [];
    this.state.notifications = [];
    this.saveState();
  }

  // Configurable Data Generation
  public generateCustomData(options: {
    eventsCount?: number;
    users?: string[];
    includeSuccess?: boolean;
    includeFailures?: boolean;
    includePortScans?: boolean;
    createIncidents?: boolean;
    createBlocks?: boolean;
    cleanFirst?: boolean;
  }): { eventsAdded: number; incidentsAdded: number; blocksAdded: number } {
    if (options.cleanFirst) {
      this.state.events = [];
      this.state.incidents = [];
      this.state.blocks = [];
      this.state.notifications = [];
    }

    const count = options.eventsCount || 15;
    const allowedUsers = options.users && options.users.length > 0 ? options.users : ['artem', 'sm1', 'intruder'];
    const incSuccess = options.includeSuccess !== false;
    const incFail = options.includeFailures !== false;
    const incScan = options.includePortScans !== false;

    const availableTypes: { type: EventType; desc: string; port: number }[] = [];
    if (incSuccess) {
      availableTypes.push(
        { type: 'AUTH_SUCCESS', desc: 'Успешный вход в рабочий аккаунт', port: 443 },
        { type: 'AUTH_SUCCESS', desc: 'Проверка системного журнала и статистики', port: 443 }
      );
    }
    if (incFail) {
      availableTypes.push(
        { type: 'AUTH_FAILURE', desc: 'Ошибка авторизации: неверный пароль', port: 443 },
        { type: 'AUTH_FAILURE', desc: 'Попытка входа с неподтвержденного устройства', port: 443 }
      );
    }
    if (incScan) {
      availableTypes.push(
        { type: 'PORT_ACCESS', desc: 'Попытка сканирования SSH-порта', port: 22 },
        { type: 'PORT_ACCESS', desc: 'Подключение к открытому порту СУБД', port: 3306 }
      );
    }
    if (availableTypes.length === 0) {
      availableTypes.push({ type: 'AUTH_SUCCESS', desc: 'Стандартное событие системы', port: 443 });
    }

    const ipsPool = [
      { ip: '192.168.1.10', city: 'Москва', country: 'Россия' },
      { ip: '192.168.1.45', city: 'Санкт-Петербург', country: 'Россия' },
      { ip: '85.114.120.4', city: 'Амстердам', country: 'Нидерланды' },
      { ip: '194.26.29.112', city: 'Нью-Йорк', country: 'США' },
      { ip: '185.220.101.5', city: 'Франкфурт', country: 'Германия' },
      { ip: '45.154.255.89', city: 'Шэньчжэнь', country: 'Китай' },
    ];

    const now = Date.now();
    let nextEvId = this.state.events.length > 0 ? Math.max(...this.state.events.map((e) => e.id)) + 1 : 1;

    for (let i = 0; i < count; i++) {
      const timeOffset = (count - i) * (Math.floor(Math.random() * 8) + 4) * 60 * 1000;
      const t = new Date(now - timeOffset).toISOString();
      const user = allowedUsers[Math.floor(Math.random() * allowedUsers.length)];
      const sample = availableTypes[Math.floor(Math.random() * availableTypes.length)];
      const isInternal = user === 'artem' || user === 'sm1';
      const loc = isInternal ? ipsPool[user === 'artem' ? 0 : 1] : ipsPool[Math.floor(Math.random() * (ipsPool.length - 2)) + 2];

      this.state.events.unshift({
        id: nextEvId++,
        timestamp: t,
        username: user,
        ipAddress: loc.ip,
        eventType: sample.type,
        port: sample.port,
        country: loc.country,
        city: loc.city,
        details: `${sample.desc} (${user})`,
        protocol: sample.port === 443 ? 'HTTPS' : sample.port === 22 ? 'TCP' : 'HTTP',
      });
    }

    let incidentsAdded = 0;
    if (options.createIncidents) {
      let nextIncId = this.state.incidents.length > 0 ? Math.max(...this.state.incidents.map((i) => i.id)) + 1 : 1;
      
      this.state.incidents.unshift({
        id: nextIncId++,
        timestamp: new Date(now - 1800000).toISOString(),
        incidentType: 'BRUTE_FORCE',
        severity: 'Critical',
        description: 'Серия неудачных попыток входа (Brute Force) с узла 194.26.29.112 на аккаунт sm1',
        sourceIp: '194.26.29.112',
        status: 'Active',
        ruleTriggered: 'RULE-AUTH-BRUTEFORCE',
      });
      incidentsAdded++;

      this.state.incidents.unshift({
        id: nextIncId++,
        timestamp: new Date(now - 3600000 * 2).toISOString(),
        incidentType: 'CRITICAL_PORT_ACCESS',
        severity: 'High',
        description: 'Несанкционированное сканирование и обращение к порту 22 (SSH) с IP 85.114.120.4',
        sourceIp: '85.114.120.4',
        status: 'Investigating',
        ruleTriggered: 'SIG-RULE-PORT-22-EXTERNAL',
      });
      incidentsAdded++;

      this.state.incidents.unshift({
        id: nextIncId++,
        timestamp: new Date(now - 3600000 * 4).toISOString(),
        incidentType: 'TIME_ANOMALY',
        severity: 'Medium',
        description: 'Аномальное время авторизации в системе (ночной интервал 03:25)',
        sourceIp: '192.168.1.10',
        status: 'Resolved',
        ruleTriggered: 'RULE-TIME-NIGHT-0300',
      });
      incidentsAdded++;
    }

    let blocksAdded = 0;
    if (options.createBlocks) {
      this.applyBlock('194.26.29.112', 'Блокировка IPS: превышен лимит 5 ошибок аутентификации (Brute Force)', 5, 'BRUTE_FORCE_BOT');
      blocksAdded++;
      this.applyBlock('85.114.120.4', 'Блокировка IPS: подозрительный скан критических портов', 3, 'PORT_SCANNER');
      blocksAdded++;
    }

    this.saveState();
    return { eventsAdded: count, incidentsAdded, blocksAdded };
  }

  // Artificial Incident Creation Tool
  public createCustomIncident(params: {
    incidentType: IncidentType;
    severity: IncidentSeverity;
    status?: IncidentStatus;
    username?: string;
    sourceIp: string;
    description: string;
    ruleTriggered?: string;
    applyIpsBlock?: boolean;
    blockDurationMinutes?: number;
    recordNetworkEvent?: boolean;
    sendAlertNotification?: boolean;
  }): SecurityIncident {
    const nextIncId = this.state.incidents.length > 0 ? Math.max(...this.state.incidents.map((i) => i.id)) + 1 : 1;
    const nowIso = new Date().toISOString();

    const incident: SecurityIncident = {
      id: nextIncId,
      timestamp: nowIso,
      incidentType: params.incidentType,
      severity: params.severity,
      description: params.description,
      sourceIp: params.sourceIp,
      username: params.username || 'unknown',
      status: params.status || 'Active',
      ruleTriggered: params.ruleTriggered || `RULE-${params.incidentType}`,
    };

    this.state.incidents.unshift(incident);

    // Optionally add associated raw network event
    if (params.recordNetworkEvent !== false) {
      let evType: EventType = 'AUTH_FAILURE';
      if (params.incidentType === 'CRITICAL_PORT_ACCESS' || params.incidentType === 'PORT_SCAN') {
        evType = 'PORT_ACCESS';
      }
      this.addEvent({
        username: params.username || 'unknown',
        ipAddress: params.sourceIp,
        eventType: evType,
        port: params.incidentType === 'CRITICAL_PORT_ACCESS' ? 22 : 443,
        details: `[ИСКУССТВЕННЫЙ ИНЦИДЕНТ #${nextIncId}] ${params.description}`,
      });
    }

    // Optionally apply IPS block immediately
    if (params.applyIpsBlock) {
      this.applyBlock(
        params.sourceIp,
        `[Искусственный инцидент #${nextIncId}] ${params.description}`,
        params.blockDurationMinutes || 3,
        `SIMULATED_${params.incidentType}`
      );
    }

    // Optionally send alert notification
    if (params.sendAlertNotification !== false) {
      this.addNotification({
        channel: 'IN_APP',
        recipient: 'Администратор SIEM',
        title: `⚠️ ИНЦИДЕНТ: ${params.incidentType} (${params.severity})`,
        message: `Создан инцидент #${nextIncId} для пользователя [${params.username || 'unknown'}]. Узел: ${params.sourceIp}. Описание: ${params.description}`,
        severity: params.severity,
      });
    }

    this.saveState();
    return incident;
  }

  // Standard demo seed (backward compatible)
  public seedDemoData(): void {
    this.generateCustomData({
      eventsCount: 15,
      users: ['artem', 'sm1', 'intruder'],
      includeSuccess: true,
      includeFailures: true,
      includePortScans: true,
      createIncidents: true,
      createBlocks: true,
      cleanFirst: true,
    });
  }

  // Notifications
  public getNotifications(): SecurityAlertNotification[] {
    return [...(this.state.notifications || [])].sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  public addNotification(alert: Omit<SecurityAlertNotification, 'id' | 'timestamp'>): SecurityAlertNotification {
    if (!this.state.notifications) this.state.notifications = [];
    const notif: SecurityAlertNotification = {
      id: `alert-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      ...alert,
      read: false,
    };
    this.state.notifications.unshift(notif);
    if (this.state.notifications.length > 50) {
      this.state.notifications = this.state.notifications.slice(0, 50);
    }
    this.saveState();
    return notif;
  }

  public markNotificationsRead(): void {
    if (this.state.notifications) {
      this.state.notifications.forEach((n) => (n.read = true));
      this.saveState();
    }
  }

  public clearNotifications(): void {
    this.state.notifications = [];
    this.saveState();
  }

  public resetDatabase(): void {
    this.clearAllData();
  }

  // Users Table
  public getUsers(): User[] {
    return [...this.state.users];
  }

  public getAllUsernames(): string[] {
    return this.state.users.map((u) => u.username);
  }

  public getUserByUsername(username: string): User | undefined {
    const search = (username || '').trim().toLowerCase();
    return this.state.users.find((u) => u.username.trim().toLowerCase() === search);
  }

  public createUser(data: {
    username: string;
    role: UserRole;
    password?: string;
    knownIps?: string[];
    fullName?: string;
  }): { success: boolean; error?: string; user?: User } {
    const trimmed = (data.username || '').trim();
    if (!trimmed) {
      return { success: false, error: 'Имя пользователя не может быть пустым' };
    }
    if (this.getUserByUsername(trimmed)) {
      return { success: false, error: `Пользователь с именем «${trimmed}» уже зарегистрирован` };
    }

    const plainPwd = (data.password || '').trim();
    if (!plainPwd) {
      return { success: false, error: 'Пароль не может быть пустым' };
    }

    const nextId = this.state.users.length > 0 ? Math.max(...this.state.users.map((u) => u.id)) + 1 : 1;
    const pwdHash = `pbkdf2:sha256:600000$${trimmed}$${Math.random().toString(36).substring(2, 12)}... (Werkzeug Hash)`;

    const newUser: User = {
      id: nextId,
      username: trimmed,
      passwordHash: pwdHash,
      passwordPlain: plainPwd,
      role: 'user', // Все новые пользователи регистрируются как обычные пользователи
      createdAt: new Date().toISOString(),
      knownIps: data.knownIps && data.knownIps.length > 0 ? data.knownIps : ['192.168.1.50'],
      fullName: data.fullName?.trim() || undefined,
    };

    this.state.users.push(newUser);

    // Audit event
    this.addEvent({
      username: 'admin',
      ipAddress: '192.168.1.10',
      eventType: 'ADMIN_ACCESS',
      port: 443,
      details: `Создана учетная запись пользователя '${trimmed}' (Роль: USER)`,
    });

    this.saveState();
    return { success: true, user: newUser };
  }

  public updateChiefAdminProfile(
    userId: number,
    newUsername: string,
    newFullName: string,
    operatorUsername?: string
  ): { success: boolean; error?: string; user?: User } {
    const user = this.state.users.find((u) => u.id === userId);
    if (!user) {
      return { success: false, error: 'Пользователь не найден' };
    }
    const isChief = Boolean(user.isChiefAdmin || user.id === 1);
    if (!isChief) {
      return { success: false, error: 'Только главный администратор может изменять свои реквизиты' };
    }

    const trimmedUsername = (newUsername || '').trim();
    if (!trimmedUsername) {
      return { success: false, error: 'Логин (никнейм) не может быть пустым' };
    }

    // Check if another user has this username
    const existing = this.getUserByUsername(trimmedUsername);
    if (existing && existing.id !== user.id) {
      return { success: false, error: `Пользователь с никнеймом «${trimmedUsername}» уже существует` };
    }

    const oldUsername = user.username;
    user.username = trimmedUsername;
    user.fullName = newFullName.trim() || undefined;

    this.addEvent({
      username: trimmedUsername,
      ipAddress: '192.168.1.10',
      eventType: 'ADMIN_ACCESS',
      port: 443,
      details: `Главный администратор обновил профиль: логин с '${oldUsername}' на '${trimmedUsername}', имя '${user.fullName || '—'}'`,
    });

    this.saveState();
    return { success: true, user };
  }

  public updateUserTrustedIp(
    userId: number,
    newIp: string
  ): { success: boolean; error?: string; user?: User } {
    const user = this.state.users.find((u) => u.id === userId);
    if (!user) {
      return { success: false, error: 'Пользователь не найден' };
    }
    const cleanIp = (newIp || '').trim();
    if (!cleanIp) {
      return { success: false, error: 'Укажите корректный IP-адрес' };
    }

    user.knownIps = [cleanIp];
    this.addEvent({
      username: user.username,
      ipAddress: cleanIp,
      eventType: 'ADMIN_ACCESS',
      port: 443,
      details: `Обновлен доверенный IP адрес пользователя '${user.username}' на '${cleanIp}'`,
    });
    this.saveState();
    return { success: true, user };
  }

  public updateUser(
    userId: number,
    updates: Partial<User>
  ): { success: boolean; error?: string; user?: User } {
    const user = this.state.users.find((u) => u.id === userId);
    if (!user) {
      return { success: false, error: 'Пользователь не найден' };
    }
    if (updates.knownIps && Array.isArray(updates.knownIps)) {
      user.knownIps = updates.knownIps;
    }
    if (updates.fullName !== undefined) {
      user.fullName = updates.fullName;
    }
    this.saveState();
    return { success: true, user };
  }

  public verifyCredentials(
    username: string,
    passwordAttempt: string
  ): { success: boolean; user?: User; error?: string } {
    const user = this.getUserByUsername(username);
    if (!user) {
      return { success: false, error: 'Пользователь с таким логином не найден' };
    }
    const attempt = (passwordAttempt || '').trim();
    if (!attempt) {
      return { success: false, error: 'Введите пароль' };
    }

    const isChief = Boolean(user.isChiefAdmin || user.id === 1);
    const expectedPassword = user.passwordPlain || (isChief ? 'admin123' : 'user123');

    const isCorrect = attempt === expectedPassword;

    if (!isCorrect) {
      return { success: false, error: 'Неверный пароль' };
    }

    user.lastLogin = new Date().toISOString();
    this.saveState();
    return { success: true, user };
  }

  public deleteUser(userId: number, operatorUsername: string = ''): { success: boolean; error?: string } {
    const target = this.state.users.find((u) => u.id === userId);
    if (!target) {
      return { success: false, error: 'Пользователь не найден' };
    }
    if (target.isChiefAdmin || target.id === 1) {
      return { success: false, error: 'Нельзя удалить главного администратора' };
    }

    const operator = this.getUserByUsername(operatorUsername);
    const isChiefAdmin = operator ? Boolean(operator.isChiefAdmin || operator.id === 1) : false;

    // Обычные администраторы могут удалять только обычных пользователей
    if (target.role === 'admin' && !isChiefAdmin) {
      return { success: false, error: 'Только главный администратор имеет право удалять других администраторов' };
    }

    this.state.users = this.state.users.filter((u) => u.id !== userId);

    // Audit event
    this.addEvent({
      username: operatorUsername || 'admin',
      ipAddress: '192.168.1.10',
      eventType: 'ADMIN_ACCESS',
      port: 443,
      details: `Удалена учетная запись '${target.username}' (роль: ${target.role}) администратором ${operatorUsername || 'admin'}`,
    });

    this.saveState();
    return { success: true };
  }

  public updateUserRole(userId: number, newRole: UserRole, operatorUsername: string = ''): { success: boolean; error?: string } {
    const operator = this.getUserByUsername(operatorUsername);
    const isChiefAdmin = operator ? Boolean(operator.isChiefAdmin || operator.id === 1) : false;

    if (!isChiefAdmin) {
      return { success: false, error: 'Только главный администратор может изменять роли пользователей' };
    }

    const target = this.state.users.find((u) => u.id === userId);
    if (!target) {
      return { success: false, error: 'Пользователь не найден' };
    }
    if (target.isChiefAdmin || target.id === 1) {
      return { success: false, error: 'Нельзя изменить роль главного администратора' };
    }

    target.role = newRole;

    this.addEvent({
      username: operatorUsername || 'admin',
      ipAddress: '192.168.1.10',
      eventType: 'ADMIN_ACCESS',
      port: 443,
      details: `Изменена роль пользователя '${target.username}' на ${newRole === 'admin' ? 'Администратор' : 'Пользователь'} главным администратором ${operatorUsername || 'admin'}`,
    });

    this.saveState();
    return { success: true };
  }

  public registerKnownIp(username: string, ip: string): void {
    const user = this.getUserByUsername(username);
    if (user && !user.knownIps.includes(ip)) {
      user.knownIps.push(ip);
      this.saveState();
    }
  }

  public updateLastLogin(username: string): void {
    const user = this.getUserByUsername(username);
    if (user) {
      user.lastLogin = new Date().toISOString();
      this.saveState();
    }
  }

  // Events Table (Сырые логи)
  public getEvents(): NetworkEvent[] {
    return [...this.state.events].sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  public addEvent(
    eventData: Omit<NetworkEvent, 'id' | 'timestamp' | 'country' | 'city'> & {
      timestamp?: string;
      country?: string;
      city?: string;
    }
  ): NetworkEvent {
    const nextId = this.state.events.length > 0 ? Math.max(...this.state.events.map((e) => e.id)) + 1 : 1;
    const newEvent: NetworkEvent = {
      id: nextId,
      timestamp: eventData.timestamp || new Date().toISOString(),
      username: eventData.username,
      ipAddress: eventData.ipAddress,
      eventType: eventData.eventType,
      port: eventData.port,
      country: eventData.country || 'RU',
      city: eventData.city || 'Москва',
      details: eventData.details,
      protocol: eventData.protocol || 'HTTP',
      payloadSnippet: eventData.payloadSnippet,
    };

    this.state.events.unshift(newEvent);
    if (this.state.events.length > 500) {
      this.state.events = this.state.events.slice(0, 500);
    }
    this.saveState();
    return newEvent;
  }

  public updateEvent(id: number, updates: Partial<NetworkEvent>): boolean {
    const ev = this.state.events.find((e) => e.id === id);
    if (!ev) return false;
    Object.assign(ev, updates);
    this.saveState();
    return true;
  }

  // Incidents Table (Журнал угроз)
  public getIncidents(): SecurityIncident[] {
    return [...this.state.incidents].sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  public addIncident(incidentData: Omit<SecurityIncident, 'id' | 'timestamp'>): SecurityIncident {
    const nextId = this.state.incidents.length > 0 ? Math.max(...this.state.incidents.map((i) => i.id)) + 1 : 1;
    const newIncident: SecurityIncident = {
      id: nextId,
      timestamp: new Date().toISOString(),
      ...incidentData,
    };

    this.state.incidents.unshift(newIncident);

    // Auto-generate on-site notification for Critical / High incidents for Administrator
    if (newIncident.severity === 'Critical' || newIncident.severity === 'High') {
      const isCritical = newIncident.severity === 'Critical';
      this.addNotification({
        channel: 'IN_APP',
        recipient: 'Администратор SIEM',
        title: `${isCritical ? '🔴 КРИТИЧЕСКИЙ' : '🟠 ВЫСОКИЙ'} ИНЦИДЕНТ: ${newIncident.incidentType}`,
        message: `${newIncident.description} (Пользователь: ${newIncident.username || 'unknown'}, Источник: ${newIncident.sourceIp})`,
        severity: newIncident.severity,
      });
    }

    this.saveState();
    return newIncident;
  }

  // REST API Receiver simulation (/api/log with X-API-Key)
  public ingestApiLog(apiKey: string, payload: {
    ip: string;
    port?: number;
    eventType?: string;
    details: string;
    username?: string;
    protocol?: 'TCP' | 'UDP' | 'HTTP' | 'HTTPS';
  }): { success: boolean; status: number; message: string; event?: NetworkEvent } {
    const VALID_API_KEY = 'ut_secret_key_prod_2026';
    if (!apiKey || apiKey.trim() !== VALID_API_KEY) {
      return {
        success: false,
        status: 401,
        message: '401 Unauthorized: Неверный или отсутствующий заголовок X-API-Key.',
      };
    }

    const event = this.addEvent({
      username: payload.username || 'agent.py',
      ipAddress: payload.ip,
      eventType: 'API_LOG_INGEST',
      port: payload.port || 443,
      country: 'Локальная сеть',
      city: 'Удаленный хост сети',
      protocol: payload.protocol || 'HTTP',
      details: `[REST API Ingest] ${payload.details}`,
    });

    return {
      success: true,
      status: 200,
      message: '200 OK: Событие успешно принято в ядро UserTrack через REST API',
      event,
    };
  }

  public updateIncidentStatus(id: number, status: IncidentStatus): void {
    const incident = this.state.incidents.find((i) => i.id === id);
    if (incident) {
      incident.status = status;
      if (status === 'Resolved') {
        incident.resolvedAt = new Date().toISOString();
      }
      this.saveState();
    }
  }

  // Blocks Table (IPS Защита)
  public getBlocks(): IPBlock[] {
    const now = new Date().getTime();
    let changed = false;
    this.state.blocks.forEach((b) => {
      if (b.isActive && new Date(b.unlockTime).getTime() <= now) {
        b.isActive = false;
        changed = true;
      }
    });
    if (changed) {
      this.saveState();
    }
    return [...this.state.blocks].sort(
      (a, b) => new Date(b.blockedAt).getTime() - new Date(a.blockedAt).getTime()
    );
  }

  public isIpBlocked(ip: string): boolean {
    const now = new Date().getTime();
    return this.state.blocks.some((b) => b.ipAddress === ip && b.isActive && new Date(b.unlockTime).getTime() > now);
  }

  public applyBlock(ip: string, reason: string, durationMinutes: number = 3, threatActor?: string): IPBlock {
    const now = new Date();
    const unlockTime = new Date(now.getTime() + durationMinutes * 60 * 1000);

    const existing = this.state.blocks.find((b) => b.ipAddress === ip);
    if (existing) {
      existing.isActive = true;
      existing.reason = reason;
      existing.blockedAt = now.toISOString();
      existing.unlockTime = unlockTime.toISOString();
      existing.blockDurationMinutes = durationMinutes;
      if (threatActor) existing.threatActor = threatActor;
      this.saveState();
      return existing;
    }

    const nextId = this.state.blocks.length > 0 ? Math.max(...this.state.blocks.map((b) => b.id)) + 1 : 1;
    const newBlock: IPBlock = {
      id: nextId,
      ipAddress: ip,
      reason,
      blockedAt: now.toISOString(),
      unlockTime: unlockTime.toISOString(),
      isActive: true,
      blockDurationMinutes: durationMinutes,
      threatActor,
    };

    this.state.blocks.unshift(newBlock);
    this.saveState();
    return newBlock;
  }

  public unblockIp(ip: string): void {
    const block = this.state.blocks.find((b) => b.ipAddress === ip);
    if (block) {
      block.isActive = false;
      this.saveState();
    }
  }

  public countRecentFailedLogins(ip: string, windowMinutes: number = 5): number {
    const cutoff = new Date(Date.now() - windowMinutes * 60 * 1000).getTime();
    return this.state.events.filter(
      (e) => e.ipAddress === ip && e.eventType === 'AUTH_FAILURE' && new Date(e.timestamp).getTime() >= cutoff
    ).length;
  }

  // SQL Runner for Console
  public executeSql(sql: string): { columns: string[]; rows: (string | number | boolean | null)[][]; message?: string; error?: string } {
    const trimmed = sql.trim().replace(/;$/, '');
    const upper = trimmed.toUpperCase();

    try {
      if (!upper.startsWith('SELECT')) {
        if (upper.startsWith('INSERT') || upper.startsWith('UPDATE') || upper.startsWith('DELETE') || upper.startsWith('DROP')) {
          return {
            columns: ['status'],
            rows: [['Песочница работает в режиме безопасного чтения (Read-Only) для демонстрации данных usertrack.db']],
            message: 'Разрешены SELECT-запросы к базе данных SQLite.',
          };
        }
      }

      if (/SELECT\s+COUNT\(\*\)\s+FROM\s+events/i.test(trimmed)) {
        return {
          columns: ['COUNT(*)'],
          rows: [[this.state.events.length]],
          message: `В таблице events: ${this.state.events.length} записей`,
        };
      }

      if (/SELECT\s+COUNT\(\*\)\s+FROM\s+incidents/i.test(trimmed)) {
        return {
          columns: ['COUNT(*)'],
          rows: [[this.state.incidents.length]],
          message: `В таблице incidents: ${this.state.incidents.length} записей`,
        };
      }

      if (/SELECT\s+DISTINCT\s+ip_address\s+FROM\s+events/i.test(trimmed)) {
        const unique = Array.from(new Set(this.state.events.map((e) => e.ipAddress)));
        return {
          columns: ['ip_address'],
          rows: unique.map((ip) => [ip]),
          message: `Найдено ${unique.length} уникальных IP-адресов`,
        };
      }

      if (/SELECT\s+\*\s+FROM\s+users/i.test(trimmed)) {
        const cols = ['id', 'username', 'role', 'password_hash', 'created_at'];
        const rows = this.state.users.map((u) => [u.id, u.username, u.role, u.passwordHash.substring(0, 24) + '...', u.createdAt.substring(0, 10)]);
        return { columns: cols, rows, message: `${rows.length} строк(и) из таблицы users` };
      }

      if (/FROM\s+blocks/i.test(trimmed)) {
        let blocks = this.getBlocks();
        if (/WHERE\s+is_active\s*=\s*1/i.test(trimmed)) {
          blocks = blocks.filter((b) => b.isActive);
        }
        const cols = ['id', 'ip_address', 'reason', 'blocked_at', 'unlock_time', 'is_active', 'threat_actor'];
        const rows = blocks.map((b) => [
          b.id,
          b.ipAddress,
          b.reason,
          b.blockedAt.substring(11, 19),
          b.unlockTime.substring(11, 19),
          b.isActive ? 1 : 0,
          b.threatActor || 'UNKNOWN',
        ]);
        return { columns: cols, rows, message: `${rows.length} строк(и) из таблицы blocks (IPS)` };
      }

      if (/FROM\s+incidents/i.test(trimmed)) {
        let incidents = this.getIncidents();
        if (/WHERE\s+severity\s*=\s*'Critical'/i.test(trimmed)) {
          incidents = incidents.filter((i) => i.severity === 'Critical');
        } else if (/WHERE\s+severity\s*=\s*'High'/i.test(trimmed)) {
          incidents = incidents.filter((i) => i.severity === 'High');
        } else if (/WHERE\s+status\s*=\s*'Active'/i.test(trimmed)) {
          incidents = incidents.filter((i) => i.status === 'Active');
        }
        const cols = ['id', 'timestamp', 'incident_type', 'severity', 'source_ip', 'status', 'description'];
        const rows = incidents.map((i) => [
          i.id,
          i.timestamp.substring(11, 19),
          i.incidentType,
          i.severity,
          i.sourceIp,
          i.status,
          i.description,
        ]);
        return { columns: cols, rows, message: `${rows.length} инцидент(ов) из таблицы incidents` };
      }

      // Default: events table
      let events = this.getEvents();
      if (/WHERE\s+event_type\s*=\s*'AUTH_FAILURE'/i.test(trimmed)) {
        events = events.filter((e) => e.eventType === 'AUTH_FAILURE');
      } else if (/WHERE\s+event_type\s*=\s*'HONEYPOT_HIT'/i.test(trimmed)) {
        events = events.filter((e) => e.eventType === 'HONEYPOT_HIT');
      }

      const cols = ['id', 'timestamp', 'username', 'ip_address', 'event_type', 'port', 'country', 'details'];
      const rows = events.slice(0, 25).map((e) => [
        e.id,
        e.timestamp.substring(11, 19),
        e.username || '-',
        e.ipAddress,
        e.eventType,
        e.port,
        e.country,
        e.details,
      ]);
      return { columns: cols, rows, message: `${rows.length} строк из таблицы events (LIMIT 25)` };
    } catch (err: unknown) {
      return {
        columns: ['error'],
        rows: [[(err as Error).message || 'Синтаксическая ошибка SQL']],
        error: (err as Error).message,
      };
    }
  }
}

export const db = new DatabaseService();
