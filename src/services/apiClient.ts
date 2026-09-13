/**
 * UserTrack Python API Client
 * Связывает клиентский интерфейс React с бэкендом на Python (backend/app.py)
 */

import { User, NetworkEvent, SecurityIncident, IPBlock, SecurityAlertNotification } from '../types';

export interface PythonBackendStatus {
  status: string;
  engine: string;
  framework: string;
  database: string;
  modules: {
    database: string;
    rule_engine: string;
    geo_service: string;
    analytics: string;
  };
}

export const pythonApi = {
  /** Проверка статуса ядра Python */
  async getStatus(): Promise<PythonBackendStatus | null> {
    try {
      const res = await fetch('/api/status');
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  /** Загрузка пользователей из SQLite через Python */
  async getUsers(): Promise<User[]> {
    try {
      const res = await fetch('/api/users');
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  /** Создание пользователя в SQLite */
  async createUser(payload: { username: string; password: string; role?: string; fullName?: string; ip?: string }): Promise<User | null> {
    try {
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  /** Обновление пользователя */
  async updateUser(userId: number, updates: Partial<User>): Promise<boolean> {
    try {
      const res = await fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      });
      return res.ok;
    } catch {
      return false;
    }
  },

  /** Удаление пользователя */
  async deleteUser(userId: number): Promise<boolean> {
    try {
      const res = await fetch(`/api/users/${userId}`, {
        method: 'DELETE',
      });
      return res.ok;
    } catch {
      return false;
    }
  },

  /** Получение событий из SQLite через Python */
  async getEvents(limit = 1000): Promise<NetworkEvent[]> {
    try {
      const res = await fetch(`/api/events?limit=${limit}`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  /** Добавление события */
  async addEvent(event: Partial<NetworkEvent>): Promise<NetworkEvent | null> {
    try {
      const res = await fetch('/api/events', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  /** Получение инцидентов */
  async getIncidents(): Promise<SecurityIncident[]> {
    try {
      const res = await fetch('/api/incidents');
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  /** Добавление инцидента */
  async addIncident(incident: Partial<SecurityIncident>): Promise<SecurityIncident | null> {
    try {
      const res = await fetch('/api/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(incident),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  /** Получение активных блокировок */
  async getBlocks(): Promise<IPBlock[]> {
    try {
      const res = await fetch('/api/blocks');
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  /** Добавление блокировки */
  async applyBlock(ip: string, reason: string, durationMinutes = 60, rule = 'MANUAL_OPERATOR_BLOCK'): Promise<IPBlock | null> {
    try {
      const res = await fetch('/api/blocks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ipAddress: ip, reason, durationMinutes, rule }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  /** Снятие блокировки */
  async removeBlock(blockIdOrIp: string | number): Promise<boolean> {
    try {
      const res = await fetch(`/api/blocks/${blockIdOrIp}`, {
        method: 'DELETE',
      });
      return res.ok;
    } catch {
      return false;
    }
  },

  /** Получение уведомлений */
  async getNotifications(): Promise<SecurityAlertNotification[]> {
    try {
      const res = await fetch('/api/notifications');
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  /** Вычисление попытки входа в Python UEBA Rule Engine */
  async evaluateAuth(params: {
    ip: string;
    username: string;
    isSuccess: boolean;
    simulatedHour?: number;
    geoOverride?: any;
  }): Promise<{ allowed: boolean; blockedReason?: string; event: NetworkEvent; incident?: SecurityIncident }> {
    const res = await fetch('/api/auth/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    return await res.json();
  },

  /** Срабатывание ловушки Honeypot в Python */
  async evaluateHoneypot(path: string, ip: string, username = 'scanner_bot'): Promise<any> {
    const res = await fetch('/api/honeypot/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, ip, username }),
    });
    return await res.json();
  },

  /** Сигнатурный анализ сканирования порта в Python */
  async evaluateProbe(port: number, ip: string, username = 'probe_scanner'): Promise<any> {
    const res = await fetch('/api/probe/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ port, ip, username }),
    });
    return await res.json();
  },

  /** Получение аналитики SIEM и Threat Score из Python */
  async getAnalytics(): Promise<any> {
    try {
      const res = await fetch('/api/analytics');
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  /** Заполнение демо-данными в SQLite */
  async seedDemo(): Promise<boolean> {
    try {
      const res = await fetch('/api/demo/seed', { method: 'POST' });
      return res.ok;
    } catch {
      return false;
    }
  },

  /** Очистка БД */
  async clearDb(): Promise<boolean> {
    try {
      const res = await fetch('/api/db/clear', { method: 'POST' });
      return res.ok;
    } catch {
      return false;
    }
  },

  /** Запуск диагностической команды Python */
  async runCli(command: string): Promise<string> {
    try {
      const res = await fetch('/api/cli/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command }),
      });
      const data = await res.json();
      return data.output || '';
    } catch (e: any) {
      return `Ошибка связи с Python CLI: ${e.message}`;
    }
  },
};
