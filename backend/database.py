"""
UserTrack SQLite Database Engine (usertrack.db)
Реализация базы данных на чистом Python с использованием sqlite3.
Хранит таблицы: users, events, incidents, blocks, notifications.
"""

import sqlite3
import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

DB_FILE = os.path.join(os.path.dirname(__file__), 'usertrack.db')

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str, salt: str = "usertrack_salt") -> str:
    """Генерация безопасного хеша пароля PBKDF2-SHA256 (совместимо с Werkzeug/Python hashlib)"""
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return f"pbkdf2:sha256:100000${salt}${key.hex()}"

def init_db():
    """Создание таблиц SQLite по схеме schema.sql"""
    conn = get_db_connection()
    c = conn.cursor()

    # Таблица пользователей
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        password_plain TEXT,
        role TEXT CHECK(role IN ('admin', 'user')) NOT NULL DEFAULT 'user',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_login TEXT,
        known_ips TEXT DEFAULT '["192.168.1.10"]',
        full_name TEXT,
        is_chief_admin INTEGER DEFAULT 0
    )
    """)

    # Таблица событий безопасности (events)
    c.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        username TEXT,
        ip_address TEXT NOT NULL,
        event_type TEXT NOT NULL,
        port INTEGER DEFAULT 80,
        protocol TEXT DEFAULT 'TCP',
        country TEXT DEFAULT '',
        city TEXT DEFAULT '',
        details TEXT
    )
    """)

    # Таблица инцидентов (incidents)
    c.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        incident_type TEXT NOT NULL,
        severity TEXT CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')) NOT NULL,
        description TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        username TEXT,
        status TEXT CHECK(status IN ('Active', 'Investigating', 'Resolved')) DEFAULT 'Active',
        rule_triggered TEXT
    )
    """)

    # Таблица активных блокировок IPS (blocks)
    c.execute("""
    CREATE TABLE IF NOT EXISTS blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        reason TEXT NOT NULL,
        blocked_at TEXT DEFAULT CURRENT_TIMESTAMP,
        unlock_time TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        rule TEXT
    )
    """)

    # Таблица уведомлений безопасности (notifications)
    c.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        source_ip TEXT,
        severity TEXT DEFAULT 'warning',
        is_read INTEGER DEFAULT 0
    )
    """)

    # Индексы для ускорения поиска
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip_address)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_incidents_sev ON incidents(severity)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks(ip_address)")

    # Проверяем наличие главного администратора Артема
    c.execute("SELECT id FROM users WHERE username = 'artem'")
    admin = c.fetchone()
    if not admin:
        pwd_hash = hash_password('admin123', 'artem')
        c.execute("""
        INSERT INTO users (username, password_hash, password_plain, role, full_name, is_chief_admin, known_ips, created_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        """, (
            'artem',
            pwd_hash,
            'admin123',
            'admin',
            'Артем',
            json.dumps(['192.168.1.10']),
            datetime.utcnow().isoformat() + 'Z'
        ))

    conn.commit()
    conn.close()

# --- МЕТОДЫ ПОЛЬЗОВАТЕЛЕЙ ---

def get_users() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users ORDER BY id ASC")
    rows = c.fetchall()
    users = []
    for r in rows:
        known_ips = []
        try:
            known_ips = json.loads(r['known_ips']) if r['known_ips'] else []
        except Exception:
            known_ips = [r['known_ips']] if r['known_ips'] else []
        users.append({
            'id': r['id'],
            'username': r['username'],
            'passwordHash': r['password_hash'],
            'passwordPlain': r['password_plain'],
            'role': r['role'],
            'createdAt': r['created_at'],
            'lastLogin': r['last_login'],
            'knownIps': known_ips,
            'fullName': r['full_name'],
            'isChiefAdmin': bool(r['is_chief_admin'])
        })
    conn.close()
    return users

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username.strip(),))
    r = c.fetchone()
    conn.close()
    if not r:
        return None
    try:
        known_ips = json.loads(r['known_ips']) if r['known_ips'] else []
    except Exception:
        known_ips = []
    return {
        'id': r['id'],
        'username': r['username'],
        'passwordHash': r['password_hash'],
        'passwordPlain': r['password_plain'],
        'role': r['role'],
        'createdAt': r['created_at'],
        'lastLogin': r['last_login'],
        'knownIps': known_ips,
        'fullName': r['full_name'],
        'isChiefAdmin': bool(r['is_chief_admin'])
    }

def create_user(username: str, password_plain: str, role: str = 'user', full_name: str = '', initial_ip: str = '') -> Dict[str, Any]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (username.strip(),))
    if c.fetchone():
        conn.close()
        raise ValueError(f"Пользователь с логином '{username}' уже существует")

    known_ips = [initial_ip.strip()] if initial_ip and initial_ip.strip() else []
    pwd_hash = hash_password(password_plain, username.strip())
    now = datetime.utcnow().isoformat() + 'Z'

    c.execute("""
    INSERT INTO users (username, password_hash, password_plain, role, full_name, is_chief_admin, known_ips, created_at)
    VALUES (?, ?, ?, ?, ?, 0, ?, ?)
    """, (
        username.strip(),
        pwd_hash,
        password_plain,
        role,
        full_name.strip() or username.strip(),
        json.dumps(known_ips),
        now
    ))
    user_id = c.lastrowid
    conn.commit()
    conn.close()

    return {
        'id': user_id,
        'username': username.strip(),
        'passwordHash': pwd_hash,
        'passwordPlain': password_plain,
        'role': role,
        'createdAt': now,
        'lastLogin': None,
        'knownIps': known_ips,
        'fullName': full_name.strip() or username.strip(),
        'isChiefAdmin': False
    }

def update_user(user_id: int, updates: Dict[str, Any]) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    fields = []
    values = []

    if 'username' in updates:
        fields.append("username = ?")
        values.append(updates['username'].strip())
    if 'passwordPlain' in updates and updates['passwordPlain']:
        fields.append("password_plain = ?")
        values.append(updates['passwordPlain'])
        fields.append("password_hash = ?")
        values.append(hash_password(updates['passwordPlain'], updates.get('username', 'user')))
    if 'fullName' in updates:
        fields.append("full_name = ?")
        values.append(updates['fullName'])
    if 'knownIps' in updates:
        fields.append("known_ips = ?")
        values.append(json.dumps(updates['knownIps']))
    if 'lastLogin' in updates:
        fields.append("last_login = ?")
        values.append(updates['lastLogin'])
    if 'role' in updates:
        fields.append("role = ?")
        values.append(updates['role'])

    if not fields:
        conn.close()
        return False

    values.append(user_id)
    c.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", tuple(values))
    conn.commit()
    conn.close()
    return True

def delete_user(user_id: int) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    # Защита от удаления главного администратора Артема
    c.execute("SELECT is_chief_admin FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if row and row['is_chief_admin']:
        conn.close()
        raise ValueError("Главного администратора Артема нельзя удалить")

    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

# --- МЕТОДЫ СОБЫТИЙ (EVENTS) ---

def get_events(limit: int = 1000) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    events = []
    for r in rows:
        events.append({
            'id': r['id'],
            'timestamp': r['timestamp'],
            'username': r['username'],
            'ipAddress': r['ip_address'],
            'eventType': r['event_type'],
            'port': r['port'],
            'protocol': r['protocol'] or 'TCP',
            'country': r['country'] or '',
            'city': r['city'] or '',
            'details': r['details'] or ''
        })
    conn.close()
    return events

def add_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    c = conn.cursor()
    now = datetime.utcnow().isoformat() + 'Z'
    c.execute("""
    INSERT INTO events (timestamp, username, ip_address, event_type, port, protocol, country, city, details)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_data.get('timestamp') or now,
        event_data.get('username') or 'Неизвестный',
        event_data.get('ipAddress') or '127.0.0.1',
        event_data.get('eventType') or 'PORT_SCAN',
        int(event_data.get('port') or 80),
        event_data.get('protocol') or 'TCP',
        event_data.get('country') or '',
        event_data.get('city') or '',
        event_data.get('details') or ''
    ))
    ev_id = c.lastrowid
    conn.commit()
    conn.close()

    return {
        'id': ev_id,
        'timestamp': event_data.get('timestamp') or now,
        'username': event_data.get('username') or 'Неизвестный',
        'ipAddress': event_data.get('ipAddress') or '127.0.0.1',
        'eventType': event_data.get('eventType') or 'PORT_SCAN',
        'port': int(event_data.get('port') or 80),
        'protocol': event_data.get('protocol') or 'TCP',
        'country': event_data.get('country') or '',
        'city': event_data.get('city') or '',
        'details': event_data.get('details') or ''
    }

def update_event_geo(event_id: int, country: str, city: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE events SET country = ?, city = ? WHERE id = ?", (country, city, event_id))
    conn.commit()
    conn.close()

def count_recent_failed_logins(ip: str, minutes: int = 5) -> int:
    conn = get_db_connection()
    c = conn.cursor()
    time_limit = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
    c.execute("""
    SELECT COUNT(*) as cnt FROM events
    WHERE ip_address = ? AND event_type = 'AUTH_FAILURE' AND timestamp >= ?
    """, (ip, time_limit))
    res = c.fetchone()
    conn.close()
    return res['cnt'] if res else 0

# --- МЕТОДЫ ИНЦИДЕНТОВ (INCIDENTS) ---

def get_incidents() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM incidents ORDER BY id DESC")
    rows = c.fetchall()
    incidents = []
    for r in rows:
        incidents.append({
            'id': r['id'],
            'timestamp': r['timestamp'],
            'incidentType': r['incident_type'],
            'severity': r['severity'],
            'description': r['description'],
            'sourceIp': r['source_ip'],
            'username': r['username'] or '',
            'status': r['status'],
            'ruleTriggered': r['rule_triggered'] or ''
        })
    conn.close()
    return incidents

def add_incident(data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    c = conn.cursor()
    now = datetime.utcnow().isoformat() + 'Z'
    c.execute("""
    INSERT INTO incidents (timestamp, incident_type, severity, description, source_ip, username, status, rule_triggered)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get('timestamp') or now,
        data.get('incidentType') or 'ANOMALY',
        data.get('severity') or 'Medium',
        data.get('description') or '',
        data.get('sourceIp') or '127.0.0.1',
        data.get('username') or '',
        data.get('status') or 'Active',
        data.get('ruleTriggered') or ''
    ))
    inc_id = c.lastrowid
    conn.commit()
    conn.close()

    # Также отправляем уведомление администратору
    add_notification(
        title=f"Инцидент: {data.get('incidentType')}",
        message=data.get('description') or '',
        source_ip=data.get('sourceIp') or '',
        severity='critical' if data.get('severity') == 'Critical' else 'warning'
    )

    return {
        'id': inc_id,
        'timestamp': data.get('timestamp') or now,
        'incidentType': data.get('incidentType') or 'ANOMALY',
        'severity': data.get('severity') or 'Medium',
        'description': data.get('description') or '',
        'sourceIp': data.get('sourceIp') or '127.0.0.1',
        'username': data.get('username') or '',
        'status': data.get('status') or 'Active',
        'ruleTriggered': data.get('ruleTriggered') or ''
    }

def update_incident_status(incident_id: int, status: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE incidents SET status = ? WHERE id = ?", (status, incident_id))
    updated = c.rowcount > 0
    conn.commit()
    conn.close()
    return updated

# --- МЕТОДЫ IPS БЛОКИРОВОК (BLOCKS) ---

def get_blocks() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    c = conn.cursor()
    # Автоматически деактивируем просроченные блокировки
    now_iso = datetime.utcnow().isoformat() + 'Z'
    c.execute("UPDATE blocks SET is_active = 0 WHERE is_active = 1 AND unlock_time <= ?", (now_iso,))
    conn.commit()

    c.execute("SELECT * FROM blocks ORDER BY id DESC")
    rows = c.fetchall()
    blocks = []
    for r in rows:
        blocks.append({
            'id': r['id'],
            'ipAddress': r['ip_address'],
            'reason': r['reason'],
            'blockedAt': r['blocked_at'],
            'unlockTime': r['unlock_time'],
            'isActive': bool(r['is_active']),
            'rule': r['rule'] or ''
        })
    conn.close()
    return blocks

def is_ip_blocked(ip: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    now_iso = datetime.utcnow().isoformat() + 'Z'
    c.execute("""
    SELECT id FROM blocks
    WHERE ip_address = ? AND is_active = 1 AND unlock_time > ?
    """, (ip, now_iso))
    row = c.fetchone()
    conn.close()
    return row is not None

def apply_block(ip: str, reason: str, duration_minutes: int = 3, rule: str = 'MANUAL_BLOCK') -> Dict[str, Any]:
    conn = get_db_connection()
    c = conn.cursor()
    now = datetime.utcnow()
    unlock_time = (now + timedelta(minutes=duration_minutes)).isoformat() + 'Z'
    now_iso = now.isoformat() + 'Z'

    c.execute("SELECT id FROM blocks WHERE ip_address = ?", (ip,))
    existing = c.fetchone()
    if existing:
        c.execute("""
        UPDATE blocks
        SET reason = ?, blocked_at = ?, unlock_time = ?, is_active = 1, rule = ?
        WHERE id = ?
        """, (reason, now_iso, unlock_time, rule, existing['id']))
        block_id = existing['id']
    else:
        c.execute("""
        INSERT INTO blocks (ip_address, reason, blocked_at, unlock_time, is_active, rule)
        VALUES (?, ?, ?, ?, 1, ?)
        """, (ip, reason, now_iso, unlock_time, rule))
        block_id = c.lastrowid

    conn.commit()
    conn.close()

    add_notification(
        title=f"IPS Блокировка: {ip}",
        message=f"{reason} (срок: {duration_minutes} мин)",
        source_ip=ip,
        severity='critical'
    )

    return {
        'id': block_id,
        'ipAddress': ip,
        'reason': reason,
        'blockedAt': now_iso,
        'unlockTime': unlock_time,
        'isActive': True,
        'rule': rule
    }

def remove_block(block_id_or_ip: Any) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    if isinstance(block_id_or_ip, int) or (isinstance(block_id_or_ip, str) and block_id_or_ip.isdigit()):
        c.execute("UPDATE blocks SET is_active = 0 WHERE id = ?", (int(block_id_or_ip),))
    else:
        c.execute("UPDATE blocks SET is_active = 0 WHERE ip_address = ?", (str(block_id_or_ip),))
    updated = c.rowcount > 0
    conn.commit()
    conn.close()
    return updated

# --- УВЕДОМЛЕНИЯ (NOTIFICATIONS) ---

def get_notifications() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM notifications ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    notifs = []
    for r in rows:
        notifs.append({
            'id': r['id'],
            'timestamp': r['timestamp'],
            'title': r['title'],
            'message': r['message'],
            'sourceIp': r['source_ip'] or '',
            'severity': r['severity'],
            'isRead': bool(r['is_read'])
        })
    conn.close()
    return notifs

def add_notification(title: str, message: str, source_ip: str = '', severity: str = 'warning') -> Dict[str, Any]:
    conn = get_db_connection()
    c = conn.cursor()
    now = datetime.utcnow().isoformat() + 'Z'
    c.execute("""
    INSERT INTO notifications (timestamp, title, message, source_ip, severity, is_read)
    VALUES (?, ?, ?, ?, ?, 0)
    """, (now, title, message, source_ip, severity))
    n_id = c.lastrowid
    conn.commit()
    conn.close()
    return {
        'id': n_id,
        'timestamp': now,
        'title': title,
        'message': message,
        'sourceIp': source_ip,
        'severity': severity,
        'isRead': False
    }

def clear_notifications():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM notifications")
    conn.commit()
    conn.close()

# --- ОЧИСТКА И ЗАПОЛНЕНИЕ ДЕМО-ДАННЫМИ ---

def clear_database_records():
    """Полная очистка событий, инцидентов и блокировок (пользователи сохраняются)"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM events")
    c.execute("DELETE FROM incidents")
    c.execute("DELETE FROM blocks")
    c.execute("DELETE FROM notifications")
    conn.commit()
    conn.close()

def seed_demo_data():
    """Заполнение демонстрационными событиями для презентации работы UEBA и IPS"""
    clear_database_records()

    now = datetime.utcnow()

    # Создаем серию событий
    demo_events = [
        ('artem', '192.168.1.10', 'AUTH_SUCCESS', 443, 'TCP', 'Россия', 'Москва', 'Успешный вход системного администратора в консоль SIEM', -180),
        ('artem', '192.168.1.10', 'AUTH_SUCCESS', 443, 'TCP', 'Россия', 'Москва', 'Запрос дашборда и статистики IPS', -120),
        ('unknown_bot', '185.220.101.5', 'PORT_SCAN', 22, 'TCP', 'Германия', 'Франкфурт', 'Сканирование закрытого порта SSH', -90),
        ('unknown_bot', '185.220.101.5', 'PORT_SCAN', 3389, 'TCP', 'Германия', 'Франкфурт', 'Попытка зондирования службы удаленного рабочего стола RDP', -85),
        ('unknown_bot', '185.220.101.5', 'HONEYPOT_HIT', 80, 'TCP', 'Германия', 'Франкфурт', 'Сработал Honeypot-маршрутизатор: обращение к /.env', -80),
        ('ivan', '95.24.12.88', 'AUTH_SUCCESS', 443, 'TCP', 'Россия', 'Санкт-Петербург', 'Обычный пользовательский вход в рабочую систему', -50),
        ('ivan', '95.24.12.88', 'AUTH_SUCCESS', 443, 'TCP', 'Россия', 'Санкт-Петербург', 'Просмотр журнала личной активности', -30),
        ('hacker_brute', '45.154.255.89', 'AUTH_FAILURE', 443, 'TCP', 'Нидерланды', 'Амстердам', 'Неудачная попытка подбора пароля (попытка 1/5)', -10),
        ('hacker_brute', '45.154.255.89', 'AUTH_FAILURE', 443, 'TCP', 'Нидерланды', 'Амстердам', 'Неудачная попытка подбора пароля (попытка 2/5)', -9),
        ('hacker_brute', '45.154.255.89', 'AUTH_FAILURE', 443, 'TCP', 'Нидерланды', 'Амстердам', 'Неудачная попытка подбора пароля (попытка 3/5)', -8),
        ('hacker_brute', '45.154.255.89', 'AUTH_FAILURE', 443, 'TCP', 'Нидерланды', 'Амстердам', 'Неудачная попытка подбора пароля (попытка 4/5)', -7),
        ('hacker_brute', '45.154.255.89', 'AUTH_FAILURE', 443, 'TCP', 'Нидерланды', 'Амстердам', 'Неудачная попытка подбора пароля (попытка 5/5) — сработала блокировка IPS', -6),
    ]

    for username, ip, ev_type, port, proto, country, city, details, offset_min in demo_events:
        ts = (now + timedelta(minutes=offset_min)).isoformat() + 'Z'
        add_event({
            'timestamp': ts,
            'username': username,
            'ipAddress': ip,
            'eventType': ev_type,
            'port': port,
            'protocol': proto,
            'country': country,
            'city': city,
            'details': details
        })

    # Добавляем инциденты
    add_incident({
        'timestamp': (now - timedelta(minutes=80)).isoformat() + 'Z',
        'incidentType': 'HONEYPOT_ACCESS',
        'severity': 'Critical',
        'description': 'Обнаружен вредоносный краулер: попытка доступа к скрытой ловушке /.env со стороны 185.220.101.5',
        'sourceIp': '185.220.101.5',
        'username': 'unknown_bot',
        'status': 'Active',
        'ruleTriggered': 'RULE-HONEYPOT-ENV'
    })

    add_incident({
        'timestamp': (now - timedelta(minutes=6)).isoformat() + 'Z',
        'incidentType': 'BRUTE_FORCE',
        'severity': 'Critical',
        'description': 'Серия из 5 последовательных неудачных авторизаций с IP 45.154.255.89. Превышен лимит UEBA.',
        'sourceIp': '45.154.255.89',
        'username': 'hacker_brute',
        'status': 'Active',
        'ruleTriggered': 'RULE-BF-5MIN-THRESHOLD-5'
    })

    # Добавляем блокировки
    apply_block('185.220.101.5', 'Срабатывание Honeypot ловушки (доступ к конфигурационным файлам)', 10, 'HACKER_BOT')
    apply_block('45.154.255.89', 'Обнаружена атака Brute Force (5 ошибок авторизации за 5 минут)', 3, 'BRUTE_FORCE_BOT')

# Инициализируем БД при загрузке модуля
init_db()
