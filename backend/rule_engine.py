"""
UserTrack Analytical Core & UEBA / IPS Rule Engine (Python)
Ядро поведенческого анализа и модуль превентивных блокировок на чистом Python.
"""

from datetime import datetime
from typing import Dict, Any, Optional
from . import database as db
from . import geo_service

HONEYPOT_PATHS = [
    {"path": "/wp-login.php", "desc": "Фальшивая панель входа WordPress"},
    {"path": "/.env", "desc": "Утечка файлов конфигурации и секретов"},
    {"path": "/admin-panel-secret.php", "desc": "Скрытый административный бэкдор"},
    {"path": "/phpmyadmin", "desc": "Интерфейс управления базами данных"},
    {"path": "/api/v1/debug", "desc": "Неавторизованный отладочный endpoint"},
]

class RuleEngine:
    """Ядро правил безопасности UserTrack"""

    @staticmethod
    def handle_auth_attempt(
        ip: str,
        username: str,
        is_success: bool,
        simulated_hour: Optional[int] = None,
        geo_override: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Обработка попытки авторизации пользователя:
        1. Проверка активного бана в таблице blocks (IPS).
        2. При ошибке: фиксация AUTH_FAILURE, подсчет за 5 минут. При >= 5 ошибках — автобан на 3 мин.
        3. При успехе: фиксация AUTH_SUCCESS, проверка ночного входа (02:00-05:00), проверка нового IP (UEBA).
        """
        geo = geo_override or geo_service.get_quick_geo(ip)

        # 1. Проверка IPS черного списка
        if db.is_ip_blocked(ip):
            blocked_event = db.add_event({
                'username': username,
                'ipAddress': ip,
                'eventType': 'SUSPICIOUS_PROBE',
                'port': 443,
                'protocol': 'TCP',
                'country': geo.get('country', ''),
                'city': geo.get('city', ''),
                'details': f"[IPS DROP] Запрос отклонён: IP {ip} находится в активном черном списке блокировок"
            })

            return {
                'allowed': False,
                'blockedReason': f"IP-адрес {ip} заблокирован системой IPS. Доступ запрещен до истечения таймаута.",
                'event': blocked_event,
                'incident': None
            }

        # 2. Неудачная авторизация
        if not is_success:
            fail_event = db.add_event({
                'username': username,
                'ipAddress': ip,
                'eventType': 'AUTH_FAILURE',
                'port': 443,
                'protocol': 'TCP',
                'country': geo.get('country', ''),
                'city': geo.get('city', ''),
                'details': f"Неудачная попытка входа для пользователя '{username}' (неверный пароль)"
            })

            fail_count = db.count_recent_failed_logins(ip, minutes=5)

            if fail_count >= 5:
                # На 5-й ошибке активируем блокировку на 3 минуты
                db.apply_block(ip, f"Обнаружена Brute Force атака ({fail_count} ошибок за 5 минут)", duration_minutes=3, rule='BRUTE_FORCE_BOT')
                incident = db.add_incident({
                    'incidentType': 'BRUTE_FORCE',
                    'severity': 'Critical',
                    'description': f"Зафиксирована серия из {fail_count} неудачных авторизаций с IP {ip}. Модуль IPS заблокировал адрес на 3 минуты.",
                    'sourceIp': ip,
                    'username': username,
                    'status': 'Active',
                    'ruleTriggered': 'RULE-BF-5MIN-THRESHOLD-5'
                })

                return {
                    'allowed': False,
                    'blockedReason': f"Превышен лимит попыток входа ({fail_count} ошибок). Ваш IP {ip} автоматически заблокирован на 3 минуты модулем IPS!",
                    'event': fail_event,
                    'incident': incident
                }

            return {
                'allowed': False,
                'blockedReason': f"Неверный пароль. Попытка {fail_count} из 5.",
                'event': fail_event,
                'incident': None
            }

        # 3. Успешная авторизация (AUTH_SUCCESS)
        success_event = db.add_event({
            'username': username,
            'ipAddress': ip,
            'eventType': 'AUTH_SUCCESS',
            'port': 443,
            'protocol': 'TCP',
            'country': geo.get('country', ''),
            'city': geo.get('city', ''),
            'details': f"Успешный вход пользователя '{username}' в систему"
        })

        # Обновляем last_login пользователя в БД
        user = db.get_user_by_username(username)
        if user:
            db.update_user(user['id'], {'lastLogin': datetime.utcnow().isoformat() + 'Z'})

        incidents_created = []

        # Поведенческий анализ времени (UEBA: 02:00 - 05:00)
        hour = simulated_hour if simulated_hour is not None else datetime.now().hour
        if 2 <= hour <= 5:
            inc = db.add_incident({
                'incidentType': 'TIME_ANOMALY',
                'severity': 'Medium',
                'description': f"Поведенческая аномалия: Вход пользователя '{username}' зафиксирован в ночное нерабочее время ({hour}:15). Возможна работа бота или компрометация учетной записи.",
                'sourceIp': ip,
                'username': username,
                'status': 'Active',
                'ruleTriggered': 'RULE-TIME-NIGHT-LOGIN'
            })
            incidents_created.append(inc)

        # Поведенческий анализ геолокации и нового IP (UEBA Geo Anomaly)
        if user:
            known = user.get('knownIps', [])
            if ip not in known:
                country_name = geo.get('country', '')
                is_foreign = country_name and country_name not in ['Россия', 'Russian Federation', 'Локальная сеть (Loopback)', 'Корпоративная сеть (LAN)', '']
                severity = 'High' if is_foreign else 'Low'
                geo_desc = f"Вход с нового сетевого адреса {ip} ({geo.get('city', '')} {country_name})"
                if is_foreign:
                    geo_desc += f" — ВНИМАНИЕ: подключение из зарубежной локации ({country_name})!"

                inc = db.add_incident({
                    'incidentType': 'GEO_ANOMALY',
                    'severity': severity,
                    'description': f"Географическая аномалия: Пользователь '{username}'. {geo_desc}",
                    'sourceIp': ip,
                    'username': username,
                    'status': 'Active',
                    'ruleTriggered': 'RULE-GEO-UNRECOGNIZED-IP'
                })
                incidents_created.append(inc)

                # Добавляем IP в список доверенных
                updated_known = list(known) + [ip]
                db.update_user(user['id'], {'knownIps': updated_known})

        return {
            'allowed': True,
            'event': success_event,
            'incident': incidents_created[0] if incidents_created else None
        }

    @staticmethod
    def handle_honeypot_trap(path: str, ip: str, username: str = 'scanner_bot') -> Dict[str, Any]:
        """Срабатывание ловушки honeypot (краулер, сканирование секретов)"""
        geo = geo_service.get_quick_geo(ip)

        event = db.add_event({
            'username': username,
            'ipAddress': ip,
            'eventType': 'HONEYPOT_HIT',
            'port': 80,
            'protocol': 'HTTP',
            'country': geo.get('country', ''),
            'city': geo.get('city', ''),
            'details': f"[HONEYPOT TRIGGERED] Попытка несанкционированного доступа к скрытому маршруту: {path}"
        })

        # Мгновенная блокировка IPS на 10 минут
        block = db.apply_block(ip, f"Срабатывание Honeypot ловушки ({path})", duration_minutes=10, rule='HACKER_BOT')

        incident = db.add_incident({
            'incidentType': 'HONEYPOT_ACCESS',
            'severity': 'Critical',
            'description': f"Автоматическая реакция IPS: адрес {ip} обратился к защищенной ловушке {path}. Наложена немедленная блокировка на 10 минут.",
            'sourceIp': ip,
            'username': username,
            'status': 'Active',
            'ruleTriggered': 'RULE-HONEYPOT-ROUTER-TRAP'
        })

        return {
            'event': event,
            'block': block,
            'incident': incident
        }

    @staticmethod
    def handle_port_scan_probe(port: int, ip: str, username: str = 'network_probe') -> Dict[str, Any]:
        """Обработка сканирования портов и сигнатурного анализа"""
        geo = geo_service.get_quick_geo(ip)

        is_critical_port = port in [22, 23, 3389, 3306, 1433, 5432]
        port_names = {22: 'SSH', 23: 'Telnet', 3389: 'RDP', 3306: 'MySQL', 1433: 'MSSQL', 5432: 'PostgreSQL'}
        port_name = port_names.get(port, f"Port {port}")

        event = db.add_event({
            'username': username,
            'ipAddress': ip,
            'eventType': 'PORT_SCAN',
            'port': port,
            'protocol': 'TCP',
            'country': geo.get('country', ''),
            'city': geo.get('city', ''),
            'details': f"Сканирование сетевого порта {port} ({port_name})"
        })

        incident = None
        if is_critical_port:
            incident = db.add_incident({
                'incidentType': 'PORT_SCAN',
                'severity': 'High',
                'description': f"Обнаружено сканирование критического сервиса {port_name} (порт {port}) со стороны {ip}.",
                'sourceIp': ip,
                'username': username,
                'status': 'Active',
                'ruleTriggered': f"RULE-PORT-SCAN-{port}"
            })

        return {
            'event': event,
            'incident': incident
        }
