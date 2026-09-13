"""
UserTrack Python REST API Microservice (app.py)
Полнофункциональный HTTP сервер на базе стандартной библиотеки Python http.server.
Предоставляет REST API для всех подсистем SIEM, UEBA, базы данных SQLite и IPS.
"""

import sys
import os
import json
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any

# Добавляем родительскую директорию в PYTHONPATH для корректных импортов
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend import database as db
from backend.rule_engine import RuleEngine, HONEYPOT_PATHS
from backend import geo_service
from backend import analytics

class UserTrackAPIHandler(BaseHTTPRequestHandler):
    """Обработчик HTTP запросов к API на чистом Python"""

    def _set_headers(self, status: int = 200, content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_OPTIONS(self):
        """Обработка CORS pre-flight запросов"""
        self._set_headers(204)

    def _send_json(self, data: Any, status: int = 200):
        self._set_headers(status, "application/json")
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))

    def _parse_body(self) -> Dict[str, Any]:
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}
        raw = self.rfile.read(content_length).decode('utf-8')
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Health & System Status
        if path in ['/api/status', '/api/health']:
            self._send_json({
                "status": "ok",
                "engine": f"Python {sys.version.split()[0]}",
                "framework": "UserTrack Native Python Core",
                "database": "SQLite 3 (usertrack.db)",
                "modules": {
                    "database": "backend.database (Active)",
                    "rule_engine": "backend.rule_engine (UEBA Active)",
                    "geo_service": "backend.geo_service (ipaddress stdlib)",
                    "analytics": "backend.analytics (Active)"
                }
            })
            return

        # 2. Users
        if path == '/api/users':
            users = db.get_users()
            self._send_json(users)
            return

        # 3. Events
        if path == '/api/events':
            limit = int(query.get('limit', [1000])[0])
            events = db.get_events(limit=limit)
            self._send_json(events)
            return

        # 4. Incidents
        if path == '/api/incidents':
            incidents = db.get_incidents()
            self._send_json(incidents)
            return

        # 5. IPS Blocks
        if path == '/api/blocks':
            blocks = db.get_blocks()
            self._send_json(blocks)
            return

        # 6. Notifications
        if path == '/api/notifications':
            notifs = db.get_notifications()
            self._send_json(notifs)
            return

        # 7. Geo Lookup
        if path == '/api/geo/lookup':
            ip = query.get('ip', [''])[0]
            geo = geo_service.lookup_online_geo(ip)
            self._send_json(geo)
            return

        # 8. SIEM Analytics & Threat Metrics
        if path == '/api/analytics':
            metrics = analytics.calculate_threat_metrics()
            self._send_json(metrics)
            return

        # 9. Honeypot paths info
        if path == '/api/honeypot/traps':
            self._send_json(HONEYPOT_PATHS)
            return

        self._send_json({"error": "Endpoint not found", "path": path}, status=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._parse_body()

        # 1. Полноценная оценка попытки авторизации (UEBA + IPS) на Python
        if path == '/api/auth/evaluate':
            ip = body.get('ip', '127.0.0.1')
            username = body.get('username', '')
            is_success = bool(body.get('isSuccess', False))
            simulated_hour = body.get('simulatedHour')
            geo_override = body.get('geoOverride')

            result = RuleEngine.handle_auth_attempt(
                ip=ip,
                username=username,
                is_success=is_success,
                simulated_hour=simulated_hour,
                geo_override=geo_override
            )
            self._send_json(result)
            return

        # 2. Ловушка Honeypot
        if path == '/api/honeypot/evaluate':
            trap_path = body.get('path', '/.env')
            ip = body.get('ip', '127.0.0.1')
            username = body.get('username', 'scanner_bot')
            res = RuleEngine.handle_honeypot_trap(path=trap_path, ip=ip, username=username)
            self._send_json(res)
            return

        # 3. Сканирование портов
        if path == '/api/probe/evaluate':
            port = int(body.get('port', 80))
            ip = body.get('ip', '127.0.0.1')
            username = body.get('username', 'probe_scanner')
            res = RuleEngine.handle_port_scan_probe(port=port, ip=ip, username=username)
            self._send_json(res)
            return

        # 4. Добавление пользователя
        if path == '/api/users':
            try:
                created = db.create_user(
                    username=body.get('username', ''),
                    password_plain=body.get('password', ''),
                    role=body.get('role', 'user'),
                    full_name=body.get('fullName', ''),
                    initial_ip=body.get('ip', '')
                )
                self._send_json(created, status=201)
            except ValueError as ve:
                self._send_json({"error": str(ve)}, status=400)
            return

        # 5. Добавление сетевого события
        if path == '/api/events':
            ev = db.add_event(body)
            self._send_json(ev, status=201)
            return

        # 6. Добавление инцидента
        if path == '/api/incidents':
            inc = db.add_incident(body)
            self._send_json(inc, status=201)
            return

        # 7. Добавление IPS блокировки
        if path == '/api/blocks':
            ip = body.get('ipAddress', '')
            reason = body.get('reason', 'Ручная блокировка оператором')
            duration = int(body.get('durationMinutes', 60))
            rule = body.get('rule', 'MANUAL_OPERATOR_BLOCK')
            blk = db.apply_block(ip, reason, duration, rule)
            self._send_json(blk, status=201)
            return

        # 8. Заполнение демо-данными
        if path == '/api/demo/seed':
            db.seed_demo_data()
            self._send_json({"success": True, "message": "Демо-данные успешно записаны в SQLite через Python"})
            return

        # 9. Очистка БД
        if path == '/api/db/clear':
            db.clear_database_records()
            self._send_json({"success": True, "message": "Журналы и инциденты очищены из SQLite"})
            return

        # 10. Запуск Python CLI диагностики
        if path == '/api/cli/execute':
            cmd = body.get('command', 'status')
            output = run_cli_diagnostic(cmd)
            self._send_json({"command": cmd, "output": output})
            return

        self._send_json({"error": "Endpoint not found", "path": path}, status=404)

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._parse_body()

        # Обновление пользователя /api/users/{id}
        if path.startswith('/api/users/'):
            try:
                user_id = int(path.split('/')[-1])
                updated = db.update_user(user_id, body)
                self._send_json({"success": updated})
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
            return

        # Обновление статуса инцидента /api/incidents/{id}
        if path.startswith('/api/incidents/'):
            try:
                inc_id = int(path.split('/')[-1])
                status = body.get('status', 'Resolved')
                updated = db.update_incident_status(inc_id, status)
                self._send_json({"success": updated})
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
            return

        self._send_json({"error": "Endpoint not found", "path": path}, status=404)

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Удаление пользователя /api/users/{id}
        if path.startswith('/api/users/'):
            try:
                user_id = int(path.split('/')[-1])
                deleted = db.delete_user(user_id)
                self._send_json({"success": deleted})
            except ValueError as ve:
                self._send_json({"error": str(ve)}, status=400)
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
            return

        # Разблокировка IP /api/blocks/{id}
        if path.startswith('/api/blocks/'):
            block_id = path.split('/')[-1]
            removed = db.remove_block(block_id)
            self._send_json({"success": removed})
            return

        self._send_json({"error": "Endpoint not found", "path": path}, status=404)

    def log_message(self, format, *args):
        """Кастомный логгер без засорения консоли"""
        sys.stderr.write(f"[UserTrack Python API] {self.address_string()} - {format % args}\n")

def run_cli_diagnostic(cmd: str) -> str:
    """Выполнение внутренней проверки системы на Python"""
    if cmd == 'status':
        metrics = analytics.calculate_threat_metrics()
        users = db.get_users()
        return (
            f"=== СИСТЕМА ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ USERTRACK ===\n"
            f"Ядро: Python {sys.version.split()[0]} | База: SQLite3 (usertrack.db)\n"
            f"Индекс угрозы системы (Threat Score): {metrics['threatScore']}/100 ({metrics['threatLevel']})\n"
            f"Пользователей в системе: {len(users)}\n"
            f"Всего событий в базе: {metrics['totalEventsCount']}\n"
            f"Активных инцидентов: {metrics['activeIncidents']} (Критич: {metrics['criticalCount']})\n"
            f"Активных блокировок IPS: {metrics['activeBlocksCount']}\n"
            f"UEBA модули: BruteForce Detector, Night Activity, Geo Anomaly, Honeypot Trap — АКТИВНЫ"
        )
    elif cmd == 'test_brute_force':
        ip = '198.51.100.77'
        RuleEngine.handle_auth_attempt(ip, 'test_hacker', False)
        RuleEngine.handle_auth_attempt(ip, 'test_hacker', False)
        RuleEngine.handle_auth_attempt(ip, 'test_hacker', False)
        RuleEngine.handle_auth_attempt(ip, 'test_hacker', False)
        res = RuleEngine.handle_auth_attempt(ip, 'test_hacker', False)
        return f"[Python UEBA] Тест Brute Force: IP {ip} получил 5 неудачных попыток.\nРезультат: {res['blockedReason']}"
    elif cmd == 'schema':
        return db.SCHEMA_SQL if hasattr(db, 'SCHEMA_SQL') else "Таблицы: users, events, incidents, blocks, notifications"
    else:
        return f"Неизвестная команда: {cmd}. Доступны: status, test_brute_force, schema"

def start_server(port: int = 8000, host: str = "127.0.0.1"):
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, UserTrackAPIHandler)
    print(f"🐍 UserTrack Python API Core запущен на http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановка Python сервера...")
        httpd.server_close()

if __name__ == '__main__':
    port = 8000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    elif '--port' in sys.argv:
        idx = sys.argv.index('--port')
        if idx + 1 < len(sys.argv) and sys.argv[idx + 1].isdigit():
            port = int(sys.argv[idx + 1])
    start_server(port=port)
