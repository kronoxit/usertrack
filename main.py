#!/usr/bin/env python3
"""
Программный комплекс информационной безопасности «UserTrack»
Главный файл запуска и управления на Python.

Использование:
  python3 main.py                     - Запуск Python бэкенда (порт 8000)
  python3 main.py --status            - Статус SIEM и аналитика угроз (Threat Score)
  python3 main.py --demo              - Заполнить базу данных SQLite демонстрационными инцидентами
  python3 main.py --test-brute-force  - Симуляция Brute Force атаки с проверкой IPS блокировки
  python3 main.py --test-night        - Симуляция входа в нерабочее время (03:00 ночи)
  python3 main.py --test-honeypot     - Симуляция обращения к Honeypot-ловушке
  python3 main.py --users             - Список пользователей из базы SQLite
  python3 main.py --events            - Последние события информационной безопасности
  python3 main.py --blocks            - Активные блокировки сетевых адресов
"""

import sys
import json
from backend import database as db
from backend.rule_engine import RuleEngine
from backend import analytics
from backend.app import start_server

def print_banner():
    print("=" * 65)
    print("   USERTRACK: СИСТЕМА МОНИТОРИНГА И АНАЛИЗА СЕТЕВЫХ УГРОЗ (PYTHON)")
    print("    База данных: SQLite3 (backend/usertrack.db)")
    print("    Аналитическое ядро: UEBA + IPS Rules Engine (Python 3.10)")
    print("=" * 65)

def main():
    if len(sys.argv) == 1 or sys.argv[1] in ['--server', '-s']:
        print_banner()
        port = 8000
        if len(sys.argv) > 2 and sys.argv[2].isdigit():
            port = int(sys.argv[2])
        start_server(port=port)
        return

    arg = sys.argv[1]

    if arg in ['--status', '-st']:
        print_banner()
        metrics = analytics.calculate_threat_metrics()
        print(f" Индекс угрозы системы: {metrics['threatScore']}/100 [{metrics['threatLevel']}]")
        print(f" Пользователей в системе: {len(db.get_users())}")
        print(f" Всего событий в БД: {metrics['totalEventsCount']}")
        print(f" Активных инцидентов: {metrics['activeIncidents']} (Критич: {metrics['criticalCount']})")
        print(f" Активных блокировок IPS: {metrics['activeBlocksCount']}")
        print("\nРаспределение типов событий:")
        for ev_type, count in metrics['eventTypeDistribution'].items():
            print(f"  - {ev_type}: {count}")
        print("\nТоп атакующих IP-адресов:")
        for item in metrics['topAttackingIps']:
            print(f"  - {item['ip']}: {item['count']} запросов")

    elif arg in ['--demo', '-d']:
        print_banner()
        db.seed_demo_data()
        print(" База данных SQLite успешно заполнена демонстрационными данными!")
        print("   Добавлено: 12 сетевых событий, 2 критических инцидента, 2 активных блокировки IPS.")

    elif arg in ['--test-brute-force', '-bf']:
        print_banner()
        target_ip = "194.26.29.112"
        print(f" Запуск симуляции атаки перебора паролей (Brute Force) с IP: {target_ip}...")
        for i in range(1, 5):
            res = RuleEngine.handle_auth_attempt(target_ip, "artem", False)
            print(f"   Попытка {i}/5: {res['blockedReason']}")
        print("   Попытка 5/5: (Порог срабатывания UEBA правила)")
        final_res = RuleEngine.handle_auth_attempt(target_ip, "artem", False)
        print(f"   Результат: {final_res['blockedReason']}")
        print("   Проверка статуса блокировки IPS:", "ЗАБЛОКИРОВАН" if db.is_ip_blocked(target_ip) else "НЕ ЗАБЛОКИРОВАН")

    elif arg in ['--test-night', '-tn']:
        print_banner()
        print(" Симуляция ночной поведенческой аномалии (вход в 03:15 ночи)...")
        res = RuleEngine.handle_auth_attempt("95.24.11.20", "artem", True, simulated_hour=3)
        print(f"   Авторизация: {'РАЗРЕШЕНА' if res['allowed'] else 'ЗАПРЕЩЕНА'}")
        if res.get('incident'):
            print(f"   Зафиксирован инцидент: [{res['incident']['severity']}] {res['incident']['description']}")

    elif arg in ['--test-honeypot', '-hp']:
        print_banner()
        print(" Симуляция обращения краулера к ловушке /.env...")
        res = RuleEngine.handle_honeypot_trap("/.env", "185.220.101.99", "scanner_bot")
        print(f"   Событие: {res['event']['details']}")
        print(f"   Реакция IPS: {res['block']['reason']} (Срок: {res['block']['unlockTime']})")
        print(f"   Инцидент: [{res['incident']['severity']}] {res['incident']['description']}")

    elif arg in ['--users', '-u']:
        print_banner()
        users = db.get_users()
        print(f"Найдено пользователей: {len(users)}\n")
        for u in users:
            admin_mark = " (Главный Администратор)" if u['isChiefAdmin'] else ""
            print(f"ID {u['id']}: {u['username']} [{u['role']}]{admin_mark} | Имя: {u['fullName']} | IP: {', '.join(u['knownIps'])}")

    elif arg in ['--events', '-e']:
        print_banner()
        events = db.get_events(limit=10)
        print(f"Последние события безопасности (10 из {len(db.get_events())}):\n")
        for ev in events:
            loc = f"{ev['city']}, {ev['country']}" if ev['city'] else (ev['country'] or 'LAN')
            print(f"[{ev['timestamp'][:19]}] {ev['eventType']:<14} | {ev['ipAddress']:<15} ({loc}) | {ev['details']}")

    elif arg in ['--blocks', '-b']:
        print_banner()
        blocks = db.get_blocks()
        print(f"Таблица блокировок IPS (usertrack.db):\n")
        for b in blocks:
            status = "АКТИВНА" if b['isActive'] else "ИСТЕКЛА"
            print(f"IP: {b['ipAddress']:<15} | Статус: {status:<8} | До: {b['unlockTime'][:19]} | Причина: {b['reason']}")

    elif arg in ['--help', '-h']:
        print_banner()
        print("Доступные команды:")
        print("  python3 main.py --status            Проверить текущий статус и метрики ИБ")
        print("  python3 main.py --demo              Сгенерировать демонстрационные данные в SQLite")
        print("  python3 main.py --test-brute-force  Тестирование UEBA правила обнаружения Brute Force")
        print("  python3 main.py --test-night        Тестирование детекции аномальной ночной активности")
        print("  python3 main.py --test-honeypot     Тестирование ловушек Honeypot")
        print("  python3 main.py --users             Список пользователей в базе данных")
        print("  python3 main.py --events            Последние сетевые события")
        print("  python3 main.py --blocks            Таблица блокировок IPS")
        print("  python3 backend/app.py              Запуск REST API сервера")

    else:
        print_banner()
        print(f"Неизвестная опция: {arg}")
        print("Доступные команды:")
        print("  python3 main.py --status")
        print("  python3 main.py --demo")
        print("  python3 main.py --test-brute-force")
        print("  python3 main.py --test-night")
        print("  python3 main.py --test-honeypot")
        print("  python3 main.py --users")
        print("  python3 main.py --events")
        print("  python3 main.py --blocks")

if __name__ == '__main__':
    main()
