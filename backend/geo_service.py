"""
UserTrack GeoIP & Network Intelligence Service (Python)
Сервис анализа IP-адресов, геолокации и провайдеров на чистом Python с использованием модуля ipaddress.
"""

import ipaddress
import urllib.request
import json
from typing import Dict, Any, Optional

# Известные российские и международные подсети и их операторы
KNOWN_SUBNETS = [
    # Москва и область
    ("95.24.0.0/14", {"city": "Москва", "country": "Россия", "flag": "🇷🇺", "isp": "ПАО ВымпелКом (Билайн)"}),
    ("178.176.0.0/13", {"city": "Москва", "country": "Россия", "flag": "🇷🇺", "isp": "ПАО МегаФон"}),
    ("212.45.0.0/16", {"city": "Москва", "country": "Россия", "flag": "🇷🇺", "isp": "МГТС / МТС"}),
    ("188.162.0.0/15", {"city": "Москва", "country": "Россия", "flag": "🇷🇺", "isp": "Yota (ООО Скартел)"}),
    ("188.170.0.0/15", {"city": "Москва", "country": "Россия", "flag": "🇷🇺", "isp": "Yota Mobile"}),
    ("94.25.0.0/16", {"city": "Москва", "country": "Россия", "flag": "🇷🇺", "isp": "Ростелеком МРФ Центр"}),
    ("85.140.0.0/15", {"city": "Москва", "country": "Россия", "flag": "🇷🇺", "isp": "Ростелеком"}),
    ("77.88.0.0/18", {"city": "Москва", "country": "Россия", "flag": "🇷🇺", "isp": "Yandex LLC"}),

    # Санкт-Петербург
    ("93.100.0.0/15", {"city": "Санкт-Петербург", "country": "Россия", "flag": "🇷🇺", "isp": "ПАО Ростелеком Северо-Запад"}),
    ("178.66.0.0/15", {"city": "Санкт-Петербург", "country": "Россия", "flag": "🇷🇺", "isp": "ЭР-Телеком Холдинг (Дом.ру)"}),
    ("188.134.0.0/16", {"city": "Санкт-Петербург", "country": "Россия", "flag": "🇷🇺", "isp": "Ростелеком СПб"}),

    # Регионы РФ
    ("92.242.0.0/16", {"city": "Калуга", "country": "Россия", "flag": "🇷🇺", "isp": "Ростелеком Калуга"}),
    ("178.64.0.0/15", {"city": "Обнинск", "country": "Россия", "flag": "🇷🇺", "isp": "Макснет Системы / Ростелеком"}),
    ("92.255.0.0/16", {"city": "Новосибирск", "country": "Россия", "flag": "🇷🇺", "isp": "Новотелеком (Электронный город)"}),
    ("178.49.0.0/16", {"city": "Новосибирск", "country": "Россия", "flag": "🇷🇺", "isp": "Ростелеком Сибирь"}),
    ("91.144.136.0/21", {"city": "Екатеринбург", "country": "Россия", "flag": "🇷🇺", "isp": "Планета (Инсис)"}),
    ("188.18.0.0/15", {"city": "Екатеринбург", "country": "Россия", "flag": "🇷🇺", "isp": "Ростелеком Урал"}),
    ("95.78.0.0/15", {"city": "Казань", "country": "Россия", "flag": "🇷🇺", "isp": "Таттелеком (Летай)"}),
    ("83.220.224.0/19", {"city": "Нижний Новгород", "country": "Россия", "flag": "🇷🇺", "isp": "Билайн Волга"}),
    ("94.180.0.0/15", {"city": "Самара", "country": "Россия", "flag": "🇷🇺", "isp": "ЭР-Телеком Самара"}),

    # Международные тестовые подсети
    ("185.220.101.0/24", {"city": "Франкфурт", "country": "Германия", "flag": "🇩🇪", "isp": "Tor Exit Node Network"}),
    ("45.154.255.0/24", {"city": "Амстердам", "country": "Нидерланды", "flag": "🇳🇱", "isp": "Hosting Provider B.V."}),
    ("8.8.8.0/24", {"city": "Маунтин-Вью", "country": "США", "flag": "🇺🇸", "isp": "Google LLC"}),
    ("1.1.1.0/24", {"city": "Сан-Франциско", "country": "США", "flag": "🇺🇸", "isp": "Cloudflare Inc."}),
]

PARSED_SUBNETS = [
    (ipaddress.ip_network(net), info) for net, info in KNOWN_SUBNETS
]

GEO_CACHE: Dict[str, Dict[str, Any]] = {}

def is_valid_ip(ip_str: str) -> bool:
    if not ip_str:
        return False
    clean = ip_str.replace("::ffff:", "").strip()
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False

def is_private_ip(ip_str: str) -> bool:
    clean = ip_str.replace("::ffff:", "").strip()
    try:
        ip_obj = ipaddress.ip_address(clean)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return False

def get_quick_geo(ip_str: str) -> Dict[str, Any]:
    """Быстрое определение геолокации без внешних задержек через анализ подсетей Python ipaddress"""
    if not ip_str:
        return {"country": "Неизвестно", "city": "", "flag": "🌐", "isp": ""}

    clean = ip_str.replace("::ffff:", "").strip()

    if clean in GEO_CACHE:
        return GEO_CACHE[clean]

    if clean == "127.0.0.1" or clean == "::1":
        return {"country": "Локальная сеть (Loopback)", "city": "Localhost", "flag": "🏠", "isp": "Local System"}

    try:
        ip_obj = ipaddress.ip_address(clean)
    except ValueError:
        return {"country": "Некорректный IP", "city": "", "flag": "⚠️", "isp": ""}

    if ip_obj.is_private or ip_obj.is_loopback:
        return {
            "country": "Корпоративная сеть (LAN)",
            "city": "Внутренняя сеть",
            "flag": "🏢",
            "isp": f"Интранет подсеть ({clean})"
        }

    # Поиск по известным подсетям
    for net, info in PARSED_SUBNETS:
        if ip_obj in net:
            res = {
                "country": info["country"],
                "city": info["city"],
                "flag": info["flag"],
                "isp": info["isp"]
            }
            GEO_CACHE[clean] = res
            return res

    # Общие российские диапазоны
    first_octet = int(clean.split('.')[0]) if '.' in clean else 0
    if first_octet in [31, 37, 46, 77, 78, 79, 80, 81, 82, 83, 84, 85, 87, 88, 89, 90, 91, 92, 93, 94, 95, 176, 178, 185, 188, 212, 213, 217]:
        res = {
            "country": "Россия",
            "city": "Москва",
            "flag": "🇷🇺",
            "isp": "Российский провайдер связи"
        }
        GEO_CACHE[clean] = res
        return res

    res = {
        "country": "Интернет",
        "city": "",
        "flag": "🌐",
        "isp": "Внешний провайдер"
    }
    GEO_CACHE[clean] = res
    return res

def lookup_online_geo(ip_str: str) -> Dict[str, Any]:
    """Онлайн поиск через публичный GeoIP сервис с fallback на quick_geo"""
    clean = ip_str.replace("::ffff:", "").strip()
    if not is_valid_ip(clean) or is_private_ip(clean):
        return get_quick_geo(clean)

    if clean in GEO_CACHE and GEO_CACHE[clean].get("country") not in ["", "Интернет", "Неизвестно"]:
        return GEO_CACHE[clean]

    # Пробуем через ip-api.com с таймаутом 2.5 сек
    try:
        url = f"http://ip-api.com/json/{clean}?fields=status,message,country,city,isp,org&lang=ru"
        req = urllib.request.Request(url, headers={"User-Agent": "UserTrack-SIEM-Python/2.4"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success':
                flag = "🇷🇺" if data.get('country') in ['Россия', 'Russian Federation'] else "🌐"
                res = {
                    "country": data.get('country') or 'Неизвестно',
                    "city": data.get('city') or '',
                    "flag": flag,
                    "isp": data.get('isp') or data.get('org') or ''
                }
                GEO_CACHE[clean] = res
                return res
    except Exception:
        pass

    return get_quick_geo(clean)
