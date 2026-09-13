"""
UserTrack SIEM Analytics & Threat Calculation Core (Python)
Вычисление метрик безопасности, индекса угроз (Threat Score) и распределений.
"""

from collections import Counter
from typing import Dict, Any, List
from . import database as db

def calculate_threat_metrics() -> Dict[str, Any]:
    """
    Расчет ключевых показателей ИБ на Python:
    - Индекс общей угрозы (0-100)
    - Количество критических, высоких, средних инцидентов
    - Статистика по протоколам и типам событий
    - Топ атакующих IP-адресов
    """
    events = db.get_events(limit=2000)
    incidents = db.get_incidents()
    blocks = db.get_blocks()

    active_blocks_count = sum(1 for b in blocks if b.get('isActive'))

    # Подсчет инцидентов по степени важности
    sev_counts = Counter(inc.get('severity') for inc in incidents if inc.get('status') == 'Active')
    critical = sev_counts.get('Critical', 0)
    high = sev_counts.get('High', 0)
    medium = sev_counts.get('Medium', 0)
    low = sev_counts.get('Low', 0)

    # Формула индекса угрозы: 0 .. 100
    raw_threat = (critical * 28) + (high * 15) + (medium * 6) + (low * 2) + (active_blocks_count * 5)
    threat_score = min(100, raw_threat)

    # Статистика типов событий
    event_type_counts = Counter(ev.get('eventType') for ev in events)

    # Статистика протоколов
    proto_counts = Counter(ev.get('protocol', 'TCP') for ev in events)

    # Топ IP-адресов по активности
    ip_counts = Counter(ev.get('ipAddress') for ev in events)
    top_ips = [{"ip": ip, "count": count} for ip, count in ip_counts.most_common(5)]

    # Топ аномалий
    anomaly_counts = Counter(inc.get('incidentType') for inc in incidents)
    top_anomalies = [{"type": t, "count": c} for t, c in anomaly_counts.most_common(5)]

    return {
        "threatScore": threat_score,
        "threatLevel": "Critical" if threat_score >= 70 else ("High" if threat_score >= 40 else ("Medium" if threat_score >= 20 else "Low")),
        "activeIncidents": len([i for i in incidents if i.get('status') == 'Active']),
        "criticalCount": critical,
        "highCount": high,
        "mediumCount": medium,
        "lowCount": low,
        "activeBlocksCount": active_blocks_count,
        "totalEventsCount": len(events),
        "eventTypeDistribution": dict(event_type_counts),
        "protocolDistribution": dict(proto_counts),
        "topAttackingIps": top_ips,
        "topAnomalies": top_anomalies
    }
