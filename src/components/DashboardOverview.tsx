import React, { useState } from 'react';
import { NetworkEvent, SecurityIncident, IPBlock } from '../types';
import { DoughnutChart, DoughnutSegment } from './DoughnutChart';
import { CreateIncidentModal } from './CreateIncidentModal';

interface DashboardOverviewProps {
  events: NetworkEvent[];
  incidents: SecurityIncident[];
  blocks: IPBlock[];
  onNavigateTab: (tab: string) => void;
  onOpenPhoneAlerts?: () => void;
  notificationsCount?: number;
  onNotification?: (msg: string, type?: 'info' | 'critical') => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  events,
  incidents,
  blocks,
  onNavigateTab,
  onOpenPhoneAlerts,
  notificationsCount = 0,
  onNotification,
}) => {
  const [chartMode, setChartMode] = useState<'events' | 'incidents'>('incidents');
  const [isCreateIncidentOpen, setIsCreateIncidentOpen] = useState(false);

  const totalEvents = events.length;
  const activeBlocks = blocks.filter((b) => b.isActive).length;
  const activeIncidents = incidents.filter((i) => i.status === 'Active').length;
  const uniqueIps = Array.from(new Set(events.map((e) => e.ipAddress))).length;

  const criticalCount = incidents.filter((i) => i.severity === 'Critical').length;
  const highCount = incidents.filter((i) => i.severity === 'High').length;
  const mediumCount = incidents.filter((i) => i.severity === 'Medium').length;
  const lowCount = incidents.filter((i) => i.severity === 'Low').length;

  const recentEvents = events.slice(0, 7);

  // Data for Incidents Doughnut Chart
  const incidentsChartData: DoughnutSegment[] = [
    { label: 'Критический (Critical)', count: criticalCount, color: '#dc2626' },
    { label: 'Высокий (High)', count: highCount, color: '#ea580c' },
    { label: 'Средний (Medium)', count: mediumCount, color: '#f59e0b' },
    { label: 'Низкий (Low)', count: lowCount, color: '#3b82f6' },
  ];

  // Group events by type for Events Doughnut Chart
  const eventCounts: Record<string, number> = {};
  events.forEach((e) => {
    eventCounts[e.eventType] = (eventCounts[e.eventType] || 0) + 1;
  });

  const eventColorMap: Record<string, string> = {
    AUTH_SUCCESS: '#10b981',
    AUTH_FAILURE: '#ef4444',
    PORT_ACCESS: '#3b82f6',
    HONEYPOT_HIT: '#f97316',
    GEO_SHIFT: '#8b5cf6',
    DATA_EXPORT: '#06b6d4',
  };

  const eventsChartData: DoughnutSegment[] = Object.entries(eventCounts).map(
    ([type, count]) => ({
      label: type,
      count,
      color: eventColorMap[type] || '#94a3b8',
    })
  );

  return (
    <div className="space-y-5 font-sans">
      {/* Top Action Header */}
      <div className="bg-white border border-slate-300 rounded p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div>
          <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
            Панель мониторинга SIEM / IPS «UserTrack»
          </h2>
          <p className="text-xs text-slate-600 mt-0.5">
            Сводка состояния безопасности: {totalEvents} событий, {activeIncidents} активных инцидентов, {activeBlocks} блокировок.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Create Incident Button */}
          <button
            onClick={() => setIsCreateIncidentOpen(true)}
            className="px-3.5 py-1.5 rounded border border-red-700 bg-red-600 hover:bg-red-700 text-white text-xs font-semibold transition shadow-xs"
            title="Создать инцидент безопасности"
          >
            + Создать инцидент
          </button>

          {/* Mobile alerts shortcut button */}
          {onOpenPhoneAlerts && (
            <button
              onClick={onOpenPhoneAlerts}
              className="px-3 py-1.5 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium flex items-center gap-1.5 transition"
              title="Оповещения администратора"
            >
              <span>Оповещения</span>
              {notificationsCount > 0 && (
                <span className="px-1.5 py-0.2 rounded-full bg-red-600 text-white font-mono text-[10px] font-bold">
                  {notificationsCount}
                </span>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Primary KPI Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Events */}
        <div
          onClick={() => onNavigateTab('events')}
          className="bg-white border border-slate-300 rounded p-4 cursor-pointer hover:border-slate-400 transition shadow-xs"
        >
          <div className="text-slate-500 text-xs font-medium">
            События (таблица events)
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-slate-900 tracking-tight">
            {totalEvents}
          </div>
          <div className="mt-1 text-[11px] text-slate-500 flex items-center justify-between">
            <span>Уникальных IP: {uniqueIps}</span>
            <span className="text-blue-600 font-medium">Журнал →</span>
          </div>
        </div>

        {/* Card 2: Active Incidents */}
        <div
          onClick={() => onNavigateTab('incidents')}
          className="bg-white border border-slate-300 rounded p-4 cursor-pointer hover:border-slate-400 transition shadow-xs"
        >
          <div className="text-slate-500 text-xs font-medium">
            Активные инциденты
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-red-600 tracking-tight">
            {activeIncidents}
          </div>
          <div className="mt-1 text-[11px] text-slate-500 flex items-center justify-between">
            <span>Критических: {criticalCount}</span>
            <span className="text-blue-600 font-medium">Управление →</span>
          </div>
        </div>

        {/* Card 3: IPS Active Blocks */}
        <div
          onClick={() => onNavigateTab('ips')}
          className="bg-white border border-slate-300 rounded p-4 cursor-pointer hover:border-slate-400 transition shadow-xs"
        >
          <div className="text-slate-500 text-xs font-medium">
            Блокировки IPS
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-slate-900 tracking-tight">
            {activeBlocks}
          </div>
          <div className="mt-1 text-[11px] text-slate-500 flex items-center justify-between">
            <span>Таймаут: 3-10 мин</span>
            <span className="text-blue-600 font-medium">Таблица blocks →</span>
          </div>
        </div>

        {/* Card 4: Database SQLite */}
        <div
          onClick={() => onNavigateTab('database')}
          className="bg-white border border-slate-300 rounded p-4 cursor-pointer hover:border-slate-400 transition shadow-xs"
        >
          <div className="text-slate-500 text-xs font-medium">
            База данных SQLite
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-emerald-700 tracking-tight">
            usertrack.db
          </div>
          <div className="mt-1 text-[11px] text-slate-500 flex items-center justify-between">
            <span>4 таблицы</span>
            <span className="text-blue-600 font-medium">SQL-консоль →</span>
          </div>
        </div>
      </div>

      {/* Grid: Doughnut Chart (7 cols) + Incident Management Card (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Doughnut Chart */}
        <div className="lg:col-span-7 bg-white border border-slate-300 rounded p-4 shadow-xs space-y-3">
          <div className="flex items-center justify-between border-b border-slate-200 pb-2.5">
            <div>
              <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wide">
                Распределение данных в системе
              </h3>
              <p className="text-[11px] text-slate-500">
                Визуализация распределения данных в реальном времени
              </p>
            </div>

            <div className="flex items-center bg-slate-100 p-0.5 rounded text-xs font-medium">
              <button
                onClick={() => setChartMode('incidents')}
                className={`px-2.5 py-1 rounded transition text-[11px] ${
                  chartMode === 'incidents'
                    ? 'bg-white shadow-xs text-slate-900 font-bold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Инциденты ({incidents.length})
              </button>
              <button
                onClick={() => setChartMode('events')}
                className={`px-2.5 py-1 rounded transition text-[11px] ${
                  chartMode === 'events'
                    ? 'bg-white shadow-xs text-slate-900 font-bold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                События ({events.length})
              </button>
            </div>
          </div>

          {chartMode === 'incidents' ? (
            <DoughnutChart
              data={incidentsChartData}
              totalLabel="Инцидентов"
              title="Распределение инцидентов по степени важности"
            />
          ) : (
            <DoughnutChart
              data={eventsChartData}
              totalLabel="Событий"
              title="Распределение событий по типам"
            />
          )}
        </div>

        {/* Incident Management & Full Form Trigger Panel */}
        <div className="lg:col-span-5 bg-white border border-slate-300 rounded p-4 space-y-4 shadow-xs flex flex-col justify-between">
          <div className="space-y-3">
            <div className="border-b border-slate-200 pb-2.5">
              <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wide">
                Управление инцидентами безопасности
              </h3>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Регистрация инцидентов по типам атак, анализ поведения (UEBA) и автоматическое реагирование IPS
              </p>
            </div>

            <div className="text-xs text-slate-600 space-y-2 leading-relaxed">
              <p>
                Создание инцидента безопасности:
              </p>
              <ul className="list-disc list-inside space-y-1 text-slate-700 font-medium">
                <li>Выбор типа угрозы (Brute Force, Time Anomaly, Geo, Honeypot и др.)</li>
                <li>Автоматическое определение степени критичности и сигнатурного правила</li>
                <li>Выбор целевого пользователя или ручной ввод никнейма</li>
                <li>Автоматическая синхронизация с событиями и оповещениями системы</li>
              </ul>
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded p-3 text-xs space-y-1.5">
              <div className="flex justify-between">
                <span className="text-slate-500">Активных инцидентов:</span>
                <span className="font-bold text-red-600 font-mono">{activeIncidents}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Активных блокировок IPS:</span>
                <span className="font-bold text-slate-800 font-mono">{activeBlocks}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Критических угроз:</span>
                <span className="font-bold text-red-700 font-mono">{criticalCount}</span>
              </div>
            </div>
          </div>

          <div className="space-y-2 pt-2">
            <button
              type="button"
              onClick={() => setIsCreateIncidentOpen(true)}
              className="w-full py-2 px-3 rounded bg-red-600 hover:bg-red-700 text-white font-semibold text-xs transition shadow-xs text-center"
            >
              Создать инцидент
            </button>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => onNavigateTab('incidents')}
                className="flex-1 py-1.5 px-2 rounded border border-slate-300 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-medium text-center transition"
              >
                Журнал инцидентов
              </button>
              <button
                type="button"
                onClick={() => onNavigateTab('ips')}
                className="flex-1 py-1.5 px-2 rounded border border-slate-300 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-medium text-center transition"
              >
                Блокировки IPS
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Latest Events Table */}
      <div className="bg-white border border-slate-300 rounded p-4 space-y-3 shadow-xs">
        <div className="flex items-center justify-between border-b border-slate-200 pb-2.5">
          <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wide">
            Последние события (таблица events)
          </h3>
          <button
            onClick={() => onNavigateTab('events')}
            className="text-xs text-blue-600 hover:underline font-medium"
          >
            Все события ({events.length}) →
          </button>
        </div>

        {recentEvents.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-500 space-y-2">
            <p>Журнал событий пуст. Таблица events очищена.</p>
            <button
              onClick={() => setIsCreateIncidentOpen(true)}
              className="px-3 py-1.5 rounded bg-red-600 text-white hover:bg-red-700 transition font-medium"
            >
              Создать первый инцидент
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-600 border-b border-slate-200 font-medium text-[11px] uppercase">
                <tr>
                  <th className="py-2 px-2.5">Время</th>
                  <th className="py-2 px-2.5">Пользователь</th>
                  <th className="py-2 px-2.5">IP-адрес</th>
                  <th className="py-2 px-2.5">Тип события</th>
                  <th className="py-2 px-2.5">Порт</th>
                  <th className="py-2 px-2.5">Описание</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-sans">
                {recentEvents.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-50">
                    <td className="py-2 px-2.5 font-mono text-slate-500 whitespace-nowrap">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2 px-2.5 font-semibold text-slate-900 whitespace-nowrap">
                      {ev.username || '—'}
                    </td>
                    <td className="py-2 px-2.5 font-mono text-slate-700 whitespace-nowrap">
                      {ev.ipAddress}
                    </td>
                    <td className="py-2 px-2.5 whitespace-nowrap">
                      <span
                        className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                          ev.eventType === 'AUTH_SUCCESS'
                            ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                            : ev.eventType === 'AUTH_FAILURE'
                            ? 'bg-red-50 text-red-800 border border-red-200'
                            : 'bg-slate-100 text-slate-800 border border-slate-200'
                        }`}
                      >
                        {ev.eventType}
                      </span>
                    </td>
                    <td className="py-2 px-2.5 font-mono text-slate-500 whitespace-nowrap">
                      {ev.port}
                    </td>
                    <td className="py-2 px-2.5 text-slate-700 truncate max-w-xs">
                      {ev.details}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Incident Creator Modal (Full form) */}
      <CreateIncidentModal
        isOpen={isCreateIncidentOpen}
        onClose={() => setIsCreateIncidentOpen(false)}
        onIncidentCreated={(msg) => {
          if (onNotification) onNotification(msg, 'critical');
        }}
      />
    </div>
  );
};
