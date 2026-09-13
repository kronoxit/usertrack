import React, { useState, useMemo } from 'react';
import { NetworkEvent } from '../types';

interface EventsTableProps {
  events: NetworkEvent[];
}

export const EventsTable: React.FC<EventsTableProps> = ({ events }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [filterIp, setFilterIp] = useState('');
  const [sortAsc, setSortAsc] = useState(false);

  const uniqueIps = useMemo(() => {
    return Array.from(new Set(events.map((e) => e.ipAddress)));
  }, [events]);

  const filteredEvents = useMemo(() => {
    return events
      .filter((e) => {
        const matchesSearch =
          e.ipAddress.toLowerCase().includes(searchTerm.toLowerCase()) ||
          (e.username && e.username.toLowerCase().includes(searchTerm.toLowerCase())) ||
          e.details.toLowerCase().includes(searchTerm.toLowerCase());

        const matchesType = selectedType === 'ALL' || e.eventType === selectedType;
        const matchesIp = !filterIp || e.ipAddress === filterIp;

        return matchesSearch && matchesType && matchesIp;
      })
      .sort((a, b) => {
        const tA = new Date(a.timestamp).getTime();
        const tB = new Date(b.timestamp).getTime();
        return sortAsc ? tA - tB : tB - tA;
      });
  }, [events, searchTerm, selectedType, filterIp, sortAsc]);

  const exportToCsv = () => {
    const headers = ['ID', 'Время', 'Пользователь', 'IP адрес', 'Тип события', 'Порт', 'Страна', 'Город', 'Описание'];
    const rows = filteredEvents.map((e) => [
      e.id,
      `"${e.timestamp}"`,
      `"${e.username || ''}"`,
      `"${e.ipAddress}"`,
      `"${e.eventType}"`,
      e.port,
      `"${e.country || ''}"`,
      `"${e.city || ''}"`,
      `"${e.details.replace(/"/g, '""')}"`,
    ]);

    const csvContent = '\uFEFF' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `usertrack_events_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="bg-white border border-slate-300 rounded p-4 shadow-xs space-y-3 font-sans">
      {/* Top Header & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 pb-3">
        <div>
          <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
            Журнал сетевых событий (таблица events)
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Аудит сетевых обращений, авторизаций и системных запросов
          </p>
        </div>

        <button
          onClick={exportToCsv}
          disabled={events.length === 0}
          className="px-3 py-1.5 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium transition shadow-xs disabled:opacity-50"
        >
          Экспорт в CSV
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 text-xs">
        {/* Search */}
        <div className="sm:col-span-5">
          <input
            type="text"
            placeholder="Поиск..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full px-3 py-1.5 rounded border border-slate-300 text-slate-900 focus:outline-none focus:border-blue-500"
          />
        </div>

        {/* Filter Event Type */}
        <div className="sm:col-span-3">
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="w-full px-2.5 py-1.5 rounded border border-slate-300 text-slate-800 bg-white focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">Все типы событий</option>
            <option value="AUTH_SUCCESS">AUTH_SUCCESS (Успешный вход)</option>
            <option value="AUTH_FAILURE">AUTH_FAILURE (Ошибка входа)</option>
            <option value="HONEYPOT_HIT">HONEYPOT_HIT (Ловушка)</option>
            <option value="PORT_ACCESS">PORT_ACCESS (Сканирование)</option>
            <option value="NETWORK_REQUEST">NETWORK_REQUEST (HTTP/S)</option>
            <option value="API_LOG_INGEST">API_LOG_INGEST (REST API)</option>
          </select>
        </div>

        {/* Filter IP */}
        <div className="sm:col-span-3">
          <select
            value={filterIp}
            onChange={(e) => setFilterIp(e.target.value)}
            className="w-full px-2.5 py-1.5 rounded border border-slate-300 text-slate-800 bg-white focus:outline-none focus:border-blue-500 font-mono"
          >
            <option value="">Все IP ({uniqueIps.length})</option>
            {uniqueIps.map((ip) => (
              <option key={ip} value={ip}>
                {ip}
              </option>
            ))}
          </select>
        </div>

        {/* Reset Filter Button */}
        <div className="sm:col-span-1">
          <button
            onClick={() => {
              setSearchTerm('');
              setSelectedType('ALL');
              setFilterIp('');
            }}
            className="w-full py-1.5 px-2 rounded border border-slate-300 bg-slate-50 hover:bg-slate-100 text-slate-600 text-xs font-medium transition text-center"
            title="Сбросить фильтры"
          >
            Сброс
          </button>
        </div>
      </div>

      {/* Events Table */}
      <div className="border border-slate-200 rounded overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 text-slate-600 border-b border-slate-200 font-medium text-[11px] uppercase">
            <tr>
              <th className="py-2.5 px-3">ID</th>
              <th
                className="py-2.5 px-3 cursor-pointer select-none hover:text-slate-900"
                onClick={() => setSortAsc(!sortAsc)}
              >
                Время {sortAsc ? '▲' : '▼'}
              </th>
              <th className="py-2.5 px-3">Пользователь</th>
              <th className="py-2.5 px-3">IP-адрес</th>
              <th className="py-2.5 px-3">Тип события</th>
              <th className="py-2.5 px-3">Порт</th>
              <th className="py-2.5 px-3">Локация</th>
              <th className="py-2.5 px-3">Детали</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 font-sans">
            {filteredEvents.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-12 text-center text-slate-400">
                  Событий не найдено (таблица events пуста или фильтры не дали совпадений).
                </td>
              </tr>
            ) : (
              filteredEvents.map((e) => (
                <tr key={e.id} className="hover:bg-slate-50">
                  <td className="py-2 px-3 font-mono text-slate-400">#{e.id}</td>
                  <td className="py-2 px-3 font-mono text-slate-600 whitespace-nowrap">
                    {new Date(e.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2 px-3 font-medium text-slate-900 whitespace-nowrap">
                    {e.username || '—'}
                  </td>
                  <td className="py-2 px-3 font-mono text-slate-700 whitespace-nowrap">
                    {e.ipAddress}
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap">
                    <span
                      className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        e.eventType === 'AUTH_SUCCESS'
                          ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                          : e.eventType === 'AUTH_FAILURE'
                          ? 'bg-red-50 text-red-800 border border-red-200'
                          : e.eventType === 'HONEYPOT_HIT'
                          ? 'bg-amber-50 text-amber-800 border border-amber-200'
                          : 'bg-slate-100 text-slate-700 border border-slate-200'
                      }`}
                    >
                      {e.eventType}
                    </span>
                  </td>
                  <td className="py-2 px-3 font-mono text-slate-500 whitespace-nowrap">
                    {e.port}
                  </td>
                  <td className="py-2 px-3 text-slate-500 whitespace-nowrap">
                    {e.city ? `${e.city} (${e.country})` : '—'}
                  </td>
                  <td className="py-2 px-3 text-slate-700 max-w-sm truncate">
                    {e.details}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
