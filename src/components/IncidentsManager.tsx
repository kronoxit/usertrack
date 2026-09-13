import React, { useState, useMemo } from 'react';
import { SecurityIncident, IncidentStatus, IncidentSeverity } from '../types';
import { db } from '../services/db';
import { CreateIncidentModal } from './CreateIncidentModal';

interface IncidentsManagerProps {
  incidents: SecurityIncident[];
  onBlockIp: (ip: string, reason: string, durationMinutes?: number) => void;
}

export const IncidentsManager: React.FC<IncidentsManagerProps> = ({
  incidents,
  onBlockIp,
}) => {
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedUser, setSelectedUser] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [isCreateOpen, setIsCreateOpen] = useState(false);

  // Manual block modal state
  const [blockingTarget, setBlockingTarget] = useState<{ ip: string; reason: string } | null>(null);
  const [blockMinutes, setBlockMinutes] = useState(5);

  const registeredUsers = db.getUsers();

  const filtered = useMemo(() => {
    return incidents.filter((inc) => {
      const matchStatus = selectedStatus === 'ALL' || inc.status === selectedStatus;
      const matchSev = selectedSeverity === 'ALL' || inc.severity === selectedSeverity;
      const matchUser =
        selectedUser === 'ALL' ||
        (inc.username && inc.username.toLowerCase() === selectedUser.toLowerCase());
      const matchSearch =
        inc.sourceIp.includes(searchTerm) ||
        inc.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        inc.incidentType.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (inc.username && inc.username.toLowerCase().includes(searchTerm.toLowerCase()));
      return matchStatus && matchSev && matchUser && matchSearch;
    });
  }, [incidents, selectedStatus, selectedSeverity, selectedUser, searchTerm]);

  const handleStatusChange = (id: number, newStatus: IncidentStatus) => {
    db.updateIncidentStatus(id, newStatus);
  };

  return (
    <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-4">
        <div>
          <h2 className="text-base font-bold text-slate-900">
            Журнал инцидентов и угроз (таблица incidents)
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Аномалии и угрозы, выявленные аналитическим ядром (Brute Force, аномалии времени, ловушки Honeypot, доступ к портам).
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsCreateOpen(true)}
            className="px-3.5 py-1.5 rounded bg-red-600 hover:bg-red-700 text-white text-xs font-medium transition shadow-xs"
          >
            + Создать инцидент
          </button>
          <div className="text-xs text-slate-500 font-mono">
            Всего инцидентов: <strong className="text-slate-800">{incidents.length}</strong>
          </div>
        </div>
      </div>

      {/* Filters Toolbar */}
      <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 text-xs">
        <div className="sm:col-span-4">
          <input
            type="text"
            placeholder="Поиск..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full px-3 py-1.5 rounded border border-slate-300 text-slate-900 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="sm:col-span-3">
          <select
            value={selectedUser}
            onChange={(e) => setSelectedUser(e.target.value)}
            className="w-full px-2.5 py-1.5 rounded border border-slate-300 text-slate-800 bg-white focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">Все пользователи (цели)</option>
            {registeredUsers.map((u) => (
              <option key={u.id} value={u.username}>
                Пользователь: {u.username}
              </option>
            ))}
          </select>
        </div>

        <div className="sm:col-span-3">
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="w-full px-2.5 py-1.5 rounded border border-slate-300 text-slate-800 bg-white focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">Все статусы</option>
            <option value="Active">Active (Активные)</option>
            <option value="Investigating">Investigating (В расследовании)</option>
            <option value="Resolved">Resolved (Закрытые)</option>
          </select>
        </div>

        <div className="sm:col-span-2">
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="w-full px-2.5 py-1.5 rounded border border-slate-300 text-slate-800 bg-white focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">Критичность</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="border border-slate-200 rounded overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 text-slate-600 border-b border-slate-200 font-medium text-[11px] uppercase">
            <tr>
              <th className="py-2.5 px-3">ID</th>
              <th className="py-2.5 px-3">Время</th>
              <th className="py-2.5 px-3">Критичность</th>
              <th className="py-2.5 px-3">Тип угрозы</th>
              <th className="py-2.5 px-3">Пользователь</th>
              <th className="py-2.5 px-3">IP-источник</th>
              <th className="py-2.5 px-3">Описание инцидента</th>
              <th className="py-2.5 px-3">Статус</th>
              <th className="py-2.5 px-3 text-right">Действия</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 font-sans">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-12 text-center text-slate-400">
                  {incidents.length === 0
                    ? 'Инцидентов нет. Произведите подозрительное действие во вкладке «Отслеживание».'
                    : 'По заданным критериям инцидентов не найдено.'}
                </td>
              </tr>
            ) : (
              filtered.map((inc) => {
                const isBlocked = db.isIpBlocked(inc.sourceIp);
                return (
                  <tr key={inc.id} className="hover:bg-slate-50">
                    <td className="py-2 px-3 font-mono text-slate-400">#{inc.id}</td>
                    <td className="py-2 px-3 font-mono text-slate-500 whitespace-nowrap">
                      {new Date(inc.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span
                        className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          inc.severity === 'Critical'
                            ? 'bg-red-50 text-red-700 border border-red-200'
                            : inc.severity === 'High'
                            ? 'bg-orange-50 text-orange-700 border border-orange-200'
                            : inc.severity === 'Medium'
                            ? 'bg-amber-50 text-amber-700 border border-amber-200'
                            : 'bg-blue-50 text-blue-700 border border-blue-200'
                        }`}
                      >
                        {inc.severity}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-mono text-slate-700 text-[11px] whitespace-nowrap">
                      {inc.incidentType}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      {inc.username ? (
                        <span className="px-1.5 py-0.5 rounded bg-slate-100 font-mono text-slate-800 text-[11px] border border-slate-200 font-medium">
                          {inc.username}
                        </span>
                      ) : (
                        <span className="text-slate-400 font-mono text-[11px]">—</span>
                      )}
                    </td>
                    <td className="py-2 px-3 font-mono font-medium text-slate-800">{inc.sourceIp}</td>
                    <td className="py-2 px-3 text-slate-700 max-w-sm">{inc.description}</td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <select
                        value={inc.status}
                        onChange={(e) => handleStatusChange(inc.id, e.target.value as IncidentStatus)}
                        className={`text-[11px] font-medium rounded border px-1.5 py-0.5 ${
                          inc.status === 'Active'
                            ? 'bg-red-50 border-red-200 text-red-700'
                            : inc.status === 'Investigating'
                            ? 'bg-amber-50 border-amber-200 text-amber-700'
                            : 'bg-emerald-50 border-emerald-200 text-emerald-700'
                        }`}
                      >
                        <option value="Active">Active</option>
                        <option value="Investigating">Investigating</option>
                        <option value="Resolved">Resolved</option>
                      </select>
                    </td>
                    <td className="py-2 px-3 text-right whitespace-nowrap">
                      {!isBlocked ? (
                        <button
                          onClick={() =>
                            setBlockingTarget({
                              ip: inc.sourceIp,
                              reason: `Блокировка по инциденту #${inc.id}: ${inc.description}`,
                            })
                          }
                          className="px-2.5 py-1 rounded bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 text-[11px] font-medium transition"
                        >
                          Заблокировать в IPS
                        </button>
                      ) : (
                        <span className="text-[11px] text-amber-700 font-medium bg-amber-50 border border-amber-200 px-2 py-0.5 rounded">
                          В черном списке
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Manual IP Block Modal with Custom Duration */}
      {blockingTarget && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 flex items-center justify-center p-4">
          <div className="bg-white border border-slate-300 rounded shadow-lg max-w-md w-full overflow-hidden">
            <div className="px-4 py-3 bg-slate-100 border-b border-slate-200 flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                Блокировка узла в подсистеме IPS
              </h3>
              <button
                onClick={() => setBlockingTarget(null)}
                className="text-slate-400 hover:text-slate-700 rounded p-1 text-sm font-bold leading-none"
              >
                ✕
              </button>
            </div>

            <div className="p-4 space-y-3.5 text-xs text-slate-700">
              <div>
                <span className="text-slate-500 block mb-0.5">IP-адрес:</span>
                <span className="font-mono font-bold text-slate-900 bg-slate-100 px-2 py-1 rounded inline-block border border-slate-200">
                  {blockingTarget.ip}
                </span>
              </div>

              <div>
                <span className="text-slate-500 block mb-0.5">Причина блокировки:</span>
                <p className="text-slate-800 bg-slate-50 p-2 rounded border border-slate-200 leading-relaxed">
                  {blockingTarget.reason}
                </p>
              </div>

              <div>
                <label className="block text-slate-800 font-bold mb-1">
                  Время блокировки (в минутах):
                </label>
                <input
                  type="number"
                  min={1}
                  max={525600}
                  value={blockMinutes}
                  onChange={(e) =>
                    setBlockMinutes(Math.max(1, parseInt(e.target.value, 10) || 1))
                  }
                  className="w-full px-3 py-2 rounded border border-slate-300 font-mono text-sm font-bold text-slate-900 focus:outline-none focus:border-red-500"
                />
                <div className="flex items-center gap-2 mt-1.5 text-[11px] text-slate-500">
                  <span>Быстрый выбор:</span>
                  {[3, 5, 15, 30, 60, 1440].map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setBlockMinutes(m)}
                      className={`px-1.5 py-0.5 rounded border ${
                        blockMinutes === m
                          ? 'border-red-400 bg-red-50 text-red-700 font-semibold'
                          : 'border-slate-200 hover:bg-slate-100 text-slate-700'
                      }`}
                    >
                      {m >= 60 ? `${m / 60}ч` : `${m}м`}
                    </button>
                  ))}
                </div>
              </div>

              <div className="pt-2 flex items-center justify-end gap-2 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setBlockingTarget(null)}
                  className="px-3.5 py-1.5 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 font-medium transition"
                >
                  Отмена
                </button>
                <button
                  type="button"
                  onClick={() => {
                    onBlockIp(blockingTarget.ip, blockingTarget.reason, blockMinutes);
                    setBlockingTarget(null);
                  }}
                  className="px-4 py-1.5 rounded bg-red-600 hover:bg-red-700 text-white font-medium transition shadow-xs"
                >
                  Заблокировать на {blockMinutes} мин
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <CreateIncidentModal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        onIncidentCreated={() => {}}
      />
    </div>
  );
};
