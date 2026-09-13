import React, { useState, useEffect } from 'react';
import { IPBlock } from '../types';
import { db } from '../services/db';

interface IPSManagerProps {
  blocks: IPBlock[];
}

export const IPSManager: React.FC<IPSManagerProps> = ({ blocks }) => {
  const [newIp, setNewIp] = useState('');
  const [newReason, setNewReason] = useState('Ручная превентивная блокировка администратора');
  const [newDuration, setNewDuration] = useState(3);
  const [, setTick] = useState(0);

  // Timer countdown tick
  useEffect(() => {
    const timer = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(timer);
  }, []);

  const handleAddBlock = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIp) return;

    db.applyBlock(newIp.trim(), newReason, Number(newDuration), 'ADMIN_MANUAL');
    setNewIp('');
  };

  const handleUnblock = (ip: string) => {
    db.unblockIp(ip);
  };

  const calculateRemainingSeconds = (unlockIso: string) => {
    const diff = new Date(unlockIso).getTime() - Date.now();
    return Math.max(0, Math.floor(diff / 1000));
  };

  return (
    <div className="space-y-5 font-sans">
      {/* Top Banner & Manual Add Block */}
      <div className="bg-white border border-slate-300 rounded p-4 shadow-xs">
        <div className="border-b border-slate-200 pb-3 mb-4">
          <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
            Подсистема активной защиты IPS (таблица blocks)
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Любые сетевые запросы и попытки авторизации от заблокированных IP-адресов отсекаются IPS ещё до проверки учётных записей.
          </p>
        </div>

        <form onSubmit={handleAddBlock} className="grid grid-cols-1 sm:grid-cols-12 gap-3 text-xs">
          <div className="sm:col-span-4">
            <label className="block text-slate-600 font-medium mb-1">IP-адрес для блокировки:</label>
            <input
              type="text"
              value={newIp}
              onChange={(e) => setNewIp(e.target.value)}
              className="w-full px-3 py-1.5 rounded border border-slate-300 font-mono text-slate-900 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="sm:col-span-4">
            <label className="block text-slate-600 font-medium mb-1">Причина блокировки:</label>
            <input
              type="text"
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              className="w-full px-3 py-1.5 rounded border border-slate-300 text-slate-900 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="sm:col-span-2">
            <label className="block text-slate-600 font-medium mb-1">Время (минут):</label>
            <input
              type="number"
              min={1}
              max={525600}
              value={newDuration}
              onChange={(e) => setNewDuration(Math.max(1, parseInt(e.target.value, 10) || 1))}
              className="w-full px-2.5 py-1.5 rounded border border-slate-300 text-slate-900 font-mono text-xs focus:outline-none focus:border-blue-500 font-medium"
            />
            <div className="flex items-center gap-1.5 mt-1 text-[10px] text-slate-500">
              <span>Быстро:</span>
              {[3, 10, 30, 60].map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setNewDuration(m)}
                  className="text-blue-600 hover:underline"
                >
                  {m}м
                </button>
              ))}
            </div>
          </div>

          <div className="sm:col-span-2 flex items-end">
            <button
              type="submit"
              className="w-full py-1.5 px-3 rounded bg-amber-600 hover:bg-amber-700 text-white font-semibold text-xs transition"
            >
              Заблокировать
            </button>
          </div>
        </form>
      </div>

      {/* Blocks Table */}
      <div className="bg-white border border-slate-300 rounded p-4 shadow-xs space-y-3">
        <div className="flex items-center justify-between border-b border-slate-200 pb-2.5">
          <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wide">
            Текущий список блокировок
          </h3>
          <span className="text-xs text-slate-500 font-mono">
            Активных: <strong className="text-slate-800">{blocks.filter((b) => b.isActive).length}</strong>
          </span>
        </div>

        <div className="border border-slate-200 rounded overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-600 border-b border-slate-200 font-medium text-[11px] uppercase">
              <tr>
                <th className="py-2.5 px-3">ID</th>
                <th className="py-2.5 px-3">IP-адрес</th>
                <th className="py-2.5 px-3">Причина блокировки</th>
                <th className="py-2.5 px-3">Время блокировки</th>
                <th className="py-2.5 px-3">Осталось времени</th>
                <th className="py-2.5 px-3">Статус</th>
                <th className="py-2.5 px-3 text-right">Действие</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-sans">
              {blocks.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    Таблица blocks пуста. Заблокированных IP-адресов нет.
                  </td>
                </tr>
              ) : (
                blocks.map((b) => {
                  const rem = calculateRemainingSeconds(b.unlockTime);
                  const isAlive = b.isActive && rem > 0;
                  const mins = Math.floor(rem / 60);
                  const secs = rem % 60;

                  return (
                    <tr key={b.id} className="hover:bg-slate-50">
                      <td className="py-2 px-3 font-mono text-slate-400">#{b.id}</td>
                      <td className="py-2 px-3 font-mono font-medium text-slate-900">{b.ipAddress}</td>
                      <td className="py-2 px-3 text-slate-700">{b.reason}</td>
                      <td className="py-2 px-3 font-mono text-slate-500 whitespace-nowrap">
                        {new Date(b.blockedAt).toLocaleTimeString()}
                      </td>
                      <td className="py-2 px-3 font-mono whitespace-nowrap">
                        {isAlive ? (
                          <span className="text-amber-700 font-bold">
                            {mins}:{secs < 10 ? `0${secs}` : secs}
                          </span>
                        ) : (
                          <span className="text-slate-400">Истекло</span>
                        )}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        {isAlive ? (
                          <span className="inline-block px-2 py-0.5 rounded text-[10px] font-bold bg-red-50 text-red-700 border border-red-200">
                            АКТИВЕН
                          </span>
                        ) : (
                          <span className="inline-block px-2 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-600">
                            РАЗБЛОКИРОВАН
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-right whitespace-nowrap">
                        {isAlive ? (
                          <button
                            onClick={() => handleUnblock(b.ipAddress)}
                            className="px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium transition"
                          >
                            Разблокировать
                          </button>
                        ) : (
                          <span className="text-slate-400 text-xs">-</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
