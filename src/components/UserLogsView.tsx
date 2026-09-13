import React, { useState, useMemo, useEffect } from 'react';
import { NetworkEvent, User, SecurityIncident } from '../types';
import { db } from '../services/db';
import { ruleEngine } from '../services/ruleEngine';
import { detectRealIp } from '../services/ipDetector';
import { getQuickGeo, lookupIpGeo, GeoLookup } from '../services/geoService';

interface UserLogsViewProps {
  events: NetworkEvent[];
  currentUser: User;
  onUserSwitch?: (username: string) => void;
  onAuthSuccess?: () => void;
  onLogout?: () => void;
  incidents?: SecurityIncident[];
}

export const UserLogsView: React.FC<UserLogsViewProps> = ({
  events,
  currentUser,
  onAuthSuccess,
  onLogout,
  incidents = [],
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('all');

  // User's registered IP (specified during registration or account creation)
  const registeredIp = currentUser.knownIps && currentUser.knownIps.length > 0
    ? currentUser.knownIps[0]
    : '';

  // Authentication simulator state:
  // Password is empty by default
  // IP corresponds to the user's registration IP by default
  const [testPassword, setTestPassword] = useState('');
  const [testIp, setTestIp] = useState(registeredIp);
  const [testIpGeo, setTestIpGeo] = useState<GeoLookup | null>(null);
  const [liveRealIp, setLiveRealIp] = useState<string>('');
  const [liveRealGeo, setLiveRealGeo] = useState<GeoLookup | null>(null);
  const [isDetectingIp, setIsDetectingIp] = useState(false);
  const [simulateNight, setSimulateNight] = useState(false);
  const [authFeedback, setAuthFeedback] = useState<{
    type: 'success' | 'error' | 'warning';
    message: string;
  } | null>(null);

  const fetchLiveIp = async (force = false) => {
    setIsDetectingIp(true);
    try {
      const ip = await detectRealIp(force);
      if (ip) {
        setLiveRealIp(ip);
        const geo = await lookupIpGeo(ip);
        setLiveRealGeo(geo);
        // If user's registered IP is currently empty or mock 192.168.1.10 and testIp is still default, offer to set it
        if (!testIp || testIp === '192.168.1.10' || testIp === '192.168.1.100') {
          setTestIp(ip);
        }
      }
    } finally {
      setIsDetectingIp(false);
    }
  };

  // Sync testIp with registration IP and keep password empty whenever currentUser changes
  useEffect(() => {
    setTestPassword('');
    const userRegIp = currentUser.knownIps && currentUser.knownIps.length > 0
      ? currentUser.knownIps[0]
      : '';
    if (userRegIp && userRegIp !== '192.168.1.10') {
      setTestIp(userRegIp);
    } else {
      fetchLiveIp(false);
    }
    setAuthFeedback(null);
  }, [currentUser.id, currentUser.username, currentUser.knownIps]);

  useEffect(() => {
    fetchLiveIp(false);
  }, []);

  // Update Geo details whenever testIp changes
  useEffect(() => {
    const clean = testIp.trim();
    if (!clean) {
      setTestIpGeo(null);
      return;
    }
    setTestIpGeo(getQuickGeo(clean));
    let isCurrent = true;
    lookupIpGeo(clean).then((geo) => {
      if (isCurrent) setTestIpGeo(geo);
    });
    return () => {
      isCurrent = false;
    };
  }, [testIp]);

  // Filter user's specific events
  const userEvents = useMemo(() => {
    return events.filter(
      (e) =>
        e.username?.toLowerCase() === currentUser.username.toLowerCase() ||
        (currentUser.knownIps && currentUser.knownIps.includes(e.ipAddress))
    );
  }, [events, currentUser]);

  // Incidents for this user
  const userIncidents = useMemo(() => {
    return incidents.filter(
      (inc) =>
        inc.username?.toLowerCase() === currentUser.username.toLowerCase() ||
        inc.description.toLowerCase().includes(currentUser.username.toLowerCase())
    );
  }, [incidents, currentUser]);

  const filteredEvents = useMemo(() => {
    return userEvents.filter((e) => {
      const matchSearch =
        e.ipAddress.toLowerCase().includes(searchTerm.toLowerCase()) ||
        e.details.toLowerCase().includes(searchTerm.toLowerCase());
      const matchType = filterType === 'all' || e.eventType === filterType;
      return matchSearch && matchType;
    });
  }, [userEvents, searchTerm, filterType]);

  const successCount = userEvents.filter((e) => e.eventType === 'AUTH_SUCCESS').length;
  const failureCount = userEvents.filter((e) => e.eventType === 'AUTH_FAILURE').length;
  const lastEvent = userEvents[0];

  const handleLoginSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    // Check if IP is currently blocked
    const activeBlocks = db.getBlocks().filter((b) => b.isActive);
    const isBlocked = activeBlocks.some((b) => b.ipAddress === testIp.trim());

    if (isBlocked) {
      setAuthFeedback({
        type: 'error',
        message: `Доступ с IP ${testIp} заблокирован подсистемой IPS! Соединение сброшено.`,
      });
      return;
    }

    const freshUser = db.getUserByUsername(currentUser.username) || currentUser;
    const isChief = Boolean(freshUser.isChiefAdmin || freshUser.id === 1);
    const expectedPassword = freshUser.passwordPlain || (isChief ? 'admin123' : 'user123');
    const isCorrectPassword = testPassword.trim() === expectedPassword;

    const result = ruleEngine.handleAuthAttempt({
      ip: testIp.trim(),
      username: currentUser.username,
      isSuccess: isCorrectPassword,
      simulatedHour: simulateNight ? 3 : undefined,
      geoOverride: testIpGeo || undefined,
    });

    if (!result.allowed) {
      setAuthFeedback({
        type: 'error',
        message: result.blockedReason || 'Ошибка авторизации: доступ отклонен.',
      });
    } else {
      if (result.incident?.incidentType === 'TIME_ANOMALY') {
        setAuthFeedback({
          type: 'warning',
          message:
            'Авторизация выполнена, но зафиксирована ночная аномалия (03:00). Создан инцидент безопасности.',
        });
      } else if (result.incident?.incidentType === 'GEO_ANOMALY') {
        setAuthFeedback({
          type: 'warning',
          message: `Авторизация выполнена с нового IP-адреса (${testIp}). Создано предупреждение в системе безопасности.`,
        });
      } else {
        setAuthFeedback({
          type: 'success',
          message: `Успешная авторизация в системе «UserTrack»! Пользователь: ${currentUser.username}. Сессия открыта.`,
        });
      }
      if (onAuthSuccess) onAuthSuccess();
    }
  };

  return (
    <div className="space-y-5 font-sans text-xs">
      {/* User Profile Banner */}
      <div className="bg-white border border-slate-300 rounded p-4 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded bg-blue-600 flex items-center justify-center text-white text-base font-bold shadow-xs">
              {currentUser.username[0].toUpperCase()}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-slate-900">{currentUser.username}</h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-50 text-blue-700 border border-blue-200">
                  {currentUser.role.toUpperCase()}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  (ID: {currentUser.id})
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Личный журнал действий пользователя (/logs). Аутентификация и аудит событий.
              </p>
            </div>
          </div>

          {onLogout && (
            <button
              onClick={onLogout}
              className="px-3 py-1.5 rounded border border-slate-300 hover:border-slate-400 bg-white text-slate-700 font-medium transition"
            >
              Сменить аккаунт
            </button>
          )}
        </div>

        {/* Quick User Stat Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 pt-3 border-t border-slate-100 text-xs">
          <div className="bg-slate-50 border border-slate-200 rounded p-2">
            <div className="text-slate-500 text-[11px]">Всего событий</div>
            <div className="text-base font-bold text-slate-900 font-mono mt-0.5">
              {userEvents.length}
            </div>
          </div>
          <div className="bg-slate-50 border border-slate-200 rounded p-2">
            <div className="text-slate-500 text-[11px]">Успешные авторизации</div>
            <div className="text-base font-bold text-emerald-700 font-mono mt-0.5">
              {successCount}
            </div>
          </div>
          <div className="bg-slate-50 border border-slate-200 rounded p-2">
            <div className="text-slate-500 text-[11px]">Ошибки авторизации</div>
            <div className="text-base font-bold text-red-700 font-mono mt-0.5">
              {failureCount}
            </div>
          </div>
          <div className="bg-slate-50 border border-slate-200 rounded p-2">
            <div className="text-slate-500 text-[11px]">Последнее действие</div>
            <div className="text-xs font-medium text-slate-800 mt-1 truncate">
              {lastEvent ? new Date(lastEvent.timestamp).toLocaleTimeString() : 'Нет записей'}
            </div>
          </div>
        </div>
      </div>

      {/* User Security Incidents Section */}
      <div className="bg-white border border-slate-300 rounded p-4 shadow-xs space-y-3">
        <div className="border-b border-slate-200 pb-2.5">
          <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
            Инциденты безопасности учетной записи ({userIncidents.length})
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Инциденты, зарегистрированные системой обнаружения вторжений для пользователя «{currentUser.username}»
          </p>
        </div>

        {userIncidents.length === 0 ? (
          <div className="py-6 text-center text-xs text-slate-500 bg-slate-50 rounded border border-slate-100">
            <p className="font-semibold text-slate-700">Инцидентов безопасности не зафиксировано</p>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Все попытки входа и активность учетной записи «{currentUser.username}» в пределах нормы.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {userIncidents.map((inc) => (
              <div
                key={inc.id}
                className="p-3 rounded border border-slate-200 bg-slate-50 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                        inc.severity === 'Critical'
                          ? 'bg-red-100 text-red-700 border border-red-200'
                          : inc.severity === 'High'
                          ? 'bg-orange-100 text-orange-700 border border-orange-200'
                          : 'bg-amber-100 text-amber-700 border border-amber-200'
                      }`}
                    >
                      {inc.severity.toUpperCase()}
                    </span>
                    <span className="font-semibold text-slate-900">{inc.title}</span>
                    <span className="font-mono text-slate-400 text-[11px]">
                      {new Date(inc.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-slate-600 text-[11px]">{inc.description}</p>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="font-mono text-[11px] bg-slate-200 px-2 py-0.5 rounded text-slate-700">
                    IP: {inc.sourceIp}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                      inc.status === 'Active'
                        ? 'bg-red-50 text-red-700 border border-red-200'
                        : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    }`}
                  >
                    {inc.status === 'Active' ? 'АКТИВЕН' : 'ЗАКРЫТ'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Authentication Form Card */}
      <div className="bg-white border border-slate-300 rounded p-4 shadow-xs space-y-3">
        <div className="border-b border-slate-200 pb-2.5 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
              Форма аутентификации пользователя
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Проверка учетных записей, алгоритмов детекции аномалий (UEBA) и защиты от подбора паролей
            </p>
          </div>
          <div className="text-xs text-slate-500 font-mono">
            Пользователь: <span className="text-blue-700 font-bold">{currentUser.username}</span>
          </div>
        </div>

        <form onSubmit={handleLoginSubmit} className="space-y-3 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-slate-700 font-semibold mb-1">
                Логин учетной записи:
              </label>
              <input
                type="text"
                value={currentUser.username}
                disabled
                className="w-full px-3 py-1.5 rounded border border-slate-200 bg-slate-100 text-slate-600 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-700 font-semibold mb-1">
                Пароль:
              </label>
              <input
                type="password"
                value={testPassword}
                onChange={(e) => setTestPassword(e.target.value)}
                className="w-full px-3 py-1.5 rounded border border-slate-300 font-mono text-slate-900 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-slate-700 font-semibold">
                  IP-адрес подключения:
                </label>
                <button
                  type="button"
                  onClick={() => fetchLiveIp(true)}
                  disabled={isDetectingIp}
                  className="text-[10px] text-blue-600 hover:text-blue-800 font-medium flex items-center gap-1 transition"
                  title="Определить ваш реальный сетевой IP заново"
                >
                  {isDetectingIp ? 'Определение...' : '🔄 Определить IP сети'}
                </button>
              </div>
              <input
                type="text"
                value={testIp}
                onChange={(e) => setTestIp(e.target.value)}
                placeholder="IP адрес (напр. 95.24.xx.xx)"
                className="w-full px-3 py-1.5 rounded border border-slate-300 font-mono text-slate-900 focus:outline-none focus:border-blue-500"
              />
              {testIp.trim() && (
                <div className="mt-1 text-[11px] text-slate-700 bg-blue-50/70 border border-blue-200/80 px-2 py-1 rounded flex items-center justify-between">
                  <span className="truncate">
                    Локация IP: <strong className="text-slate-900">{testIpGeo?.flag || '🌐'} {testIpGeo?.city ? `${testIpGeo.city}, ` : ''}{testIpGeo?.country || 'Определение...'}</strong>
                    {testIpGeo?.isp ? <span className="text-slate-500 text-[10px] ml-1">({testIpGeo.isp})</span> : null}
                  </span>
                  {testIpGeo?.country && testIpGeo.country !== 'Определение...' && (
                    <span className="text-[10px] text-emerald-700 font-semibold shrink-0 ml-1">✓ определена</span>
                  )}
                </div>
              )}
              <div className="flex flex-wrap items-center justify-between gap-1 mt-1 text-[10px]">
                {liveRealIp ? (
                  <button
                    type="button"
                    onClick={() => setTestIp(liveRealIp)}
                    className="text-blue-700 hover:text-blue-900 font-medium underline text-left"
                  >
                    Вставить мой реальный IP: <span className="font-mono font-bold">{liveRealIp}</span>
                    {liveRealGeo?.country && (
                      <span className="ml-1 text-slate-600 font-normal">
                        ({liveRealGeo.flag} {liveRealGeo.city ? `${liveRealGeo.city}, ` : ''}{liveRealGeo.country})
                      </span>
                    )}
                  </button>
                ) : (
                  <span className="text-slate-400">
                    {isDetectingIp ? 'Определяем ваш IP...' : 'Реальный IP не определен'}
                  </span>
                )}
                {testIp && testIp !== registeredIp && (
                  <button
                    type="button"
                    onClick={() => {
                      db.updateUser(currentUser.id, { knownIps: [testIp.trim()] });
                      setAuthFeedback({
                        type: 'success',
                        message: `IP «${testIp.trim()}» сохранен как доверенный для пользователя ${currentUser.username}`,
                      });
                      if (onAuthSuccess) onAuthSuccess();
                    }}
                    className="text-emerald-700 hover:text-emerald-900 font-medium underline"
                    title="Сохранить этот IP как доверенный адрес в профиле пользователя"
                  >
                    Сохранить в профиль
                  </button>
                )}
              </div>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
            <label className="flex items-center gap-2 text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={simulateNight}
                onChange={(e) => setSimulateNight(e.target.checked)}
                className="rounded border-slate-300 text-blue-600"
              />
              <span>Симулировать ночной вход (03:00 — проверка ночной временной аномалии)</span>
            </label>

            <button
              type="submit"
              className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-700 text-white font-semibold transition shadow-xs"
            >
              Выполнить вход
            </button>
          </div>
        </form>

        {authFeedback && (
          <div
            className={`p-2.5 rounded border text-xs font-mono ${
              authFeedback.type === 'success'
                ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                : authFeedback.type === 'warning'
                ? 'bg-amber-50 border-amber-200 text-amber-900'
                : 'bg-red-50 border-red-200 text-red-900'
            }`}
          >
            {authFeedback.message}
          </div>
        )}
      </div>

      {/* User Logs Full-Width Table */}
      <div className="bg-white border border-slate-300 rounded p-4 shadow-xs space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 pb-2.5">
          <div>
            <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
              Журнал сетевых действий пользователя {currentUser.username}
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              История входов, обращений к сервисам и сетевой активности
            </p>
          </div>

          {/* Search and Filters */}
          <div className="flex items-center gap-2 flex-wrap">
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Поиск..."
              className="px-3 py-1.5 rounded border border-slate-300 text-xs w-48 sm:w-56 focus:outline-none focus:border-blue-500"
            />

            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="px-2 py-1.5 rounded border border-slate-300 bg-white text-xs text-slate-700 focus:outline-none"
            >
              <option value="all">Все типы событий</option>
              <option value="AUTH_SUCCESS">Только успешные входы</option>
              <option value="AUTH_FAILURE">Только ошибки входа</option>
              <option value="PORT_ACCESS">Сетевой доступ</option>
            </select>
          </div>
        </div>

        {/* Table */}
        <div className="border border-slate-200 rounded overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-700 border-b border-slate-200 font-semibold text-[11px] uppercase">
              <tr>
                <th className="py-2.5 px-3">Время</th>
                <th className="py-2.5 px-3">Тип события</th>
                <th className="py-2.5 px-3">IP-адрес</th>
                <th className="py-2.5 px-3">Локация</th>
                <th className="py-2.5 px-3">Протокол/Порт</th>
                <th className="py-2.5 px-3">Подробности действия</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-sans">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400">
                    {userEvents.length === 0
                      ? `Для пользователя ${currentUser.username} в базе данных пока нет записанных событий.`
                      : 'Ни одно событие не соответствует текущим критериям поиска.'}
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-50 transition">
                    <td className="py-2.5 px-3 font-mono text-slate-500 whitespace-nowrap">
                      {new Date(ev.timestamp).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      {ev.eventType === 'AUTH_SUCCESS' ? (
                        <span className="inline-block px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          Успешный вход
                        </span>
                      ) : ev.eventType === 'AUTH_FAILURE' ? (
                        <span className="inline-block px-2 py-0.5 rounded text-[10px] font-semibold bg-red-50 text-red-700 border border-red-200">
                          Ошибка входа
                        </span>
                      ) : (
                        <span className="inline-block px-2 py-0.5 rounded text-[10px] font-mono bg-slate-100 text-slate-700 border border-slate-200">
                          {ev.eventType}
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-slate-900 font-medium whitespace-nowrap">
                      {ev.ipAddress}
                    </td>
                    <td className="py-2.5 px-3 text-slate-700 whitespace-nowrap">
                      {(() => {
                        const rowGeo = getQuickGeo(ev.ipAddress);
                        const hasRealGeo = rowGeo.country && rowGeo.country !== 'Интернет';
                        const locationText = ev.city && ev.country
                          ? `${ev.city}, ${ev.country}`
                          : (hasRealGeo
                              ? `${rowGeo.city ? `${rowGeo.city}, ` : ''}${rowGeo.country}`
                              : (ev.country || 'Локальная сеть'));
                        const flag = rowGeo.flag || (locationText.includes('Россия') ? '🇷🇺' : '🌐');
                        return (
                          <span className="inline-flex items-center gap-1.5">
                            <span>{flag}</span>
                            <span>{locationText}</span>
                          </span>
                        );
                      })()}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-500 whitespace-nowrap">
                      {ev.protocol || 'TCP'}:{ev.port}
                    </td>
                    <td className="py-2.5 px-3 text-slate-800">
                      {ev.details}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between text-xs text-slate-500 pt-1">
          <span>Показано: {filteredEvents.length} из {userEvents.length} записей</span>
          <span className="text-slate-400">
            Журналирование SQLite
          </span>
        </div>
      </div>
    </div>
  );
};
