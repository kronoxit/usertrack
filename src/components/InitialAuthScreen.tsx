import React, { useState, useEffect } from 'react';
import { User, UserRole } from '../types';
import { db } from '../services/db';
import { detectRealIp } from '../services/ipDetector';
import { getQuickGeo, lookupIpGeo, GeoLookup } from '../services/geoService';

interface InitialAuthScreenProps {
  users: User[];
  onLoginSuccess: (user: User) => void;
}

export const InitialAuthScreen: React.FC<InitialAuthScreenProps> = ({
  users,
  onLoginSuccess,
}) => {
  const [activeTab, setActiveTab] = useState<'login' | 'register'>('login');

  // Login form state
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState<string | null>(null);

  // Register form state
  const [regUsername, setRegUsername] = useState('');
  const [regFullName, setRegFullName] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regIp, setRegIp] = useState('');
  const [regIpGeo, setRegIpGeo] = useState<GeoLookup | null>(null);
  const [isDetectingIp, setIsDetectingIp] = useState(false);
  const [regError, setRegError] = useState<string | null>(null);

  const fetchClientIp = async (force = false) => {
    setIsDetectingIp(true);
    try {
      const ip = await detectRealIp(force);
      if (ip) {
        setRegIp(ip);
      }
    } finally {
      setIsDetectingIp(false);
    }
  };

  // Detect real client IP on component mount
  useEffect(() => {
    fetchClientIp(false);
  }, []);

  // Update Geo info whenever regIp changes
  useEffect(() => {
    const clean = regIp.trim();
    if (!clean) {
      setRegIpGeo(null);
      return;
    }
    setRegIpGeo(getQuickGeo(clean));
    let isCurrent = true;
    lookupIpGeo(clean).then((geo) => {
      if (isCurrent) setRegIpGeo(geo);
    });
    return () => {
      isCurrent = false;
    };
  }, [regIp]);

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);

    const trimmed = loginUsername.trim();
    if (!trimmed) {
      setLoginError('Введите имя пользователя');
      return;
    }

    const res = db.verifyCredentials(trimmed, loginPassword);
    if (!res.success || !res.user) {
      setLoginError(res.error || 'Ошибка входа');
      return;
    }

    onLoginSuccess(res.user);
  };

  const handleQuickLogin = (user: User) => {
    onLoginSuccess(user);
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setRegError(null);

    const trimmed = regUsername.trim();
    if (!trimmed) {
      setRegError('Укажите имя пользователя');
      return;
    }

    const trimmedPassword = regPassword.trim();
    if (!trimmedPassword) {
      setRegError('Укажите пароль учетной записи');
      return;
    }

    const detected = await detectRealIp();
    const finalIp = regIp.trim() || detected || '192.168.1.100';

    const result = db.createUser({
      username: trimmed,
      fullName: regFullName.trim(),
      password: trimmedPassword,
      role: 'user',
      knownIps: [finalIp],
    });

    if (!result.success || !result.user) {
      setRegError(result.error || 'Ошибка при регистрации');
      return;
    }

    onLoginSuccess(result.user);
  };

  return (
    <div className="min-h-screen bg-slate-100 flex flex-col justify-center py-10 px-4 sm:px-6 lg:px-8 text-slate-800 font-sans">
      <div className="max-w-md w-full mx-auto">
        {/* Title */}
        <div className="text-center mb-6">
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">UserTrack</h1>
          <p className="text-xs text-slate-500 mt-1">Авторизация и регистрация в системе безопасности</p>
        </div>

        {/* Main Box */}
        <div className="bg-white border border-slate-300 rounded shadow-xs overflow-hidden">
          {/* Tabs */}
          <div className="flex border-b border-slate-200 bg-slate-50 text-xs font-semibold">
            <button
              type="button"
              onClick={() => {
                setActiveTab('login');
                setLoginError(null);
              }}
              className={`flex-1 py-3 text-center border-b-2 transition ${
                activeTab === 'login'
                  ? 'border-blue-600 text-blue-700 bg-white'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              Вход в систему
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveTab('register');
                setRegError(null);
              }}
              className={`flex-1 py-3 text-center border-b-2 transition ${
                activeTab === 'register'
                  ? 'border-blue-600 text-blue-700 bg-white'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              Регистрация
            </button>
          </div>

          <div className="p-6">
            {activeTab === 'login' ? (
              <div className="space-y-5 text-xs">
                {/* Existing Accounts Quick Login */}
                {users.length > 0 && (
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-2">
                      Быстрый выбор пользователя:
                    </label>
                    <div className="space-y-1.5">
                      {users.map((u) => {
                        const isChief = Boolean(u.isChiefAdmin || u.id === 1);
                        const isAdmin = u.role === 'admin';
                        return (
                          <div
                            key={u.id}
                            className="flex items-center justify-between p-2.5 rounded border border-slate-200 hover:border-slate-300 hover:bg-slate-50 transition"
                          >
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-slate-900">{u.username}</span>
                                <span
                                  className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                                    isChief
                                      ? 'bg-amber-100 text-amber-900 border border-amber-300'
                                      : isAdmin
                                      ? 'bg-blue-100 text-blue-800 border border-blue-200'
                                      : 'bg-slate-100 text-slate-700'
                                  }`}
                                >
                                  {isChief
                                    ? 'Главный администратор'
                                    : isAdmin
                                    ? 'Администратор'
                                    : 'Пользователь'}
                                </span>
                              </div>
                              {u.fullName && (
                                <div className="text-[11px] text-slate-500 mt-0.5">{u.fullName}</div>
                              )}
                            </div>
                            <button
                              type="button"
                              onClick={() => handleQuickLogin(u)}
                              className="px-3 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white font-medium text-xs transition"
                            >
                              Войти
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Divider */}
                <div className="relative flex items-center justify-center my-3">
                  <div className="border-t border-slate-200 w-full" />
                  <span className="bg-white px-2 text-[11px] text-slate-400 font-medium absolute">
                    или ввод учетных данных
                  </span>
                </div>

                {/* Login Form */}
                <form onSubmit={handleLogin} className="space-y-3">
                  {loginError && (
                    <div className="p-2.5 rounded bg-red-50 border border-red-200 text-red-700 text-xs">
                      {loginError}
                    </div>
                  )}

                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Логин:
                    </label>
                    <input
                      type="text"
                      value={loginUsername}
                      onChange={(e) => setLoginUsername(e.target.value)}
                      className="w-full px-3 py-1.5 rounded border border-slate-300 text-xs focus:outline-none focus:border-blue-500"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Пароль:
                    </label>
                    <input
                      type="password"
                      value={loginPassword}
                      onChange={(e) => setLoginPassword(e.target.value)}
                      className="w-full px-3 py-1.5 rounded border border-slate-300 text-xs focus:outline-none focus:border-blue-500"
                    />
                  </div>

                  <button
                    type="submit"
                    className="w-full py-2 rounded bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs transition mt-2"
                  >
                    Войти в аккаунт
                  </button>
                </form>
              </div>
            ) : (
              /* Registration Form */
              <form onSubmit={handleRegister} className="space-y-3.5 text-xs">
                {regError && (
                  <div className="p-2.5 rounded bg-red-50 border border-red-200 text-red-700 text-xs">
                    {regError}
                  </div>
                )}

                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    Логин (никнейм):
                  </label>
                  <input
                    type="text"
                    required
                    value={regUsername}
                    onChange={(e) => setRegUsername(e.target.value)}
                    className="w-full px-3 py-1.5 rounded border border-slate-300 text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    Пароль:
                  </label>
                  <input
                    type="password"
                    required
                    value={regPassword}
                    onChange={(e) => setRegPassword(e.target.value)}
                    className="w-full px-3 py-1.5 rounded border border-slate-300 text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    ФИО / Отдел:
                  </label>
                  <input
                    type="text"
                    value={regFullName}
                    onChange={(e) => setRegFullName(e.target.value)}
                    className="w-full px-3 py-1.5 rounded border border-slate-300 text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="block text-xs font-medium text-slate-700">
                      Доверенный IP:
                    </label>
                    <button
                      type="button"
                      onClick={() => fetchClientIp(true)}
                      disabled={isDetectingIp}
                      className="text-[10px] text-blue-600 hover:text-blue-800 font-medium flex items-center gap-1 transition"
                      title="Определить ваш реальный IP заново"
                    >
                      {isDetectingIp ? 'Определение...' : '🔄 Определить мой IP'}
                    </button>
                  </div>
                  <div className="relative">
                    <input
                      type="text"
                      value={regIp}
                      onChange={(e) => setRegIp(e.target.value)}
                      placeholder={isDetectingIp ? 'Определение IP адреса...' : 'Ваш реальный IP (напр. 95.24.xx.xx)'}
                      className="w-full px-3 py-1.5 rounded border border-slate-300 text-xs font-mono focus:outline-none focus:border-blue-500 pr-16"
                    />
                    {regIp && !isDetectingIp && (
                      <span className="absolute right-2 top-1.5 text-[10px] text-emerald-600 font-semibold bg-emerald-50 px-1 rounded">
                        ✓ готов
                      </span>
                    )}
                  </div>
                  {regIp.trim() && (
                    <div className="mt-1 text-[11px] text-slate-700 bg-blue-50/70 border border-blue-200/80 px-2 py-1 rounded flex items-center justify-between">
                      <span className="truncate">
                        Локация: <strong className="text-slate-900">{regIpGeo?.flag || '🌐'} {regIpGeo?.city ? `${regIpGeo.city}, ` : ''}{regIpGeo?.country || 'Определение...'}</strong>
                        {regIpGeo?.isp ? <span className="text-slate-500 text-[10px] ml-1">({regIpGeo.isp})</span> : null}
                      </span>
                      {regIpGeo?.country && regIpGeo.country !== 'Определение...' && (
                        <span className="text-[10px] text-emerald-700 font-semibold shrink-0 ml-1">✓ определена</span>
                      )}
                    </div>
                  )}
                  <p className="text-[10px] text-slate-500 mt-1">
                    Определяется автоматически через сетевое подключение. Вы также можете изменить IP вручную.
                  </p>
                </div>

                <button
                  type="submit"
                  className="w-full py-2 rounded bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs transition mt-2"
                >
                  Зарегистрировать и войти
                </button>
              </form>
            )}
          </div>
        </div>

        <p className="text-center text-[11px] text-slate-500 mt-4">
          Для выхода из системы нажмите «Выйти» в правом верхнем углу интерфейса.
        </p>
      </div>
    </div>
  );
};
