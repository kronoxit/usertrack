import React from 'react';
import { UserRole, User } from '../types';

interface NavbarProps {
  currentRole: UserRole;
  onRoleChange?: (role: UserRole) => void;
  activeTab: string;
  onTabChange: (tab: string) => void;
  blockedCount: number;
  criticalIncidentsCount: number;
  eventsCount: number;
  notificationsCount: number;
  onClearDb: () => void;
  onOpenPhoneAlerts: () => void;
  onOpenPythonInfo?: () => void;
  onLogout: () => void;
  users?: User[];
  currentUser?: User;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentRole,
  activeTab,
  onTabChange,
  blockedCount,
  criticalIncidentsCount,
  eventsCount,
  notificationsCount,
  onClearDb,
  onOpenPhoneAlerts,
  onOpenPythonInfo,
  onLogout,
  users = [],
  currentUser,
}) => {
  return (
    <header className="bg-slate-900 border-b border-slate-800 text-white sticky top-0 z-40 font-sans">
      {/* Top Brand & Global Stats */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-13">
          {/* Logo & Product Name */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => onTabChange(currentRole === 'admin' ? 'dashboard' : 'logs')}
              className="flex items-center gap-2 text-left"
            >
              <div className="font-bold text-base text-white tracking-tight">
                UserTrack
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                SIEM / IPS
              </span>
            </button>
          </div>

          {/* Indicators & Actions */}
          <div className="flex items-center gap-2 text-xs">
            {/* Database indicator */}
            <div className="hidden sm:inline-block px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono text-[11px]">
              БД: {eventsCount} соб.
            </div>

            {/* On-site Notifications button (Admin only) */}
            {currentRole === 'admin' && (
              <button
                onClick={onOpenPhoneAlerts}
                title="Оповещения безопасности администратора"
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 flex items-center gap-1.5 font-medium transition"
              >
                <span>Оповещения</span>
                {notificationsCount > 0 && (
                  <span className="px-1.5 py-0.2 rounded bg-red-600 text-white font-mono text-[10px] font-bold">
                    {notificationsCount}
                  </span>
                )}
              </button>
            )}

            {/* Critical incidents badge */}
            {criticalIncidentsCount > 0 && (
              <button
                onClick={() => onTabChange('incidents')}
                className="px-2.5 py-1 rounded bg-red-950 border border-red-800 text-red-300 font-medium hover:bg-red-900 transition"
              >
                Угроз: {criticalIncidentsCount}
              </button>
            )}

            {/* Active blocks badge */}
            {blockedCount > 0 && (
              <button
                onClick={() => onTabChange('ips')}
                className="px-2.5 py-1 rounded bg-amber-950 border border-amber-800 text-amber-300 font-medium hover:bg-amber-900 transition"
              >
                Блокировок: {blockedCount}
              </button>
            )}

            {/* Clear Database button (Admin only) */}
            {currentRole === 'admin' && (
              <button
                onClick={onClearDb}
                title="Очистить события, инциденты и блокировки в базе данных"
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white transition"
              >
                Очистить БД
              </button>
            )}

            {/* Current Active Account & Logout */}
            <div className="flex items-center bg-slate-950 px-2.5 py-1 rounded border border-slate-800 ml-1 gap-2">
              <span className="text-xs font-mono font-bold text-slate-200">
                {currentUser?.username || 'аккаунт'}
              </span>

              <span
                className={`px-1.5 py-0.2 rounded text-[9px] font-bold tracking-wider ${
                  currentRole === 'admin'
                    ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                }`}
              >
                {currentRole.toUpperCase()}
              </span>

              <div className="h-3 w-[1px] bg-slate-800" />

              <button
                onClick={onLogout}
                title="Выйти из учетной записи"
                className="text-slate-400 hover:text-red-300 text-[11px] transition"
              >
                Выйти
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs (clean, solid text tabs without clutter icons) */}
      <div className="bg-slate-800/80 border-t border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <nav className="flex space-x-1 overflow-x-auto py-1.5 text-xs font-medium">
            {currentRole === 'admin' ? (
              <>
                <button
                  onClick={() => onTabChange('dashboard')}
                  className={`px-3 py-1.5 rounded transition whitespace-nowrap ${
                    activeTab === 'dashboard'
                      ? 'bg-slate-900 text-white font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-700/50'
                  }`}
                >
                  Обзор
                </button>

                <button
                  onClick={() => onTabChange('events')}
                  className={`px-3 py-1.5 rounded transition whitespace-nowrap ${
                    activeTab === 'events'
                      ? 'bg-slate-900 text-white font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-700/50'
                  }`}
                >
                  События ({eventsCount})
                </button>

                <button
                  onClick={() => onTabChange('incidents')}
                  className={`px-3 py-1.5 rounded transition whitespace-nowrap ${
                    activeTab === 'incidents'
                      ? 'bg-slate-900 text-white font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-700/50'
                  }`}
                >
                  Инциденты
                </button>

                <button
                  onClick={() => onTabChange('ips')}
                  className={`px-3 py-1.5 rounded transition whitespace-nowrap ${
                    activeTab === 'ips'
                      ? 'bg-slate-900 text-white font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-700/50'
                  }`}
                >
                  Блокировки IPS ({blockedCount})
                </button>

                <button
                  onClick={() => onTabChange('users')}
                  className={`px-3 py-1.5 rounded transition whitespace-nowrap ${
                    activeTab === 'users'
                      ? 'bg-slate-900 text-white font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-700/50'
                  }`}
                >
                  Пользователи ({users.length})
                </button>

                <button
                  onClick={() => onTabChange('database')}
                  className={`px-3 py-1.5 rounded transition whitespace-nowrap ${
                    activeTab === 'database'
                      ? 'bg-slate-900 text-white font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-700/50'
                  }`}
                >
                  База данных SQLite
                </button>
              </>
            ) : (
              <button
                onClick={() => onTabChange('logs')}
                className={`px-3 py-1.5 rounded transition whitespace-nowrap ${
                  activeTab === 'logs'
                    ? 'bg-slate-900 text-white font-semibold'
                    : 'text-slate-300 hover:text-white hover:bg-slate-700/50'
                }`}
              >
                Журнал действий (/logs)
              </button>
            )}
          </nav>
        </div>
      </div>
    </header>
  );
};
