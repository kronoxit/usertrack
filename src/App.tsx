import React, { useState, useEffect, useCallback } from 'react';
import { db } from './services/db';
import { UserRole, NetworkEvent, SecurityIncident, IPBlock, User, SecurityAlertNotification } from './types';
import { Navbar } from './components/Navbar';
import { DashboardOverview } from './components/DashboardOverview';
import { EventsTable } from './components/EventsTable';
import { IncidentsManager } from './components/IncidentsManager';
import { IPSManager } from './components/IPSManager';
import { SqlSandbox } from './components/SqlSandbox';
import { UserLogsView } from './components/UserLogsView';
import { UsersManager } from './components/UsersManager';
import { PhoneAlertModal } from './components/PhoneAlertModal';
import { InitialAuthScreen } from './components/InitialAuthScreen';
import { PythonBackendModal } from './components/PythonBackendModal';

export default function App() {
  const [currentUser, setCurrentUser] = useState<User | null>(() => {
    try {
      const savedUsername = localStorage.getItem('usertrack_active_username');
      if (savedUsername) {
        const found = db.getUserByUsername(savedUsername);
        if (found) return found;
      }
    } catch {
      // Ignore
    }
    return null;
  });

  const [currentRole, setCurrentRole] = useState<UserRole>(() => currentUser?.role || 'admin');
  const [activeTab, setActiveTab] = useState<string>(() => (currentUser?.role === 'user' ? 'logs' : 'dashboard'));
  const [events, setEvents] = useState<NetworkEvent[]>(() => db.getEvents());
  const [incidents, setIncidents] = useState<SecurityIncident[]>(() => db.getIncidents());
  const [blocks, setBlocks] = useState<IPBlock[]>(() => db.getBlocks());
  const [notifications, setNotifications] = useState<SecurityAlertNotification[]>(() => db.getNotifications());
  const [users, setUsers] = useState<User[]>(() => db.getUsers());
  const [notification, setNotification] = useState<{ message: string; type: 'info' | 'critical' } | null>(null);
  const [isPhoneModalOpen, setIsPhoneModalOpen] = useState(false);
  const [isPythonModalOpen, setIsPythonModalOpen] = useState(false);

  // Sync state from Database
  const refreshDbState = useCallback(() => {
    setEvents(db.getEvents());
    setIncidents(db.getIncidents());
    setBlocks(db.getBlocks());
    setNotifications(db.getNotifications());
    const freshUsers = db.getUsers();
    setUsers(freshUsers);

    // Keep currentUser reference up to date if user list changes
    if (currentUser) {
      const updatedCurrent = freshUsers.find((u) => u.id === currentUser.id);
      if (updatedCurrent) {
        setCurrentUser(updatedCurrent);
        setCurrentRole(updatedCurrent.role);
        try {
          localStorage.setItem('usertrack_active_username', updatedCurrent.username);
        } catch {
          // Ignore
        }
      } else {
        // Current user was deleted from system
        setCurrentUser(null);
        try {
          localStorage.removeItem('usertrack_active_username');
        } catch {
          // Ignore
        }
        setNotification({
          message: 'Ваша учетная запись была удалена администратором',
          type: 'critical',
        });
        setTimeout(() => setNotification(null), 4000);
      }
    }
  }, [currentUser]);

  useEffect(() => {
    const unsubDb = db.subscribe(refreshDbState);
    return () => {
      unsubDb();
    };
  }, [refreshDbState]);

  const handleLoginSuccess = (user: User) => {
    setCurrentUser(user);
    setCurrentRole(user.role);
    try {
      localStorage.setItem('usertrack_active_username', user.username);
    } catch {
      // Ignore
    }

    if (user.role === 'admin') {
      setActiveTab('dashboard');
    } else {
      setActiveTab('logs');
    }

    setNotification({
      message: `Вход выполнен: ${user.username} (${user.role === 'admin' ? 'Администратор SIEM' : 'Пользователь'})`,
      type: 'info',
    });
    setTimeout(() => setNotification(null), 3500);
  };

  const handleLogout = () => {
    const prevName = currentUser?.username;
    setCurrentUser(null);
    try {
      localStorage.removeItem('usertrack_active_username');
    } catch {
      // Ignore
    }

    setNotification({
      message: prevName ? `Сессия пользователя ${prevName} завершена. Возврат на начальный экран.` : 'Выполнен выход из системы',
      type: 'info',
    });
    setTimeout(() => setNotification(null), 3000);
  };

  const handleBlockIp = (ip: string, reason: string, durationMinutes: number = 3) => {
    db.applyBlock(ip, reason, durationMinutes, 'ADMIN_MANUAL');
    setActiveTab('ips');
    setNotification({
      message: `IP-адрес ${ip} заблокирован администратором на ${durationMinutes} мин`,
      type: 'critical',
    });
    setTimeout(() => setNotification(null), 4000);
  };

  const handleClearDb = () => {
    db.clearAllData();
    refreshDbState();
    setNotification({
      message: 'Дашборд и база данных очищены (0 событий, 0 инцидентов, 0 блокировок)',
      type: 'info',
    });
    setTimeout(() => setNotification(null), 3500);
  };

  const handleClearNotifications = () => {
    db.clearNotifications();
    refreshDbState();
  };

  const handleSendTestNotification = () => {
    db.addNotification({
      channel: 'IN_APP',
      recipient: 'Администратор SIEM',
      title: 'Тестовое оповещение: Проверка подсистемы мониторинга',
      message: 'Внутренняя система оповещений UserTrack функционирует штатно. Оповещение зафиксировано на сайте.',
      severity: 'Low',
    });
    refreshDbState();
  };

  const activeBlocksCount = blocks.filter((b) => b.isActive).length;
  const criticalCount = incidents.filter((i) => i.severity === 'Critical' && i.status === 'Active').length;

  // If user is not authenticated, display the dedicated Initial Registration & Login Screen
  if (!currentUser) {
    return (
      <>
        {notification && (
          <div
            className={`fixed top-4 right-4 z-50 px-4 py-3 rounded border shadow max-w-md flex items-center justify-between gap-3 text-xs ${
              notification.type === 'critical'
                ? 'bg-red-50 border-red-300 text-red-900'
                : 'bg-blue-50 border-blue-300 text-blue-900'
            }`}
          >
            <span>{notification.message}</span>
            <button
              onClick={() => setNotification(null)}
              className="text-slate-400 hover:text-slate-700 font-bold ml-2"
            >
              ✕
            </button>
          </div>
        )}
        <InitialAuthScreen users={users} onLoginSuccess={handleLoginSuccess} />
      </>
    );
  }

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900 flex flex-col font-sans antialiased">
      {/* Status Notification Toast */}
      {notification && (
        <div
          className={`fixed top-16 right-4 z-50 px-4 py-3 rounded border shadow max-w-md flex items-center justify-between gap-3 text-xs ${
            notification.type === 'critical'
              ? 'bg-red-50 border-red-300 text-red-900'
              : 'bg-blue-50 border-blue-300 text-blue-900'
          }`}
        >
          <span>{notification.message}</span>
          <button
            onClick={() => setNotification(null)}
            className="text-slate-400 hover:text-slate-700 font-bold ml-2"
          >
            ✕
          </button>
        </div>
      )}

      {/* Main Navigation Header */}
      <Navbar
        currentRole={currentUser.role}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        blockedCount={activeBlocksCount}
        criticalIncidentsCount={criticalCount}
        eventsCount={events.length}
        notificationsCount={notifications.length}
        onClearDb={handleClearDb}
        onOpenPhoneAlerts={() => setIsPhoneModalOpen(true)}
        onOpenPythonInfo={() => setIsPythonModalOpen(true)}
        onLogout={handleLogout}
        users={users}
        currentUser={currentUser}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {currentUser.role === 'admin' ? (
          <>
            {activeTab === 'dashboard' && (
              <DashboardOverview
                events={events}
                incidents={incidents}
                blocks={blocks}
                onNavigateTab={setActiveTab}
                onOpenPhoneAlerts={() => setIsPhoneModalOpen(true)}
                notificationsCount={notifications.length}
                onNotification={(message, type) => {
                  setNotification({ message, type: type || 'info' });
                  setTimeout(() => setNotification(null), 4000);
                }}
              />
            )}
            {activeTab === 'events' && <EventsTable events={events} />}
            {activeTab === 'incidents' && (
              <IncidentsManager incidents={incidents} onBlockIp={handleBlockIp} />
            )}
            {activeTab === 'ips' && <IPSManager blocks={blocks} />}
            {activeTab === 'users' && (
              <UsersManager
                users={users}
                currentUser={currentUser}
                onRefresh={refreshDbState}
                onNotification={(message, type) => {
                  setNotification({ message, type: type || 'info' });
                  setTimeout(() => setNotification(null), 4000);
                }}
              />
            )}
            {activeTab === 'database' && <SqlSandbox onDatabaseChanged={refreshDbState} />}
          </>
        ) : (
          <UserLogsView
            events={events}
            currentUser={currentUser}
            onAuthSuccess={refreshDbState}
            onLogout={handleLogout}
            incidents={incidents}
          />
        )}
      </main>

      {/* Internal Security Alert Modal */}
      <PhoneAlertModal
        isOpen={isPhoneModalOpen}
        onClose={() => setIsPhoneModalOpen(false)}
        notifications={notifications}
        onClear={handleClearNotifications}
        onSendTestNotification={handleSendTestNotification}
      />

      {/* Python Backend Diagnostics Modal */}
      <PythonBackendModal
        isOpen={isPythonModalOpen}
        onClose={() => setIsPythonModalOpen(false)}
      />

      {/* Standard Clean Footer */}
      <footer className="bg-white border-t border-slate-200 py-4 text-xs text-slate-600">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-800">UserTrack SIEM & IPS</span>
            <span className="text-slate-300">|</span>
            <span>
              Пользователь: <strong className="text-slate-900">{currentUser.username}</strong> ({currentUser.role})
            </span>
          </div>

          <div className="flex items-center gap-4 font-mono text-[11px] text-slate-500">
            <span>Пользователей: {users.length}</span>
            <span>•</span>
            <span>Событий: {events.length}</span>
            <span>•</span>
            <span>Блокировок: {activeBlocksCount}</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
