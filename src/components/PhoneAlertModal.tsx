import React from 'react';
import { SecurityAlertNotification } from '../types';

interface PhoneAlertModalProps {
  isOpen: boolean;
  onClose: () => void;
  notifications: SecurityAlertNotification[];
  onClear: () => void;
  onSendTestNotification: () => void;
}

export const PhoneAlertModal: React.FC<PhoneAlertModalProps> = ({
  isOpen,
  onClose,
  notifications,
  onClear,
  onSendTestNotification,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 font-sans">
      <div className="bg-white border border-slate-300 rounded shadow-lg w-full max-w-lg overflow-hidden">
        {/* Header */}
        <div className="bg-slate-900 text-white px-4 py-3 flex items-center justify-between border-b border-slate-800">
          <div>
            <div className="text-sm font-bold flex items-center gap-2">
              <span>Оповещения администратора</span>
              <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" />
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              Внутренние уведомления об инцидентах и угрозах
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white px-2 py-1 text-sm font-bold"
          >
            ✕
          </button>
        </div>

        {/* Action strip */}
        <div className="bg-slate-50 px-4 py-2 border-b border-slate-200 flex items-center justify-between text-xs">
          <span className="text-slate-600 font-medium">
            Всего оповещений: <strong className="text-slate-900">{notifications.length}</strong>
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={onSendTestNotification}
              className="text-blue-600 hover:text-blue-800 font-medium text-xs px-2 py-1 rounded hover:bg-blue-50 transition"
            >
              + Тестовое оповещение
            </button>
            {notifications.length > 0 && (
              <button
                onClick={onClear}
                className="text-red-600 hover:text-red-800 font-medium text-xs px-2 py-1 rounded hover:bg-red-50 transition"
              >
                Очистить
              </button>
            )}
          </div>
        </div>

        {/* Notifications Feed */}
        <div className="p-4 max-h-[400px] overflow-y-auto space-y-2.5 bg-slate-50">
          {notifications.length === 0 ? (
            <div className="py-10 text-center text-slate-400 space-y-1">
              <p className="text-xs font-semibold text-slate-700">Оповещений нет</p>
              <p className="text-[11px] text-slate-400 max-w-xs mx-auto">
                Новые оповещения регистрируются при фиксации угроз или создании инцидентов.
              </p>
            </div>
          ) : (
            notifications.map((notif) => {
              const isCritical = notif.severity === 'Critical';
              return (
                <div
                  key={notif.id}
                  className={`p-3 rounded border shadow-xs transition text-xs ${
                    isCritical
                      ? 'bg-red-50 border-red-200 text-red-950'
                      : notif.severity === 'High'
                      ? 'bg-amber-50 border-amber-200 text-amber-950'
                      : 'bg-white border-slate-200 text-slate-900'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <span className="font-bold text-xs">{notif.title}</span>
                    <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                      {new Date(notif.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <p className="text-xs mt-1.5 text-slate-700 leading-relaxed">
                    {notif.message}
                  </p>

                  <div className="mt-2 pt-1.5 border-t border-slate-200/60 flex items-center justify-between text-[10px] text-slate-500">
                    <span>Получатель: {notif.recipient || 'Администратор SIEM'}</span>
                    <span className="text-emerald-700 font-medium">
                      Зафиксировано
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="p-2.5 bg-white border-t border-slate-200 text-center">
          <p className="text-[11px] text-slate-500">
            Оповещения формируются подсистемой анализа угроз и доступны только администраторам.
          </p>
        </div>
      </div>
    </div>
  );
};
