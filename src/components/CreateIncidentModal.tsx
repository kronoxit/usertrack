import React, { useState, useEffect } from 'react';
import { db } from '../services/db';
import { IncidentType, IncidentSeverity, IncidentStatus, User } from '../types';

interface CreateIncidentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onIncidentCreated: (msg: string) => void;
}

const TYPE_CONFIG: Record<
  IncidentType,
  {
    label: string;
    defaultSeverity: IncidentSeverity;
    defaultIp: string;
    defaultRule: string;
    defaultDescription: string;
  }
> = {
  BRUTE_FORCE: {
    label: 'BRUTE_FORCE (Подбор пароля / Brute Force)',
    defaultSeverity: 'Critical',
    defaultIp: '194.26.29.112',
    defaultRule: 'RULE-AUTH-BRUTEFORCE',
    defaultDescription: 'Серия неудачных попыток аутентификации (5 подряд) на учётную запись пользователя',
  },
  TIME_ANOMALY: {
    label: 'TIME_ANOMALY (Ночная временная аномалия / Вне графика)',
    defaultSeverity: 'Medium',
    defaultIp: '192.168.1.10',
    defaultRule: 'RULE-TIME-NIGHT-0300',
    defaultDescription: 'Вход в систему в нерабочее ночное время (03:15). Потенциальная компрометация учетной записи',
  },
  GEO_ANOMALY: {
    label: 'GEO_ANOMALY (Аномальная геолокация / GeoIP)',
    defaultSeverity: 'High',
    defaultIp: '85.114.120.4',
    defaultRule: 'RULE-GEO-FOREIGN-IP',
    defaultDescription: 'Вход с зарубежного IP-адреса (Амстердам, Нидерланды). Ранее пользователь подключался только из корпоративной сети',
  },
  HONEYPOT_TRIGGER: {
    label: 'HONEYPOT_TRIGGER (Срабатывание сетевой ловушки / Honeypot)',
    defaultSeverity: 'Critical',
    defaultIp: '185.190.140.22',
    defaultRule: 'SIG-HONEYPOT-INTERACTION',
    defaultDescription: 'Попытка несанкционированного взаимодействия с ловушкой Honeypot (порт 2222)',
  },
  CRITICAL_PORT_ACCESS: {
    label: 'CRITICAL_PORT_ACCESS (Доступ к закрытому порту / SSH 22)',
    defaultSeverity: 'High',
    defaultIp: '185.220.101.5',
    defaultRule: 'SIG-RULE-PORT-22-EXTERNAL',
    defaultDescription: 'Несанкционированная попытка подключения к сервису SSH (порт 22) из внешней сети',
  },
  PORT_SCAN: {
    label: 'PORT_SCAN (Сканирование портов / Разведка)',
    defaultSeverity: 'Medium',
    defaultIp: '45.154.255.89',
    defaultRule: 'RULE-PORT-SWEEP-DETECTED',
    defaultDescription: 'Обнаружена сигнатура разведки сети: последовательный перебор портов 21, 22, 80, 443, 3306, 8080',
  },
  MALICIOUS_PAYLOAD: {
    label: 'MALICIOUS_PAYLOAD (Вредоносный запрос / SQLi / XSS)',
    defaultSeverity: 'Critical',
    defaultIp: '91.240.118.22',
    defaultRule: 'SIG-SQLI-DETECTION-01',
    defaultDescription: "Обнаружен вредоносный SQL-пейлоад: ' OR 1=1; DROP TABLE users; -- в теле сетевого запроса",
  },
};

export const CreateIncidentModal: React.FC<CreateIncidentModalProps> = ({
  isOpen,
  onClose,
  onIncidentCreated,
}) => {
  const [users, setUsers] = useState<User[]>([]);
  const [incidentType, setIncidentType] = useState<IncidentType>('BRUTE_FORCE');
  const [status, setStatus] = useState<IncidentStatus>('Active');

  // Automatically determined by incident type
  const severity = TYPE_CONFIG[incidentType].defaultSeverity;
  const ruleTriggered = TYPE_CONFIG[incidentType].defaultRule;

  // Nickname selection state: either an existing username, system user, or custom input
  const [selectedUserChoice, setSelectedUserChoice] = useState<string>('artem');
  const [customUsername, setCustomUsername] = useState<string>('');
  const [sourceIp, setSourceIp] = useState<string>(TYPE_CONFIG.BRUTE_FORCE.defaultIp);
  const [description, setDescription] = useState<string>(TYPE_CONFIG.BRUTE_FORCE.defaultDescription);

  // Load existing registered users when modal opens
  useEffect(() => {
    if (isOpen) {
      const allUsers = db.getUsers();
      setUsers(allUsers);
      // Default to chief admin or first registered user if available
      const chief = allUsers.find((u) => u.isChiefAdmin || u.id === 1);
      const defaultNick = chief ? chief.username : allUsers[0]?.username || 'admin';
      setSelectedUserChoice(defaultNick);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleTypeChange = (newType: IncidentType) => {
    setIncidentType(newType);
    const config = TYPE_CONFIG[newType];
    if (config) {
      setSourceIp(config.defaultIp);
      setDescription(config.defaultDescription);
    }
  };

  const handleUserSelect = (val: string) => {
    setSelectedUserChoice(val);
    if (val !== '__custom__') {
      const foundUser = users.find((u) => u.username.toLowerCase() === val.toLowerCase());
      if (foundUser && foundUser.knownIps && foundUser.knownIps.length > 0) {
        setSourceIp(foundUser.knownIps[0]);
      }
    }
  };

  const getEffectiveUsername = (): string => {
    if (selectedUserChoice === '__custom__') {
      return customUsername.trim() || 'unknown';
    }
    return selectedUserChoice;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const targetUser = getEffectiveUsername();
    const created = db.createCustomIncident({
      incidentType,
      severity,
      status,
      username: targetUser,
      sourceIp: sourceIp.trim() || '194.26.29.112',
      description: description.trim(),
      ruleTriggered,
      applyIpsBlock: false,
      recordNetworkEvent: true, // Всегда включено по умолчанию
      sendAlertNotification: true, // Всегда включено по умолчанию
    });

    onIncidentCreated(
      `Создан инцидент #${created.id} [${incidentType}] (Пользователь: ${targetUser}, IP: ${created.sourceIp})`
    );
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/40 flex items-center justify-center p-4">
      <div className="bg-white border border-slate-300 rounded shadow-lg max-w-lg w-full overflow-hidden">
        {/* Header */}
        <div className="px-4 py-3 bg-slate-100 border-b border-slate-200 flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-800">Создание инцидента безопасности</h3>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 text-sm font-bold leading-none p-1"
            title="Закрыть"
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-3.5 text-xs text-slate-700 max-h-[82vh] overflow-y-auto">
          {/* Incident Type Selector */}
          <div>
            <label className="block font-medium text-slate-700 mb-1">
              Тип инцидента:
            </label>
            <select
              value={incidentType}
              onChange={(e) => handleTypeChange(e.target.value as IncidentType)}
              className="w-full px-2.5 py-1.5 rounded border border-slate-300 bg-white text-xs text-slate-900 font-medium focus:outline-none focus:border-blue-500"
            >
              {(Object.keys(TYPE_CONFIG) as IncidentType[]).map((typeKey) => (
                <option key={typeKey} value={typeKey}>
                  {TYPE_CONFIG[typeKey].label}
                </option>
              ))}
            </select>
          </div>

          {/* User / Nickname Selection */}
          <div className="p-3 bg-slate-50 border border-slate-200 rounded space-y-2">
            <label className="block font-medium text-slate-800">
              Выбор целевого пользователя (никнейм):
            </label>

            <select
              value={selectedUserChoice}
              onChange={(e) => handleUserSelect(e.target.value)}
              className="w-full px-2.5 py-1.5 rounded border border-slate-300 bg-white text-xs text-slate-800 focus:outline-none focus:border-blue-500 font-medium"
            >
              <optgroup label="Зарегистрированные пользователи">
                {users.map((u) => {
                  const isChief = Boolean(u.isChiefAdmin || u.id === 1);
                  const roleLabel = isChief
                    ? 'Главный администратор'
                    : u.role === 'admin'
                    ? 'Администратор'
                    : 'Пользователь';
                  const cleanFullName = (u.fullName || '').replace(/\(Главный администратор\)|\(Администратор\)/gi, '').trim();
                  const namePart = cleanFullName && cleanFullName.toLowerCase() !== u.username.toLowerCase()
                    ? ` (${cleanFullName})`
                    : '';
                  return (
                    <option key={u.id} value={u.username}>
                      {u.username}{namePart} — {roleLabel}
                    </option>
                  );
                })}
              </optgroup>
              <optgroup label="Системные / Внешние субъекты">
                <option value="root">root (системный суперпользователь)</option>
                <option value="guest">guest (гостевой)</option>
                <option value="anonymous">anonymous (анонимный)</option>
              </optgroup>
              <option value="__custom__">Другой никнейм (ввести вручную)...</option>
            </select>

            {selectedUserChoice === '__custom__' && (
              <div className="pt-1">
                <input
                  type="text"
                  required
                  value={customUsername}
                  onChange={(e) => setCustomUsername(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded border border-slate-300 bg-white text-xs text-slate-900 focus:outline-none focus:border-blue-500"
                />
              </div>
            )}
            <div className="text-[11px] text-slate-500">
              Текущий никнейм для записи в инцидент: <strong className="text-slate-800 font-mono">{getEffectiveUsername()}</strong>
            </div>
          </div>

          {/* Severity & Status */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block font-medium text-slate-700 mb-1">
                Степень критичности:
              </label>
              <div className="px-2.5 py-1.5 rounded border border-slate-200 bg-slate-50 flex items-center justify-between text-xs min-h-[34px]">
                <span className="text-slate-500 text-[11px]">Автоматически:</span>
                <span
                  className={`px-2 py-0.5 rounded font-bold text-[11px] border ${
                    severity === 'Critical'
                      ? 'bg-red-100 text-red-700 border-red-200'
                      : severity === 'High'
                      ? 'bg-orange-100 text-orange-700 border-orange-200'
                      : severity === 'Medium'
                      ? 'bg-amber-100 text-amber-700 border-amber-200'
                      : 'bg-blue-100 text-blue-700 border-blue-200'
                  }`}
                >
                  {severity} ({severity === 'Critical' ? 'Критический' : severity === 'High' ? 'Высокий' : severity === 'Medium' ? 'Средний' : 'Низкий'})
                </span>
              </div>
            </div>

            <div>
              <label className="block font-medium text-slate-700 mb-1">
                Начальный статус:
              </label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as IncidentStatus)}
                className="w-full px-2.5 py-1.5 rounded border border-slate-300 bg-white text-xs font-medium focus:outline-none focus:border-blue-500 min-h-[34px]"
              >
                <option value="Active">Active (Активен)</option>
                <option value="Investigating">Investigating (В расследовании)</option>
                <option value="Resolved">Resolved (Закрыт)</option>
              </select>
            </div>
          </div>

          {/* Source IP & Rule Triggered */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block font-medium text-slate-700 mb-1">
                IP-адрес источника:
              </label>
              <input
                type="text"
                required
                value={sourceIp}
                onChange={(e) => setSourceIp(e.target.value)}
                className="w-full px-2.5 py-1.5 rounded border border-slate-300 font-mono text-xs focus:outline-none focus:border-blue-500 min-h-[34px]"
              />
            </div>

            <div>
              <label className="block font-medium text-slate-700 mb-1">
                Сработавшее правило:
              </label>
              <div className="px-2.5 py-1.5 rounded border border-slate-200 bg-slate-50 font-mono text-xs text-slate-800 font-semibold truncate min-h-[34px] flex items-center">
                {ruleTriggered}
              </div>
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="block font-medium text-slate-700 mb-1">
              Подробное описание инцидента:
            </label>
            <textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full px-2.5 py-1.5 rounded border border-slate-300 text-xs focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Footer Buttons */}
          <div className="pt-2 flex items-center justify-end gap-2 border-t border-slate-200">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium transition"
            >
              Отмена
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 rounded bg-red-600 hover:bg-red-700 text-white text-xs font-medium transition"
            >
              Создать инцидент
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
