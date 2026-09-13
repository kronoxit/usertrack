import React, { useState, useEffect } from 'react';
import { pythonApi, PythonBackendStatus } from '../services/apiClient';

interface PythonBackendModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const PythonBackendModal: React.FC<PythonBackendModalProps> = ({ isOpen, onClose }) => {
  const [status, setStatus] = useState<PythonBackendStatus | null>(null);
  const [cliOutput, setCliOutput] = useState<string>('');
  const [loadingCmd, setLoadingCmd] = useState<boolean>(false);
  const [activeCommand, setActiveCommand] = useState<string>('status');

  useEffect(() => {
    if (isOpen) {
      pythonApi.getStatus().then((st) => setStatus(st));
      executeCommand('status');
    }
  }, [isOpen]);

  const executeCommand = async (cmd: string) => {
    setLoadingCmd(true);
    setActiveCommand(cmd);
    const out = await pythonApi.runCli(cmd);
    setCliOutput(out);
    setLoadingCmd(false);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-700 w-full max-w-2xl rounded-xl shadow-2xl flex flex-col max-h-[90vh] overflow-hidden text-slate-100 font-sans">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🐍</span>
            <div>
              <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                Бэкенд-ядро на Python 3.10
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800">
                  ● Активен
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Архитектура информационной безопасности «UserTrack» на чистом Python
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
            title="Закрыть"
          >
            ✕
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-xs text-slate-300">
          {/* Architecture overview card */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-[11px] font-bold text-blue-400 uppercase tracking-wider mb-2">
                ⚙️ Компоненты Python ядра
              </div>
              <ul className="space-y-1.5 font-mono text-[11px] text-slate-300">
                <li className="flex items-center justify-between">
                  <span>backend/database.py:</span>
                  <span className="text-emerald-400 font-semibold">SQLite 3 (usertrack.db)</span>
                </li>
                <li className="flex items-center justify-between">
                  <span>backend/rule_engine.py:</span>
                  <span className="text-emerald-400 font-semibold">UEBA & IPS Engine</span>
                </li>
                <li className="flex items-center justify-between">
                  <span>backend/geo_service.py:</span>
                  <span className="text-emerald-400 font-semibold">Python ipaddress</span>
                </li>
                <li className="flex items-center justify-between">
                  <span>backend/analytics.py:</span>
                  <span className="text-emerald-400 font-semibold">Threat Score (0-100)</span>
                </li>
                <li className="flex items-center justify-between">
                  <span>backend/app.py:</span>
                  <span className="text-emerald-400 font-semibold">REST API Server</span>
                </li>
                <li className="flex items-center justify-between">
                  <span>main.py:</span>
                  <span className="text-emerald-400 font-semibold">CLI консоль</span>
                </li>
              </ul>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider mb-2">
                🛡️ Реализованные алгоритмы ИБ
              </div>
              <ul className="space-y-1 text-[11px] text-slate-300">
                <li>• <strong>Brute Force:</strong> скользящее окно 5 ошибок за 5 мин → IPS бан 3 мин</li>
                <li>• <strong>UEBA Time Anomaly:</strong> анализ активности в ночное время (02:00–05:00)</li>
                <li>• <strong>UEBA Geo Anomaly:</strong> проверка новых IP и иностранных локаций</li>
                <li>• <strong>Honeypot-ловушки:</strong> маршруты /.env, /wp-login.php → мгновенный бан</li>
                <li>• <strong>Хеширование паролей:</strong> PBKDF2-SHA256 (100 000 итераций)</li>
              </ul>
            </div>
          </div>

          {/* Interactive Python CLI Simulator */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                <span>💻</span> Консоль диагностики Python ядра (main.py):
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => executeCommand('status')}
                  className={`px-2 py-1 rounded text-[11px] font-mono transition ${
                    activeCommand === 'status'
                      ? 'bg-blue-600 text-white font-bold'
                      : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  --status
                </button>
                <button
                  onClick={() => executeCommand('test_brute_force')}
                  className={`px-2 py-1 rounded text-[11px] font-mono transition ${
                    activeCommand === 'test_brute_force'
                      ? 'bg-blue-600 text-white font-bold'
                      : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  --test-brute-force
                </button>
                <button
                  onClick={() => executeCommand('schema')}
                  className={`px-2 py-1 rounded text-[11px] font-mono transition ${
                    activeCommand === 'schema'
                      ? 'bg-blue-600 text-white font-bold'
                      : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  --schema
                </button>
              </div>
            </div>

            {/* Terminal display */}
            <div className="bg-black/90 border border-slate-800 rounded-lg p-3.5 font-mono text-[11px] leading-relaxed text-emerald-400 overflow-x-auto min-h-[140px] max-h-[220px] shadow-inner">
              <div className="text-slate-500 mb-1">
                $ python3 main.py --{activeCommand}
              </div>
              {loadingCmd ? (
                <div className="text-slate-400 animate-pulse">Выполнение команды в Python 3.10...</div>
              ) : (
                <pre className="whitespace-pre-wrap">{cliOutput || 'Вывод команды...'}</pre>
              )}
            </div>
          </div>

          <div className="text-[11px] text-slate-400 bg-slate-950/70 p-2.5 rounded border border-slate-800/80">
            💡 Вы также можете запустить CLI напрямую в терминале через <code className="text-blue-300 font-mono">python3 main.py --help</code>. Все данные сохраняются в реляционной базе данных SQLite (<code className="text-blue-300 font-mono">backend/usertrack.db</code>).
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <span className="text-[11px] font-mono text-slate-400">
            {status?.engine || 'Python 3.10.12'} • SQLite 3 • UserTrack Core
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition"
          >
            Закрыть
          </button>
        </div>
      </div>
    </div>
  );
};
