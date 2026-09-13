import React, { useState } from 'react';
import { db, SCHEMA_SQL } from '../services/db';

interface SqlSandboxProps {
  onDatabaseChanged?: () => void;
}

export const SqlSandbox: React.FC<SqlSandboxProps> = ({ onDatabaseChanged }) => {
  const [query, setQuery] = useState('SELECT * FROM events;');
  const [result, setResult] = useState<{
    columns: string[];
    rows: (string | number | boolean | null)[][];
    message?: string;
    error?: string;
  } | null>(() => db.executeSql('SELECT * FROM events;'));
  const [showSchema, setShowSchema] = useState(false);
  const [resetSuccess, setResetSuccess] = useState(false);

  const handleRunSql = () => {
    const res = db.executeSql(query);
    setResult(res);
  };

  const handlePreset = (sql: string) => {
    setQuery(sql);
    const res = db.executeSql(sql);
    setResult(res);
  };

  const handleResetDb = () => {
    db.clearAllData();
    setResetSuccess(true);
    setTimeout(() => setResetSuccess(false), 2000);
    handleRunSql();
    if (onDatabaseChanged) onDatabaseChanged();
  };

  return (
    <div className="space-y-5 font-sans">
      {/* Header */}
      <div className="bg-white border border-slate-300 rounded p-4 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
              Подсистема хранения данных SQLite (usertrack.db)
            </h2>
            <p className="text-xs text-slate-500 mt-0.5 max-w-3xl">
              Интерактивная консоль выполнения SQL-запросов к 4 реляционным таблицам: <code className="text-blue-700 font-mono">users</code>, <code className="text-blue-700 font-mono">events</code>, <code className="text-blue-700 font-mono">incidents</code>, <code className="text-blue-700 font-mono">blocks</code>.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowSchema(!showSchema)}
              className="px-3 py-1.5 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium transition"
            >
              {showSchema ? 'Скрыть schema.sql' : 'Показать schema.sql'}
            </button>

            <button
              onClick={handleResetDb}
              className="px-3 py-1.5 rounded border border-rose-300 bg-rose-50 hover:bg-rose-100 text-rose-700 text-xs font-medium transition"
            >
              {resetSuccess ? 'Очищено' : 'Очистить БД'}
            </button>
          </div>
        </div>
      </div>

      {/* Schema Block */}
      {showSchema && (
        <div className="bg-slate-900 text-slate-200 rounded p-4 font-mono text-xs overflow-x-auto space-y-2">
          <div className="flex justify-between text-slate-400 text-[11px] pb-2 border-b border-slate-800">
            <span>Файл инициализации базы данных: schema.sql</span>
            <span>SQLite 3</span>
          </div>
          <pre className="text-blue-300 leading-relaxed">{SCHEMA_SQL}</pre>
        </div>
      )}

      {/* Query Console */}
      <div className="bg-white border border-slate-300 rounded p-4 shadow-xs space-y-3">
        {/* Presets */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-500 text-[11px]">Быстрые запросы:</span>
          <button
            onClick={() => handlePreset('SELECT id, username, role, full_name, known_ips FROM users;')}
            className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono text-[11px] border border-slate-300"
          >
            users
          </button>
          <button
            onClick={() => handlePreset('SELECT * FROM events ORDER BY timestamp DESC LIMIT 20;')}
            className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono text-[11px] border border-slate-300"
          >
            events
          </button>
          <button
            onClick={() => handlePreset('SELECT * FROM incidents ORDER BY timestamp DESC;')}
            className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono text-[11px] border border-slate-300"
          >
            incidents
          </button>
          <button
            onClick={() => handlePreset('SELECT * FROM blocks WHERE is_active = 1;')}
            className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono text-[11px] border border-slate-300"
          >
            blocks (active)
          </button>
          <button
            onClick={() => handlePreset('SELECT COUNT(*) FROM events;')}
            className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono text-[11px] border border-slate-300"
          >
            COUNT(*) events
          </button>
        </div>

        {/* Textarea */}
        <div>
          <textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            rows={2}
            className="w-full p-2.5 rounded border border-slate-300 font-mono text-xs text-slate-900 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center justify-between">
          <span className="text-[11px] text-slate-500 font-mono">
            База: <code>usertrack.db</code> (SQLite 3)
          </span>

          <button
            onClick={handleRunSql}
            className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition"
          >
            Выполнить SQL
          </button>
        </div>

        {/* Feedback message */}
        {result?.message && (
          <div className="p-2.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-mono">
            {result.message}
          </div>
        )}

        {result?.error && (
          <div className="p-2.5 rounded bg-red-50 border border-red-200 text-red-800 text-xs font-mono">
            Ошибка: {result.error}
          </div>
        )}

        {/* Results Table */}
        {result && result.rows && (
          <div className="border border-slate-200 rounded overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-600 font-mono border-b border-slate-200 text-[11px] uppercase">
                <tr>
                  {result.columns.map((col, idx) => (
                    <th key={idx} className="py-2 px-3">
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono text-slate-800">
                {result.rows.length === 0 ? (
                  <tr>
                    <td colSpan={result.columns.length} className="py-8 text-center text-slate-400">
                      Запрос вернул 0 строк (таблица пуста либо нет совпадений).
                    </td>
                  </tr>
                ) : (
                  result.rows.map((row, rIdx) => (
                    <tr key={rIdx} className="hover:bg-slate-50">
                      {row.map((val, cIdx) => (
                        <td key={cIdx} className="py-2 px-3 whitespace-nowrap">
                          {val === null || val === undefined ? <span className="text-slate-400">NULL</span> : String(val)}
                        </td>
                      ))}
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
