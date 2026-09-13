import React, { useState, useEffect } from 'react';
import { User, UserRole } from '../types';
import { db } from '../services/db';
import { detectRealIp } from '../services/ipDetector';
import { getQuickGeo, lookupIpGeo, GeoLookup } from '../services/geoService';

interface UsersManagerProps {
  users: User[];
  currentUser: User;
  onRefresh: () => void;
  onNotification: (message: string, type?: 'info' | 'critical') => void;
}

export const UsersManager: React.FC<UsersManagerProps> = ({
  users,
  currentUser,
  onRefresh,
  onNotification,
}) => {
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [userToDelete, setUserToDelete] = useState<User | null>(null);

  // New user form state (always role 'user')
  const [newUsername, setNewUsername] = useState('');
  const [newFullName, setNewFullName] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newIp, setNewIp] = useState('');
  const [newIpGeo, setNewIpGeo] = useState<GeoLookup | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  // Auto-detect IP when creation modal opens
  useEffect(() => {
    if (isCreateModalOpen) {
      detectRealIp().then((ip) => {
        if (ip) {
          setNewIp((prev) => (prev ? prev : ip));
        }
      });
    }
  }, [isCreateModalOpen]);

  useEffect(() => {
    const clean = newIp.trim();
    if (!clean) {
      setNewIpGeo(null);
      return;
    }
    setNewIpGeo(getQuickGeo(clean));
    let isCurrent = true;
    lookupIpGeo(clean).then((g) => {
      if (isCurrent) setNewIpGeo(g);
    });
    return () => {
      isCurrent = false;
    };
  }, [newIp]);

  // Chief Admin Profile Edit State
  const [isEditProfileModalOpen, setIsEditProfileModalOpen] = useState(false);
  const [editUsername, setEditUsername] = useState('');
  const [editFullName, setEditFullName] = useState('');
  const [editProfileError, setEditProfileError] = useState<string | null>(null);

  const isChiefAdmin = Boolean(currentUser.isChiefAdmin || currentUser.id === 1);

  const handleOpenEditProfile = () => {
    setEditUsername(currentUser.username);
    setEditFullName(currentUser.fullName || '');
    setEditProfileError(null);
    setIsEditProfileModalOpen(true);
  };

  const handleSaveProfile = (e: React.FormEvent) => {
    e.preventDefault();
    setEditProfileError(null);

    const trimmedUser = editUsername.trim();
    if (!trimmedUser) {
      setEditProfileError('Укажите никнейм (логин)');
      return;
    }

    const res = db.updateChiefAdminProfile(currentUser.id, trimmedUser, editFullName.trim(), currentUser.username);
    if (!res.success) {
      setEditProfileError(res.error || 'Ошибка при обновлении профиля');
      return;
    }

    onNotification('Данные главного администратора успешно обновлены');
    setIsEditProfileModalOpen(false);
    onRefresh();
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    const trimmed = newUsername.trim();
    if (!trimmed) {
      setFormError('Укажите никнейм пользователя');
      return;
    }

    const trimmedPassword = newPassword.trim();
    if (!trimmedPassword) {
      setFormError('Укажите пароль учетной записи');
      return;
    }

    const detected = await detectRealIp();
    const finalIp = newIp.trim() || detected || '192.168.1.100';

    const result = db.createUser({
      username: trimmed,
      fullName: newFullName.trim(),
      role: 'user',
      password: trimmedPassword,
      knownIps: [finalIp],
    });

    if (!result.success) {
      setFormError(result.error || 'Ошибка при создании пользователя');
      return;
    }

    onNotification(`Пользователь «${result.user?.username}» успешно создан`);
    setIsCreateModalOpen(false);
    setNewUsername('');
    setNewFullName('');
    setNewPassword('');
    setNewIp('');
    onRefresh();
  };

  const handleStartDelete = (user: User) => {
    if (user.isChiefAdmin || user.id === 1) {
      onNotification('Запрещено удалять главного администратора системы', 'critical');
      return;
    }

    if (user.role === 'admin' && !isChiefAdmin) {
      onNotification('Только главный администратор может удалять администраторов', 'critical');
      return;
    }

    setUserToDelete(user);
  };

  const handleConfirmDelete = () => {
    if (!userToDelete) return;

    const res = db.deleteUser(userToDelete.id, currentUser.username);
    if (res.success) {
      onNotification(`Пользователь «${userToDelete.username}» успешно удален`);
      onRefresh();
    } else {
      onNotification(res.error || 'Ошибка при удалении пользователя', 'critical');
    }

    setUserToDelete(null);
  };

  const handleToggleRole = (user: User) => {
    if (!isChiefAdmin) {
      onNotification('Только главный администратор имеет право изменять роли пользователей', 'critical');
      return;
    }

    if (user.isChiefAdmin || user.id === 1) {
      onNotification('Нельзя изменить роль главного администратора', 'critical');
      return;
    }

    const nextRole: UserRole = user.role === 'admin' ? 'user' : 'admin';
    const res = db.updateUserRole(user.id, nextRole, currentUser.username);
    if (res.success) {
      onNotification(
        `Роль пользователя «${user.username}» изменена на «${nextRole === 'admin' ? 'Администратор' : 'Пользователь'}»`
      );
      onRefresh();
    } else {
      onNotification(res.error || 'Ошибка смены роли', 'critical');
    }
  };

  return (
    <div className="space-y-4 font-sans text-xs">
      {/* Header */}
      <div className="bg-white border border-slate-300 rounded p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold text-slate-900">Пользователи</h2>
            {isChiefAdmin && (
              <span className="px-2 py-0.5 rounded bg-amber-100 border border-amber-300 text-amber-900 text-[11px] font-semibold">
                Права главного администратора
              </span>
            )}
          </div>
          <p className="text-slate-500 mt-0.5">
            Учетные записи системы и управление правами доступа
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          {isChiefAdmin && (
            <button
              onClick={handleOpenEditProfile}
              className="px-3.5 py-1.5 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 font-medium transition shadow-xs"
            >
              Изменить имя и никнейм
            </button>
          )}

          <button
            onClick={() => {
              setFormError(null);
              setIsCreateModalOpen(true);
            }}
            className="px-3.5 py-1.5 rounded bg-blue-600 hover:bg-blue-700 text-white font-medium transition shadow-xs"
          >
            Добавить пользователя
          </button>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-white border border-slate-300 rounded shadow-xs overflow-hidden">
        <div className="px-4 py-2.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between text-slate-700">
          <span className="font-semibold">
            Всего пользователей: <span className="font-bold text-slate-900">{users.length}</span>
          </span>
          <span className="text-slate-500 text-[11px]">
            Текущий сеанс: <strong className="text-slate-800">{currentUser.username}</strong>{' '}
            ({isChiefAdmin ? 'Главный администратор' : currentUser.role === 'admin' ? 'Администратор' : 'Пользователь'})
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-100 border-b border-slate-200 text-slate-600 font-semibold text-[11px] uppercase">
                <th className="p-3">Логин</th>
                <th className="p-3">ФИО / Описание</th>
                <th className="p-3">Роль</th>
                <th className="p-3">Доверенный IP</th>
                <th className="p-3">Дата создания</th>
                <th className="p-3 text-right">Действия</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {users.map((u) => {
                const isTargetChief = Boolean(u.isChiefAdmin || u.id === 1);
                const isTargetAdmin = u.role === 'admin';
                const isCurrent = currentUser.id === u.id;

                return (
                  <tr key={u.id} className={`hover:bg-slate-50 transition ${isCurrent ? 'bg-blue-50/30' : ''}`}>
                    <td className="p-3 font-semibold text-slate-900">
                      <div className="flex items-center gap-1.5">
                        <span>{u.username}</span>
                        {isCurrent && (
                          <span className="px-1 py-0.2 rounded bg-slate-200 text-slate-700 text-[10px] font-normal">
                            вы
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="p-3 text-slate-600">
                      {u.fullName || '—'}
                    </td>

                    <td className="p-3">
                      {isTargetChief ? (
                        <span className="inline-block px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-100 text-amber-900 border border-amber-300">
                          Главный администратор
                        </span>
                      ) : isTargetAdmin ? (
                        <span className="inline-block px-2 py-0.5 rounded text-[11px] font-semibold bg-blue-100 text-blue-800 border border-blue-200">
                          Администратор
                        </span>
                      ) : (
                        <span className="inline-block px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-100 text-slate-700 border border-slate-200">
                          Пользователь
                        </span>
                      )}
                    </td>

                    <td className="p-3 font-mono text-slate-600">
                      {u.knownIps && u.knownIps.length > 0 ? u.knownIps.join(', ') : '—'}
                    </td>

                    <td className="p-3 text-slate-500">
                      {new Date(u.createdAt).toLocaleDateString('ru-RU')}
                    </td>

                    <td className="p-3 text-right">
                      {isTargetChief ? (
                        <div className="flex items-center justify-end gap-2">
                          {isChiefAdmin && (
                            <button
                              type="button"
                              onClick={handleOpenEditProfile}
                              className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 font-medium text-[11px] transition"
                            >
                              Изменить имя/логин
                            </button>
                          )}
                        </div>
                      ) : (
                        <div className="flex items-center justify-end gap-2">
                          {/* Role Change: ONLY Chief Admin can promote or demote */}
                          {isChiefAdmin && (
                            <button
                              type="button"
                              onClick={() => handleToggleRole(u)}
                              className="px-2 py-1 rounded border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 text-[11px] transition font-medium"
                            >
                              {u.role === 'admin' ? 'Сделать User' : 'Сделать Admin'}
                            </button>
                          )}

                          {/* Delete Button:
                              - If target is admin: ONLY Chief Admin can delete.
                              - If target is user: BOTH Chief Admin and ordinary admins can delete.
                          */}
                          {isTargetAdmin && !isChiefAdmin ? (
                            <span className="text-slate-400 text-xs italic">
                              Не удаляется
                            </span>
                          ) : (
                            <button
                              type="button"
                              onClick={() => handleStartDelete(u)}
                              className="px-2.5 py-1 rounded bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 font-medium text-[11px] transition"
                              title="Удалить пользователя"
                            >
                              Удалить
                            </button>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Chief Admin Profile Edit Modal */}
      {isEditProfileModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40">
          <div className="bg-white border border-slate-300 rounded shadow-lg w-full max-w-md overflow-hidden">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
              <h3 className="font-bold text-slate-800 text-sm">Изменить данные главного администратора</h3>
              <button
                type="button"
                onClick={() => setIsEditProfileModalOpen(false)}
                className="text-slate-400 hover:text-slate-700 font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSaveProfile} className="p-4 space-y-3">
              {editProfileError && (
                <div className="p-2.5 bg-red-50 border border-red-200 text-red-700 rounded text-xs">
                  {editProfileError}
                </div>
              )}

              <div>
                <label className="block font-medium text-slate-700 mb-1">
                  Логин (никнейм):
                </label>
                <input
                  type="text"
                  required
                  value={editUsername}
                  onChange={(e) => setEditUsername(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded border border-slate-300 focus:outline-none focus:border-blue-500 font-mono text-xs"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-700 mb-1">
                  Имя / ФИО:
                </label>
                <input
                  type="text"
                  value={editFullName}
                  onChange={(e) => setEditFullName(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded border border-slate-300 focus:outline-none focus:border-blue-500 text-xs"
                />
              </div>

              <div className="pt-2 border-t border-slate-200 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsEditProfileModalOpen(false)}
                  className="px-3 py-1.5 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 font-medium transition"
                >
                  Отмена
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 rounded bg-blue-600 hover:bg-blue-700 text-white font-medium transition"
                >
                  Сохранить
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {userToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40">
          <div className="bg-white border border-slate-300 rounded shadow-lg w-full max-w-sm overflow-hidden p-5 space-y-4">
            <div className="text-red-600 font-bold text-sm">
              Подтверждение удаления
            </div>

            <div className="text-xs text-slate-700 leading-relaxed">
              Вы действительно хотите удалить учетную запись{' '}
              <strong className="text-slate-900 font-semibold">«{userToDelete.username}»</strong>{' '}
              ({userToDelete.role === 'admin' ? 'Администратор' : 'Пользователь'})?
              {userToDelete.role === 'admin' && (
                <p className="mt-2 text-amber-800 bg-amber-50 p-2 rounded border border-amber-200 text-[11px]">
                  Внимание: учетная запись администратора будет полностью удалена из базы данных.
                </p>
              )}
            </div>

            <div className="pt-2 border-t border-slate-200 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setUserToDelete(null)}
                className="px-3 py-1.5 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs transition"
              >
                Отмена
              </button>
              <button
                type="button"
                onClick={handleConfirmDelete}
                className="px-3.5 py-1.5 rounded bg-red-600 hover:bg-red-700 text-white font-semibold text-xs transition"
              >
                Да, удалить
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create User Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40">
          <div className="bg-white border border-slate-300 rounded shadow-lg w-full max-w-md overflow-hidden">
            <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
              <h3 className="font-bold text-slate-800 text-sm">Новый пользователь</h3>
              <button
                type="button"
                onClick={() => setIsCreateModalOpen(false)}
                className="text-slate-400 hover:text-slate-700 font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateUser} className="p-4 space-y-3">
              {formError && (
                <div className="p-2.5 bg-red-50 border border-red-200 text-red-700 rounded text-xs">
                  {formError}
                </div>
              )}

              <div>
                <label className="block font-medium text-slate-700 mb-1">
                  Логин:
                </label>
                <input
                  type="text"
                  required
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded border border-slate-300 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-700 mb-1">
                  Пароль:
                </label>
                <input
                  type="text"
                  required
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded border border-slate-300 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-700 mb-1">
                  ФИО / Отдел:
                </label>
                <input
                  type="text"
                  value={newFullName}
                  onChange={(e) => setNewFullName(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded border border-slate-300 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block font-medium text-slate-700">
                    Доверенный IP-адрес:
                  </label>
                  <button
                    type="button"
                    onClick={async () => {
                      const ip = await detectRealIp(true);
                      if (ip) setNewIp(ip);
                    }}
                    className="text-[11px] text-blue-600 hover:text-blue-800 font-medium"
                  >
                    🔄 Определить мой IP
                  </button>
                </div>
                <input
                  type="text"
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  placeholder="Определяется автоматически..."
                  className="w-full px-2.5 py-1.5 rounded border border-slate-300 font-mono focus:outline-none focus:border-blue-500"
                />
                {newIp.trim() && (
                  <div className="mt-1 text-[11px] text-slate-700 bg-blue-50/70 border border-blue-200/80 px-2 py-1 rounded flex items-center justify-between">
                    <span className="truncate">
                      Локация: <strong className="text-slate-900">{newIpGeo?.flag || '🌐'} {newIpGeo?.city ? `${newIpGeo.city}, ` : ''}{newIpGeo?.country || 'Определение...'}</strong>
                      {newIpGeo?.isp ? <span className="text-slate-500 text-[10px] ml-1">({newIpGeo.isp})</span> : null}
                    </span>
                    {newIpGeo?.country && newIpGeo.country !== 'Определение...' && (
                      <span className="text-[10px] text-emerald-700 font-semibold shrink-0 ml-1">✓ определена</span>
                    )}
                  </div>
                )}
              </div>

              <div className="pt-2 border-t border-slate-200 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-3 py-1.5 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 font-medium transition"
                >
                  Отмена
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 rounded bg-blue-600 hover:bg-blue-700 text-white font-medium transition"
                >
                  Создать
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
