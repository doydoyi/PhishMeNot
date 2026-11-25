import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { api } from '../api.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setUser(await api('/api/me'));
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const logout = useCallback(async () => {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } finally {
      setUser(null);
    }
  }, []);

  /** Email + password sign-in; returns the signed-in user. */
  const loginWithPassword = useCallback(async (email, password) => {
    const signedIn = await api('/api/auth/login', { method: 'POST', body: { email, password } });
    setUser(signedIn);
    return signedIn;
  }, []);

  /** Called when the API says the session is gone (401). */
  const sessionExpired = useCallback(() => setUser(null), []);

  return (
    <AuthContext.Provider value={{ user, setUser, loading, refresh, logout, sessionExpired, loginWithPassword }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}

export function homePathFor(user) {
  if (!user) return '/login';
  return user.role === 'ADMIN' ? '/admin' : '/dashboard';
}
