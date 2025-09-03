import { useState } from 'react';

interface User {
  id: number;
  username: string;
  // Adicione outros campos do seu modelo User conforme necessário
  email?: string;
  name?: string;
}

interface LoginData {
  username: string;
  password?: string; // Se você tiver autenticação por senha
}

interface UseLoginReturn {
  user: User | null;
  loading: boolean;
  error: string | null;
  login: (loginData: LoginData) => Promise<boolean>;
  logout: () => void;
}

const useLogin = (): UseLoginReturn => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const API_BASE_URL = 'https://6729874dcd84.ngrok-free.app/api/users'; // Ajuste conforme sua configuração

  const login = async (loginData: LoginData): Promise<boolean> => {
    setLoading(true);
    setError(null);

    try {
      // Primeiro verifica se o usuário existe
      const existsResponse = await fetch(`${API_BASE_URL}/exists/${loginData.username}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'ngrok-skip-browser-warning': 'true',
        },
      });

      if (!existsResponse.ok) {
        throw new Error('Erro ao verificar usuário');
      }

      const userExists = await existsResponse.json();

      if (!userExists) {
        setError('Usuário não encontrado');
        return false;
      }

      // Se o usuário existe, busca os dados completos
      const userResponse = await fetch(`${API_BASE_URL}/username/${loginData.username}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'ngrok-skip-browser-warning': 'true',
        },
      });

      if (!userResponse.ok) {
        throw new Error('Erro ao buscar dados do usuário');
      }

      const userData: User = await userResponse.json();
      
      // Salva no localStorage para persistir a sessão
      localStorage.setItem('user', JSON.stringify(userData));
      setUser(userData);
      
      return true;

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Erro desconhecido';
      setError(errorMessage);
      return false;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setUser(null);
    setError(null);
    localStorage.removeItem('user');
  };

  // Verifica se há um usuário salvo no localStorage ao carregar
  useState(() => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      try {
        setUser(JSON.parse(savedUser));
      } catch (err) {
        localStorage.removeItem('user');
      }
    }
  });

  return {
    user,
    loading,
    error,
    login,
    logout,
  };
};

export default useLogin;