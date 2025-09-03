import { useState } from "react";

interface Message {
  id?: number;
  sender: string;
  receiver: string;
  content: string;
  timestamp?: string;
}

export const useConversation = (apiBaseUrl: string = 'https://6729874dcd84.ngrok-free.app/api') => {
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const getConversation = async (user1: string, user2: string): Promise<Message[]> => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiBaseUrl}/messages/conversation?user1=${encodeURIComponent(user1)}&user2=${encodeURIComponent(user2)}`);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const messages: Message[] = await response.json();
      return messages;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Erro ao buscar conversa';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  return {
    getConversation,
    isLoading,
    error,
  };
};