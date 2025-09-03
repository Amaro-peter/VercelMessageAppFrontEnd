import { useState } from 'react';
import type { EncryptedMessage } from '../e2e/interface/ICryptoProvider';

interface Message {
  id?: number;
  sender: string;
  receiver: string;
  content: string;
  timestamp?: string;
  encrypted?: boolean;
  encryptedData?: EncryptedMessage;
}

interface SendMessageResponse {
  success: boolean;
  message?: Message;
  error?: string;
}

interface UseMessageSenderReturn {
  sendMessage: (messageData: Omit<Message, 'id' | 'timestamp'>) => Promise<SendMessageResponse>;
  isLoading: boolean;
  error: string | null;
}

export const useMessageSender = (apiBaseUrl: string = 'https://6729874dcd84.ngrok-free.app/api'): UseMessageSenderReturn => {
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const sendMessage = async (messageData: Omit<Message, 'id' | 'timestamp'>): Promise<SendMessageResponse> => {
    setIsLoading(true);
    setError(null);

    try {
      // Preparar payload para envio
      const payload: any = {
        sender: messageData.sender,
        receiver: messageData.receiver,
      };

      // Log para debug
      console.log('📤 Preparando mensagem para envio:', {
        sender: messageData.sender,
        receiver: messageData.receiver,
        encrypted: messageData.encrypted,
        contentLength: messageData.content.length,
        hasEncryptedData: !!messageData.encryptedData
      });

      // Se a mensagem está criptografada, enviar os dados criptografados
      if (messageData.encrypted && messageData.encryptedData) {
        payload.content = '[ENCRYPTED]'; // Placeholder para o backend
        payload.encrypted = true;
        payload.encryptedData = messageData.encryptedData;

        // Validar dados criptografados antes do envio
        if (!messageData.encryptedData.encryptedContent || 
            !messageData.encryptedData.encryptedSymmetricKey || 
            !messageData.encryptedData.nonce) {
          throw new Error('Dados criptografados incompletos');
        }

        console.log('🔐 Enviando mensagem criptografada:', {
          algorithm: messageData.encryptedData.algorithm,
          encryptedContentLength: messageData.encryptedData.encryptedContent.length,
          encryptedKeyLength: messageData.encryptedData.encryptedSymmetricKey.length,
          nonceLength: messageData.encryptedData.nonce.length
        });
      } else {
        payload.content = messageData.content;
        payload.encrypted = false;
        
        console.log('📝 Enviando mensagem não criptografada');
      }

      const response = await fetch(`${apiBaseUrl}/messages/send-message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('❌ Erro HTTP ao enviar mensagem:', {
          status: response.status,
          statusText: response.statusText,
          errorText
        });
        throw new Error(errorText || `HTTP error! status: ${response.status}`);
      }

      const sentMessage: Message = await response.json();
      
      console.log('✅ Mensagem enviada com sucesso:', {
        id: sentMessage.id,
        encrypted: sentMessage.encrypted,
        timestamp: sentMessage.timestamp
      });

      return {
        success: true,
        message: sentMessage,
      };
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Erro desconhecido ao enviar mensagem';
      console.error('❌ Erro ao enviar mensagem:', err);
      setError(errorMessage);
      
      return {
        success: false,
        error: errorMessage,
      };
    } finally {
      setIsLoading(false);
    }
  };

  return {
    sendMessage,
    isLoading,
    error,
  };
};