import { useState, useEffect, useCallback, useRef } from 'react';
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

interface UseRealTimeMessagesProps {
  currentUser: string;
  otherUser: string;
  apiBaseUrl?: string;
  pollingInterval?: number;
  enabled?: boolean;
  onDecryptMessage?: (encryptedMessage: EncryptedMessage) => Promise<string>;
  cryptoInitialized?: boolean;
}

export const useRealTimeMessages = ({
  currentUser,
  otherUser,
  apiBaseUrl = 'https://6729874dcd84.ngrok-free.app/api',
  pollingInterval = 5000,
  enabled = true,
  onDecryptMessage,
  cryptoInitialized = false
}: UseRealTimeMessagesProps) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [lastMessageId, setLastMessageId] = useState<number | null>(null);
  const [decryptionErrors, setDecryptionErrors] = useState<Map<number, string>>(new Map());
  
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const isFirstLoad = useRef<boolean>(true);
  
  // CACHE: Armazenar mensagens já processadas por ID
  const processedMessages = useRef<Map<number, Message>>(new Map());
  // CACHE LOCAL: Armazenar conteúdo original de mensagens próprias
  const ownMessagesCache = useRef<Map<number, string>>(new Map());

  // Função para validar dados criptografados
  const validateEncryptedData = (encryptedData: EncryptedMessage): boolean => {
    return !!(
      encryptedData &&
      encryptedData.encryptedContent &&
      encryptedData.encryptedSymmetricKey &&
      encryptedData.nonce &&
      encryptedData.encryptedContent.length > 0 &&
      encryptedData.encryptedSymmetricKey.length > 0 &&
      encryptedData.nonce.length > 0
    );
  };

  // Função para ordenar mensagens por timestamp e ID
  const sortMessages = (msgs: Message[]): Message[] => {
    return [...msgs].sort((a, b) => {
      // Primeiro por timestamp
      const timeA = new Date(a.timestamp || '').getTime();
      const timeB = new Date(b.timestamp || '').getTime();
      
      if (timeA !== timeB) {
        return timeA - timeB; // Ordem crescente (mais antigas primeiro)
      }
      
      // Se timestamps iguais, ordenar por ID
      const idA = a.id || 0;
      const idB = b.id || 0;
      return idA - idB;
    });
  };

  // Função para processar uma mensagem individual
  const processMessage = useCallback(async (rawMessage: Message): Promise<Message> => {
    // Se tem ID e já foi processada, usar cache
    if (rawMessage.id && processedMessages.current.has(rawMessage.id)) {
      const cached = processedMessages.current.get(rawMessage.id)!;
      console.log(`📦 Usando mensagem cached para ID: ${rawMessage.id}`);
      return cached;
    }

    let processedMessage = rawMessage;

    // Para mensagens próprias, verificar se temos o conteúdo original em cache
    if (rawMessage.sender === currentUser) {
      console.log(`📤 Processando mensagem própria (${rawMessage.id})`);
      
      // Se temos o conteúdo original em cache, usar ele
      if (rawMessage.id && ownMessagesCache.current.has(rawMessage.id)) {
        const originalContent = ownMessagesCache.current.get(rawMessage.id)!;
        console.log(`✅ Usando conteúdo original do cache para mensagem ${rawMessage.id}: "${originalContent}"`);
        processedMessage = {
          ...rawMessage,
          content: originalContent
        };
      } else if (rawMessage.content === '[ENCRYPTED]') {
        // Se não temos o cache e veio como [ENCRYPTED], tentar descriptografar nossa própria mensagem
        console.warn(`⚠️ Mensagem própria veio como [ENCRYPTED], tentando descriptografar...`);
        
        if (rawMessage.encrypted && rawMessage.encryptedData && onDecryptMessage && cryptoInitialized) {
          try {
            const decryptedContent = await onDecryptMessage(rawMessage.encryptedData);
            processedMessage = {
              ...rawMessage,
              content: decryptedContent
            };
            console.log(`✅ Mensagem própria descriptografada: "${decryptedContent}"`);
          } catch (err) {
            console.error(`❌ Erro ao descriptografar mensagem própria ${rawMessage.id}:`, err);
            processedMessage = {
              ...rawMessage,
              content: '[Erro ao recuperar conteúdo próprio]'
            };
          }
        } else {
          processedMessage = {
            ...rawMessage,
            content: '[Conteúdo original não disponível]'
          };
        }
      }
      // Se content não é [ENCRYPTED], manter como está
    }
    // Para mensagens de outros usuários, descriptografar se necessário
    else if (rawMessage.encrypted && rawMessage.encryptedData) {
      if (!onDecryptMessage || !cryptoInitialized) {
        // Criptografia não está pronta, retornar mensagem temporária SEM cachear
        console.log(`⏳ Criptografia não inicializada, mensagem temporária para ID: ${rawMessage.id}`);
        return {
          ...rawMessage,
          content: '[Aguardando inicialização da criptografia...]'
        };
      }

      try {
        console.log(`🔓 Descriptografando mensagem ID: ${rawMessage.id} de ${rawMessage.sender}`);

        if (!validateEncryptedData(rawMessage.encryptedData)) {
          throw new Error('Dados criptografados inválidos ou incompletos');
        }

        const decryptedContent = await onDecryptMessage(rawMessage.encryptedData);
        processedMessage = {
          ...rawMessage,
          content: decryptedContent
        };

        console.log(`✅ Mensagem ${rawMessage.id} descriptografada: "${decryptedContent}"`);
        
        // Limpar erro se existia
        if (rawMessage.id && decryptionErrors.has(rawMessage.id)) {
          setDecryptionErrors(prev => {
            const newMap = new Map(prev);
            newMap.delete(rawMessage.id!);
            return newMap;
          });
        }
      } catch (err) {
        console.error(`❌ Erro ao descriptografar mensagem ${rawMessage.id}:`, err);
        processedMessage = {
          ...rawMessage,
          content: '[Erro na descriptografia]'
        };
        
        // Armazenar erro
        if (rawMessage.id) {
          setDecryptionErrors(prev => new Map(prev.set(rawMessage.id!, err instanceof Error ? err.message : 'Erro desconhecido')));
        }
      }
    }

    // CACHEAR mensagem processada apenas se não é temporária
    if (rawMessage.id && !processedMessage.content.includes('[Aguardando inicialização')) {
      processedMessages.current.set(rawMessage.id, processedMessage);
    }

    return processedMessage;
  }, [currentUser, onDecryptMessage, cryptoInitialized, decryptionErrors]);

  // Função para buscar mensagens do servidor - CORRIGIDA para usar /recent
  const fetchMessages = useCallback(async (showLoading: boolean = false) => {
    if (!currentUser || !otherUser) return;

    if (showLoading) {
      setIsLoading(true);
    }
    
    setError(null);

    try {
      // CORREÇÃO: Usar a rota /recent que retorna mensagens com encryptedData
      const response = await fetch(
        `${apiBaseUrl}/messages/recent/${encodeURIComponent(currentUser)}`
      );
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const rawMessages: Message[] = await response.json();
      
      // Filtrar apenas mensagens da conversa atual (com otherUser)
      const conversationMessages = rawMessages.filter(msg => 
        (msg.sender === currentUser && msg.receiver === otherUser) ||
        (msg.sender === otherUser && msg.receiver === currentUser)
      );
      
      // CORREÇÃO: Ordenar mensagens por timestamp (crescente)
      const sortedMessages = sortMessages(conversationMessages);
      
      console.log(`📥 Busca de mensagens concluída: ${sortedMessages.length} mensagens da conversa encontradas (de ${rawMessages.length} totais)`);
      
      // Verificar se há novas mensagens
      if (sortedMessages.length > 0) {
        const latestMessage = sortedMessages[sortedMessages.length - 1];
        const latestMessageId = latestMessage.id || sortedMessages.length;
        
        // Se não há novas mensagens, só atualizar se é primeira carga
        if (!isFirstLoad.current && lastMessageId && latestMessageId <= lastMessageId) {
          console.log(`📌 Nenhuma nova mensagem detectada (último ID: ${latestMessageId})`);
          return;
        }
        
        setLastMessageId(latestMessageId);
      }
      
      // Processar todas as mensagens
      const processedMessagesList: Message[] = [];
      for (const rawMessage of sortedMessages) {
        const processed = await processMessage(rawMessage);
        processedMessagesList.push(processed);
      }
      
      // CORREÇÃO: Garantir que mensagens estão ordenadas antes de atualizar estado
      const finalSortedMessages = sortMessages(processedMessagesList);
      
      // Atualizar estado
      setMessages(finalSortedMessages);
      
      if (!isFirstLoad.current && sortedMessages.length > 0) {
        const newMessage = finalSortedMessages[finalSortedMessages.length - 1];
        console.log('🔔 Nova mensagem processada:', {
          id: newMessage.id,
          sender: newMessage.sender,
          content: newMessage.content.substring(0, 50) + (newMessage.content.length > 50 ? '...' : ''),
          encrypted: newMessage.encrypted,
          timestamp: newMessage.timestamp
        });
      }
      
      isFirstLoad.current = false;
      
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Erro ao buscar mensagens';
      setError(errorMessage);
      console.error('❌ Erro ao buscar mensagens:', err);
    } finally {
      if (showLoading) {
        setIsLoading(false);
      }
    }
  }, [currentUser, otherUser, apiBaseUrl, lastMessageId, processMessage]);

  // Função para reprocessar mensagens pendentes
  const reprocessPendingMessages = useCallback(async () => {
    if (!cryptoInitialized || !onDecryptMessage) return;

    console.log('🔄 Reprocessando mensagens pendentes...');

    // Buscar mensagens temporárias no estado atual
    const pendingMessages = messages.filter(msg => 
      msg.content.includes('[Aguardando inicialização') && 
      msg.encrypted && 
      msg.sender !== currentUser
    );

    if (pendingMessages.length === 0) {
      console.log('📌 Nenhuma mensagem pendente encontrada');
      return;
    }

    // Reprocessar mensagens pendentes
    const updatedMessages = [...messages];
    let hasChanges = false;

    for (let i = 0; i < updatedMessages.length; i++) {
      const msg = updatedMessages[i];
      if (msg.content.includes('[Aguardando inicialização') && 
          msg.encrypted && 
          msg.sender !== currentUser && 
          msg.id) {
        
        // Remover do cache para forçar reprocessamento
        processedMessages.current.delete(msg.id);
        
        try {
          const reprocessed = await processMessage(msg);
          updatedMessages[i] = reprocessed;
          hasChanges = true;
          console.log(`✅ Mensagem ${msg.id} reprocessada: "${reprocessed.content}"`);
        } catch (err) {
          console.error(`❌ Erro ao reprocessar mensagem ${msg.id}:`, err);
        }
      }
    }

    if (hasChanges) {
      // CORREÇÃO: Ordenar novamente após reprocessamento
      const sortedMessages = sortMessages(updatedMessages);
      setMessages(sortedMessages);
    }
  }, [cryptoInitialized, onDecryptMessage, messages, currentUser, processMessage]);

  // Função para adicionar mensagem localmente - CORRIGIDA
  const addMessageLocally = useCallback(async (message: Message) => {
    try {
      console.log('📤 Adicionando mensagem localmente:', {
        id: message.id,
        sender: message.sender,
        content: message.content.substring(0, 50) + (message.content.length > 50 ? '...' : ''),
        encrypted: message.encrypted,
        isOwnMessage: message.sender === currentUser
      });

      // CORREÇÃO: Para mensagens próprias, armazenar o conteúdo original no cache
      if (message.sender === currentUser && message.id) {
        ownMessagesCache.current.set(message.id, message.content);
        console.log(`💾 Conteúdo original armazenado no cache para mensagem ${message.id}: "${message.content}"`);
      }

      const processedMessage = await processMessage(message);
      
      setMessages(prev => {
        // Verificar duplicatas
        const exists = prev.some(m => 
          m.id === processedMessage.id ||
          (m.sender === processedMessage.sender && 
          m.content === processedMessage.content && 
          Math.abs(new Date(m.timestamp || '').getTime() - new Date(processedMessage.timestamp || '').getTime()) < 1000)
        );
        
        if (!exists) {
          const newMessages = [...prev, processedMessage];
          
          // CORREÇÃO: Ordenar mensagens após adicionar
          const sortedMessages = sortMessages(newMessages);
          
          if (processedMessage.id) {
            setLastMessageId(processedMessage.id);
          }
          return sortedMessages;
        }
        
        return prev;
      });
    } catch (err) {
      console.error('❌ Erro ao adicionar mensagem localmente:', err);
    }
  }, [processMessage, currentUser]);

  // Função para forçar atualização
  const refreshMessages = useCallback(() => {
    console.log('🔄 Forçando atualização de mensagens');
    // NÃO limpar o cache de mensagens próprias, apenas o de processamento
    processedMessages.current.clear();
    isFirstLoad.current = true;
    fetchMessages(true);
  }, [fetchMessages]);

  // Função para limpar mensagens
  const clearMessages = useCallback(() => {
    console.log('🗑️ Limpando mensagens');
    setMessages([]);
    setLastMessageId(null);
    setDecryptionErrors(new Map());
    processedMessages.current.clear();
    ownMessagesCache.current.clear();
    isFirstLoad.current = true;
  }, []);

  // Efeito para reprocessar quando criptografia for inicializada
  useEffect(() => {
    if (cryptoInitialized) {
      const timer = setTimeout(() => {
        reprocessPendingMessages();
      }, 1000);

      return () => clearTimeout(timer);
    }
  }, [cryptoInitialized]);

  // Efeito para polling
  useEffect(() => {
    if (!enabled || !currentUser || !otherUser) {
      console.log('⏸️ Polling desabilitado');
      return;
    }

    console.log(`🎯 Iniciando polling a cada ${pollingInterval}ms para usuário: ${currentUser}`);
    console.log(`🔐 Status da criptografia: ${cryptoInitialized ? 'Inicializada' : 'Não inicializada'}`);

    // Carregamento inicial
    fetchMessages(true);

    // Polling
    intervalRef.current = setInterval(() => {
      fetchMessages(false);
    }, pollingInterval);

    return () => {
      if (intervalRef.current) {
        console.log('🛑 Parando polling');
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [enabled, currentUser, otherUser, pollingInterval, fetchMessages]);

  // Cleanup
  useEffect(() => {
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
      processedMessages.current.clear();
      ownMessagesCache.current.clear();
    };
  }, []);

  return {
    messages,
    isLoading,
    error,
    addMessageLocally,
    refreshMessages,
    clearMessages,
    lastMessageId,
    decryptionErrors
  };
};