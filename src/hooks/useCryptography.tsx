import { useState, useCallback, useEffect, useRef } from 'react';
import type { ICryptoProvider, EncryptedMessage, KeyPair } from '../e2e/interface/ICryptoProvider';
import { CryptoProviderFactory, CryptoAlgorithm } from '../e2e/factory/CryptoProviderFactory';
import { KeyManager } from '../e2e/KeyManager';

interface UseCryptographyProps {
  userId: string;
  algorithm?: CryptoAlgorithm;
  apiBaseUrl?: string;
  initializeImmediately?: boolean;
}

interface UseCryptographyReturn {
  isInitialized: boolean;
  isInitializing: boolean;
  error: string | null;
  encryptMessage: (message: string, recipientUserId: string) => Promise<EncryptedMessage>;
  decryptMessage: (encryptedMessage: EncryptedMessage) => Promise<string>;
  getPublicKey: () => string | null;
  exchangePublicKeys: (recipientUserId: string, recipientPublicKey: string) => void;
  fetchPublicKeyFromServer: (userId: string) => Promise<string | null>;
  uploadPublicKeyToServer: (publicKey: string) => Promise<boolean>;
  regenerateKeys: () => Promise<void>;
  clearKeys: () => void;
  preloadRecipientKey: (recipientUserId: string) => Promise<boolean>;
  getCachedKeys: () => string[];
  debugKeys: () => void;
  initializeCryptography: () => Promise<void>; // NOVO: função manual de inicialização
}

// Armazenamento temporário para chaves públicas de outros usuários
const publicKeysCache = new Map<string, Uint8Array>();

// Função helper para logs detalhados
const logCrypto = (action: string, data?: any) => {
  const timestamp = new Date().toISOString();
  console.log(`🔐 [${timestamp}] ${action}`, data || '');
};

export const useCryptography = ({ 
  userId, 
  algorithm = CryptoAlgorithm.CRYSTAL_KYBER_MLKEM1024,
  apiBaseUrl = 'https://6729874dcd84.ngrok-free.app/api',
  initializeImmediately = false // MODIFICADO: padrão false
}: UseCryptographyProps): UseCryptographyReturn => {
  const [isInitialized, setIsInitialized] = useState<boolean>(false);
  const [isInitializing, setIsInitializing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  
  // Use useRef to prevent recreating these instances
  const keyManagerRef = useRef<KeyManager | null>(null);
  const cryptoProviderRef = useRef<ICryptoProvider | null>(null);
  const [userKeyPair, setUserKeyPair] = useState<KeyPair | null>(null);
  const initializationRef = useRef<boolean>(false);

  // MODIFICADO: Recriar providers quando algoritmo mudar
  useEffect(() => {
    logCrypto(`🔄 Recreando providers para algoritmo: ${algorithm}`);
    keyManagerRef.current = new KeyManager(algorithm);
    cryptoProviderRef.current = CryptoProviderFactory.createProvider(algorithm);
    
    // Limpar estado anterior se mudar algoritmo
    if (isInitialized) {
      logCrypto(`🧹 Limpando estado anterior devido à mudança de algoritmo`);
      setIsInitialized(false);
      setUserKeyPair(null);
      publicKeysCache.clear();
      initializationRef.current = false;
    }
  }, [algorithm]);

  const keyManager = keyManagerRef.current;
  const cryptoProvider = cryptoProviderRef.current;

  // Debug: Função para mostrar chaves em cache
  const debugKeys = useCallback(() => {
    logCrypto('=== DEBUG KEYS ===');
    
    // Chave do usuário atual
    if (userKeyPair && cryptoProvider) {
      try {
        const myPublicKey = cryptoProvider.exportPublicKey(userKeyPair.publicKey);
        logCrypto(`📍 Minha chave pública (${userId}):`, myPublicKey.substring(0, 50) + '...');
      } catch (err) {
        logCrypto('❌ Erro ao exportar minha chave pública:', err);
      }
    } else {
      logCrypto('❌ Nenhuma chave própria disponível');
    }

    // Chaves em cache
    logCrypto(`📦 Chaves em cache (${publicKeysCache.size}):`);
    publicKeysCache.forEach((key, recipientId) => {
      logCrypto(`  - ${recipientId}:`, key.length + ' bytes');
    });

    logCrypto('==================');
  }, [userKeyPair, cryptoProvider, userId]);

  // Função para verificar se o servidor está disponível
  const checkServerAvailability = useCallback(async (): Promise<boolean> => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      await fetch(`${apiBaseUrl}/health`, {
        method: 'GET',
        headers: {
          'ngrok-skip-browser-warning': 'true',
        },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      return true;
    } catch {
      // Try a different endpoint if health check is not available
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3000);

        await fetch(`${apiBaseUrl}/users/public-key/test`, {
          method: 'GET',
          headers: {
            'ngrok-skip-browser-warning': 'true',
          },
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        // Even 404 means server is responding
        return true;
      } catch {
        return false;
      }
    }
  }, [apiBaseUrl]);

  // Função para buscar chave pública do servidor
  const fetchPublicKeyFromServer = useCallback(async (targetUserId: string): Promise<string | null> => {
    logCrypto(`🌐 Buscando chave pública do servidor para: ${targetUserId}`);
    
    try {
      const serverAvailable = await checkServerAvailability();
      if (!serverAvailable) {
        logCrypto(`⚠️ Servidor não disponível para buscar chave de ${targetUserId}`);
        return null;
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(`${apiBaseUrl}/users/public-key/${encodeURIComponent(targetUserId)}`, {
        method: 'GET',
        headers: {
          'ngrok-skip-browser-warning': 'true',
        },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        if (response.status === 404) {
          logCrypto(`❌ Chave pública não encontrada no servidor para: ${targetUserId}`);
          return null;
        }
        throw new Error(`Erro HTTP: ${response.status}`);
      }

      const data = await response.json();
      const publicKey = data.publicKey || null;
      
      if (publicKey) {
        logCrypto(`✅ Chave pública encontrada no servidor para ${targetUserId}:`, publicKey.substring(0, 50) + '...');
      }
      
      return publicKey;
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        logCrypto(`⏰ Timeout ao buscar chave pública para ${targetUserId}`);
      } else {
        logCrypto(`❌ Erro ao buscar chave pública do servidor para ${targetUserId}:`, err);
      }
      return null;
    }
  }, [apiBaseUrl, checkServerAvailability]);

  // Função para enviar chave pública para o servidor
  const uploadPublicKeyToServer = useCallback(async (publicKey: string): Promise<boolean> => {
    if (!cryptoProvider) {
      logCrypto(`❌ CryptoProvider não disponível para upload`);
      return false;
    }

    logCrypto(`🌐 Enviando chave pública para o servidor (${userId}):`, publicKey.substring(0, 50) + '...');
    
    try {
      const serverAvailable = await checkServerAvailability();
      if (!serverAvailable) {
        logCrypto(`⚠️ Servidor não disponível para upload de chave de ${userId}`);
        return false;
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      // Payload correto com algorithm
      const payload = {
        userId: userId,
        publicKey: publicKey,
        algorithm: cryptoProvider.getAlgorithmName()
      };

      logCrypto(`📤 Payload de upload:`, {
        userId: payload.userId,
        algorithm: payload.algorithm,
        publicKeyLength: payload.publicKey.length
      });

      const response = await fetch(`${apiBaseUrl}/users/public-key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'ngrok-skip-browser-warning': 'true',
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        logCrypto(`❌ Erro HTTP ${response.status} ao enviar chave:`, errorText);
        return false;
      }

      const responseData = await response.json();
      logCrypto(`✅ Chave pública enviada com sucesso para o servidor (${userId}):`, responseData);
      return true;
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        logCrypto(`⏰ Timeout ao enviar chave pública para ${userId}`);
      } else {
        logCrypto(`❌ Erro ao enviar chave pública para o servidor (${userId}):`, err);
      }
      return false;
    }
  }, [userId, apiBaseUrl, checkServerAvailability, cryptoProvider]);

  // MODIFICADO: Inicializar criptografia como função manual
  const initializeCryptography = useCallback(async () => {
    if (!userId || isInitializing || initializationRef.current || !keyManager || !cryptoProvider) {
      logCrypto(`⏸️ Inicialização cancelada:`, {
        userId: !!userId,
        isInitializing,
        initializationRef: initializationRef.current,
        keyManager: !!keyManager,
        cryptoProvider: !!cryptoProvider
      });
      return;
    }

    logCrypto(`🚀 Inicializando criptografia MANUALMENTE para usuário: ${userId} com algoritmo: ${algorithm}`);
    initializationRef.current = true;
    setIsInitializing(true);
    setError(null);

    try {
      const keyPair = await keyManager.ensureKeyPair(userId);
      setUserKeyPair(keyPair);

      // Log da chave gerada/carregada
      const publicKeyString = cryptoProvider.exportPublicKey(keyPair.publicKey);
      logCrypto(`🔑 Par de chaves carregado para ${userId}:`, publicKeyString.substring(0, 50) + '...');

      // Tentar enviar chave pública para o servidor após inicialização
      const uploadSuccess = await uploadPublicKeyToServer(publicKeyString);
      if (uploadSuccess) {
        logCrypto(`✅ Chave pública sincronizada com sucesso no servidor`);
      } else {
        logCrypto(`⚠️ Falha ao sincronizar chave pública com o servidor, mas continuando offline`);
      }

      setIsInitialized(true);
      logCrypto(`✅ Criptografia inicializada com sucesso para ${userId} com ${algorithm}`);
      
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Erro na inicialização da criptografia';
      setError(errorMessage);
      logCrypto(`❌ Erro na inicialização da criptografia para ${userId}:`, err);
    } finally {
      setIsInitializing(false);
      initializationRef.current = false;
    }
  }, [userId, keyManager, cryptoProvider, uploadPublicKeyToServer, isInitializing, algorithm]);

  // Obter chave pública de um usuário (cache + servidor)
  const getRecipientPublicKey = useCallback(async (recipientUserId: string): Promise<Uint8Array> => {
    if (!cryptoProvider) {
      throw new Error('CryptoProvider não inicializado');
    }

    logCrypto(`🔍 Obtendo chave pública para destinatário: ${recipientUserId}`);
    
    // Verificar cache local primeiro
    let recipientPublicKey = publicKeysCache.get(recipientUserId);
    
    if (recipientPublicKey) {
      logCrypto(`📦 Chave encontrada no cache para ${recipientUserId}:`, recipientPublicKey.length + ' bytes');
      return recipientPublicKey;
    }

    logCrypto(`🌐 Chave não encontrada no cache, buscando do servidor para: ${recipientUserId}`);
    
    // Buscar do servidor se não estiver no cache
    const publicKeyString = await fetchPublicKeyFromServer(recipientUserId);
    if (!publicKeyString) {
      throw new Error(`Chave pública não encontrada para o usuário: ${recipientUserId}`);
    }
    
    // Importar e armazenar no cache
    recipientPublicKey = cryptoProvider.importPublicKey(publicKeyString);
    publicKeysCache.set(recipientUserId, recipientPublicKey);
    
    logCrypto(`✅ Chave importada e armazenada no cache para ${recipientUserId}:`, recipientPublicKey.length + ' bytes');
    return recipientPublicKey;
  }, [fetchPublicKeyFromServer, cryptoProvider]);

  // Pré-carregar chave do destinatário (otimização)
  const preloadRecipientKey = useCallback(async (recipientUserId: string): Promise<boolean> => {
    logCrypto(`⚡ Pré-carregando chave para destinatário: ${recipientUserId}`);
    
    try {
      // Se já está no cache, não precisa fazer nada
      if (publicKeysCache.has(recipientUserId)) {
        logCrypto(`✅ Chave já está em cache para ${recipientUserId}`);
        return true;
      }

      await getRecipientPublicKey(recipientUserId);
      logCrypto(`✅ Chave pré-carregada com sucesso para ${recipientUserId}`);
      return true;
    } catch (err) {
      logCrypto(`❌ Falha ao pré-carregar chave para ${recipientUserId}:`, err);
      return false;
    }
  }, [getRecipientPublicKey]);

  // Encriptar mensagem (com busca automática de chave pública)
  const encryptMessage = useCallback(async (message: string, recipientUserId: string): Promise<EncryptedMessage> => {
    logCrypto(`🔒 Iniciando criptografia de mensagem para: ${recipientUserId}`);
    
    if (!isInitialized || !userKeyPair || !cryptoProvider) {
      throw new Error('Criptografia não inicializada');
    }

    try {
      const recipientPublicKey = await getRecipientPublicKey(recipientUserId);
      const encryptedMessage = await cryptoProvider.encrypt(message, recipientPublicKey);
      
      logCrypto(`✅ Mensagem criptografada com sucesso para ${recipientUserId}`, {
        originalLength: message.length,
        encryptedSize: JSON.stringify(encryptedMessage).length
      });
      
      return encryptedMessage;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Erro na criptografia';
      logCrypto(`❌ Falha ao criptografar mensagem para ${recipientUserId}:`, err);
      throw new Error(`Falha ao criptografar mensagem: ${errorMessage}`);
    }
  }, [isInitialized, userKeyPair, cryptoProvider, getRecipientPublicKey]);

  // Descriptografar mensagem
  const decryptMessage = useCallback(async (encryptedMessage: EncryptedMessage): Promise<string> => {
    logCrypto(`🔓 Iniciando descriptografia de mensagem`);
    
    if (!isInitialized || !userKeyPair || !cryptoProvider) {
      throw new Error('Criptografia não inicializada');
    }

    try {
      const decryptedMessage = await cryptoProvider.decrypt(encryptedMessage, userKeyPair.privateKey);
      
      logCrypto(`✅ Mensagem descriptografada com sucesso`, {
        encryptedSize: JSON.stringify(encryptedMessage).length,
        decryptedLength: decryptedMessage.length
      });
      
      return decryptedMessage;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Erro na descriptografia';
      logCrypto(`❌ Falha ao descriptografar mensagem:`, err);
      throw new Error(`Falha ao descriptografar mensagem: ${errorMessage}`);
    }
  }, [isInitialized, userKeyPair, cryptoProvider]);

  // Obter chave pública do usuário atual
  const getPublicKey = useCallback((): string | null => {
    if (!userKeyPair || !cryptoProvider) {
      logCrypto(`❌ Tentativa de obter chave pública, mas não há par de chaves ou crypto provider`);
      return null;
    }
    
    try {
      const publicKey = cryptoProvider.exportPublicKey(userKeyPair.publicKey);
      logCrypto(`📋 Chave pública obtida:`, publicKey.substring(0, 50) + '...');
      return publicKey;
    } catch (err) {
      logCrypto(`❌ Erro ao exportar chave pública:`, err);
      return null;
    }
  }, [userKeyPair, cryptoProvider]);

  // Trocar chaves públicas (método manual para casos específicos)
  const exchangePublicKeys = useCallback((recipientUserId: string, recipientPublicKey: string) => {
    if (!cryptoProvider) {
      throw new Error('CryptoProvider não inicializado');
    }

    logCrypto(`🔄 Trocando chave pública manualmente para: ${recipientUserId}`);
    
    try {
      const publicKeyBytes = cryptoProvider.importPublicKey(recipientPublicKey);
      publicKeysCache.set(recipientUserId, publicKeyBytes);
      
      logCrypto(`✅ Chave pública armazenada manualmente para ${recipientUserId}:`, publicKeyBytes.length + ' bytes');
    } catch (err) {
      logCrypto(`❌ Erro ao importar chave pública para ${recipientUserId}:`, err);
      throw new Error('Chave pública inválida');
    }
  }, [cryptoProvider]);

  // Obter lista de chaves em cache
  const getCachedKeys = useCallback((): string[] => {
    return Array.from(publicKeysCache.keys());
  }, []);

  // Regenerar chaves
  const regenerateKeys = useCallback(async () => {
    if (!userId || isInitializing || !keyManager || !cryptoProvider) return;

    logCrypto(`🔄 Regenerando chaves para usuário: ${userId}`);
    setIsInitializing(true);
    setError(null);

    try {
      keyManager.clearKeys(userId);
      const newKeyPair = await keyManager.generateAndStoreKeyPair(userId);
      setUserKeyPair(newKeyPair);

      // Log da nova chave
      const publicKeyString = cryptoProvider.exportPublicKey(newKeyPair.publicKey);
      logCrypto(`🔑 Novas chaves geradas para ${userId}:`, publicKeyString.substring(0, 50) + '...');

      // Enviar nova chave pública para o servidor
      const uploadSuccess = await uploadPublicKeyToServer(publicKeyString);
      if (uploadSuccess) {
        logCrypto(`✅ Nova chave pública sincronizada com sucesso no servidor`);
      } else {
        logCrypto(`⚠️ Falha ao sincronizar nova chave pública com o servidor`);
      }

      logCrypto(`✅ Chaves regeneradas com sucesso para ${userId}`);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Erro ao regenerar chaves';
      setError(errorMessage);
      logCrypto(`❌ Erro ao regenerar chaves para ${userId}:`, err);
      throw new Error(errorMessage);
    } finally {
      setIsInitializing(false);
    }
  }, [userId, keyManager, cryptoProvider, uploadPublicKeyToServer, isInitializing]);

  // Limpar chaves
  const clearKeys = useCallback(() => {
    if (!userId || !keyManager) return;

    logCrypto(`🗑️ Limpando chaves para usuário: ${userId}`);
    
    keyManager.clearKeys(userId);
    setUserKeyPair(null);
    setIsInitialized(false);
    publicKeysCache.clear();
    initializationRef.current = false;
    
    logCrypto(`✅ Chaves limpas para ${userId}`);
  }, [userId, keyManager]);

  // REMOVIDO: useEffect automático - agora só inicializa manualmente
  useEffect(() => {
    if (userId && initializeImmediately && !isInitialized && !isInitializing) {
      logCrypto(`🎯 useEffect automático: Inicializando para ${userId}`);
      initializeCryptography();
    }
  }, [userId, initializeImmediately, isInitialized, isInitializing, initializeCryptography]);

  // Cleanup effect separado
  useEffect(() => {
    return () => {
      if (userId) {
        logCrypto(`🧹 Cleanup: Limpando estado para ${userId}`);
        initializationRef.current = false;
      }
    };
  }, [userId]);

  return {
    isInitialized,
    isInitializing,
    error,
    encryptMessage,
    decryptMessage,
    getPublicKey,
    exchangePublicKeys,
    fetchPublicKeyFromServer,
    uploadPublicKeyToServer,
    regenerateKeys,
    clearKeys,
    preloadRecipientKey,
    getCachedKeys,
    debugKeys,
    initializeCryptography, // NOVO: função manual
  };
};