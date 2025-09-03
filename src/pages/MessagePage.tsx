import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import useLogin from '../hooks/useLogin';
import { useMessageSender } from '../hooks/useMessageSender';
import { useRealTimeMessages } from '../hooks/useRealTimeMessages';
import { useCryptography } from '../hooks/useCryptography';
import { CryptoAlgorithm, CryptoProviderFactory } from '../e2e/factory/CryptoProviderFactory';

const MessagePage = () => {
  const [messageContent, setMessageContent] = useState('');
  const [cryptoEnabled, _] = useState<boolean>(true);
  const [showCryptoPanel, setShowCryptoPanel] = useState<boolean>(false);
  const [selectedAlgorithm, setSelectedAlgorithm] = useState<CryptoAlgorithm>(CryptoAlgorithm.CRYSTAL_KYBER_MLKEM512);
  const [algorithmLocked, setAlgorithmLocked] = useState<boolean>(false);
  const [algorithmConfirmed, setAlgorithmConfirmed] = useState<boolean>(false);
  const [showAlgorithmModal, setShowAlgorithmModal] = useState<boolean>(false);
  const [hasShownInitialModal, setHasShownInitialModal] = useState<boolean>(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  
  const { user, logout } = useLogin();
  const { sendMessage, isLoading: isSending, error: sendError } = useMessageSender();
  const navigate = useNavigate();

  // Determina o receiver baseado no usuário logado no localStorage
  const getReceiver = () => {
    // Recupera do localStorage ou usa o user do hook
    const savedUser = localStorage.getItem('user');
    let currentUser = '';
    
    if (savedUser) {
      try {
        const userData = JSON.parse(savedUser);
        currentUser = userData.username;
      } catch (err) {
        console.error('Erro ao ler localStorage:', err);
        currentUser = user?.username || '';
      }
    } else {
      currentUser = user?.username || '';
    }

    return currentUser === 'userA@gmail.com' ? 'userB@gmail.com' : 'userA@gmail.com';
  };

  const getOtherUserName = () => {
    const receiver = getReceiver();
    return receiver === 'userA@gmail.com' ? 'User A' : 'User B';
  };

  const getCurrentUser = () => {
    // Primeiro tenta do localStorage
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      try {
        const userData = JSON.parse(savedUser);
        return userData.username;
      } catch (err) {
        console.error('Erro ao ler localStorage:', err);
      }
    }
    
    // Fallback para o hook
    return user?.username || '';
  };

  // Hook de criptografia - MODIFICADO
  const {
    isInitialized: cryptoInitialized,
    isInitializing: cryptoInitializing,
    error: cryptoError,
    encryptMessage,
    decryptMessage,
    getPublicKey,
    clearKeys: clearCryptoKeys,
    preloadRecipientKey,
    getCachedKeys,
    debugKeys,
    initializeCryptography
  } = useCryptography({
    userId: getCurrentUser(),
    algorithm: selectedAlgorithm,
    apiBaseUrl: 'https://6729874dcd84.ngrok-free.app/api',
    initializeImmediately: false
  });

  // Hook para mensagens em tempo real - MODIFICADO
  const {
    messages,
    isLoading: isLoadingMessages,
    error: conversationError,
    addMessageLocally,
    refreshMessages,
    clearMessages,
    decryptionErrors
  } = useRealTimeMessages({
    currentUser: getCurrentUser(),
    otherUser: getReceiver(),
    pollingInterval: 3000,
    enabled: !!(getCurrentUser() && getReceiver() && algorithmConfirmed),
    onDecryptMessage: decryptMessage,
    cryptoInitialized: cryptoInitialized
  });

  // Scroll para a última mensagem
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  // Função para confirmar algoritmo selecionado - MODIFICADO
  const handleConfirmAlgorithm = async () => {
    console.log(`✅ Algoritmo confirmado: ${CryptoProviderFactory.getAlgorithmDisplayName(selectedAlgorithm)}`);
    setAlgorithmConfirmed(true);
    setAlgorithmLocked(true);
    setShowAlgorithmModal(false);
    // REMOVIDO: setShowCryptoPanel(false); - mantém painel aberto
  };

  // MODIFICADO: Função para inicializar criptografia manualmente
  const handleInitializeCryptography = async () => {
    if (!algorithmConfirmed) {
      alert('Primeiro confirme o algoritmo de criptografia!');
      return;
    }

    try {
      console.log('🔄 Inicializando criptografia manualmente...');
      await initializeCryptography();
      console.log('✅ Criptografia inicializada com sucesso!');
      
      // Após inicializar, pré-carregar chave do destinatário
      const receiverId = getReceiver();
      console.log(`🎯 Pré-carregando chave para destinatário: ${receiverId}`);
      
      const keySuccess = await preloadRecipientKey(receiverId);
      if (keySuccess) {
        console.log(`✅ Chave do destinatário carregada: ${receiverId}`);
        debugKeys();
        // NOVO: Fechar painel após inicialização bem-sucedida
        setShowCryptoPanel(false);
      } else {
        console.warn(`⚠️ Falha ao carregar chave do destinatário: ${receiverId}`);
      }
    } catch (err) {
      console.error('❌ Erro ao inicializar criptografia:', err);
      alert(`Erro ao inicializar criptografia: ${err}`);
    }
  };

  // Função para alterar algoritmo - MODIFICADA
  const handleAlgorithmChange = (newAlgorithm: CryptoAlgorithm) => {
    if (algorithmLocked || algorithmConfirmed || messages.length > 0) {
      return;
    }
    
    console.log(`🔄 Alterando algoritmo de criptografia para: ${newAlgorithm}`);
    setSelectedAlgorithm(newAlgorithm);
  };

  // MODIFICADO: Efeito para verificar autenticação e mostrar modal apenas uma vez
  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    
    // Se não tem usuário salvo e não tem usuário no hook, redireciona
    if (!savedUser && !user) {
      navigate('/');
      return;
    }

    // CORRIGIDO: Mostrar modal apenas uma vez ao fazer login e se ainda não foi confirmado
    if ((savedUser || user) && !algorithmConfirmed && !hasShownInitialModal) {
      setTimeout(() => {
        setShowAlgorithmModal(true);
        setShowCryptoPanel(true);
        setHasShownInitialModal(true);
      }, 500);
    }
  }, [user, navigate]);

  // Efeito para pré-carregar chave pública do destinatário - MODIFICADO
  useEffect(() => {
    if (cryptoInitialized && cryptoEnabled && algorithmConfirmed) {
      const preloadKey = async () => {
        try {
          const receiverId = getReceiver();
          console.log(`🎯 Pré-carregando chave para destinatário: ${receiverId}`);
          
          const success = await preloadRecipientKey(receiverId);
          
          if (success) {
            console.log(`✅ Chave pré-carregada com sucesso para ${receiverId}`);
            debugKeys();
          } else {
            console.warn(`⚠️ Não foi possível pré-carregar chave para ${receiverId}`);
          }
        } catch (err) {
          console.error('❌ Erro ao pré-carregar chave:', err);
        }
      };

      preloadKey();
    }
  }, [cryptoInitialized, cryptoEnabled, algorithmConfirmed, preloadRecipientKey, debugKeys]);

  // Scroll automático quando novas mensagens chegam
  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Limpa mensagens quando o usuário muda
  useEffect(() => {
    return () => {
      clearMessages();
    };
  }, [getCurrentUser(), clearMessages]);

  // Bloquear seleção de algoritmo quando inicializar ou houver mensagens - MODIFICADO
  useEffect(() => {
    if (algorithmConfirmed || cryptoInitialized || messages.length > 0) {
      setAlgorithmLocked(true);
    }
  }, [algorithmConfirmed, cryptoInitialized, messages.length]);

  // Enviar mensagem com criptografia - MODIFICADO para verificar confirmação
  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const currentUserName = getCurrentUser();
    
    if (!messageContent.trim() || !currentUserName) return;

    // Verificar se algoritmo foi confirmado
    if (!algorithmConfirmed) {
      alert('Por favor, selecione e confirme um algoritmo de criptografia no Painel E2E.');
      setShowCryptoPanel(true);
      return;
    }

    // Preparar dados base da mensagem
    let messageData: any = {
      sender: currentUserName,
      receiver: getReceiver(),
      content: messageContent.trim(),
      encrypted: false
    };

    // Criptografar mensagem se habilitado e inicializado
    if (cryptoEnabled && cryptoInitialized && algorithmConfirmed) {
      try {
        const encryptedData = await encryptMessage(messageContent.trim(), getReceiver());
        messageData = {
          ...messageData,
          encrypted: true,
          encryptedData,
        };
        
        console.log('✅ Mensagem criptografada localmente para envio');
      } catch (err) {
        console.error('❌ Erro ao criptografar mensagem:', err);
        alert('Erro na criptografia. Mensagem será enviada sem criptografia.');
      }
    }

    const result = await sendMessage(messageData);
    
    if (result.success && result.message) {
      const messageToAdd = {
        ...result.message,
        content: messageContent.trim()
      };
      
      addMessageLocally(messageToAdd);
      setMessageContent('');
      
      setTimeout(() => {
        refreshMessages();
      }, 500);
    }
  };

  // MODIFICADO: Logout com limpeza completa de estados
  const handleLogout = () => {
    clearMessages();
    if (cryptoEnabled) {
      clearCryptoKeys();
    }
    setAlgorithmConfirmed(false);
    setAlgorithmLocked(false);
    setHasShownInitialModal(false);
    setShowAlgorithmModal(false);
    setShowCryptoPanel(false);
    logout();
    navigate('/');
  };

  // MODIFICADO: Função para fechar modal manualmente
  const handleCloseModal = () => {
    setShowAlgorithmModal(false);
    // Se ainda não confirmou, abrir o painel para facilitar configuração
    if (!algorithmConfirmed) {
      setShowCryptoPanel(true);
    }
    // NOVO: Se confirmou mas não inicializou, manter painel aberto
    if (algorithmConfirmed && !cryptoInitialized) {
      setShowCryptoPanel(true);
    }
  };

  // NOVO: Função para reiniciar sessão que reseta o controle do modal
  const handleRestartSession = () => {
    if (confirm('Deseja reiniciar a sessão? Isso irá limpar todas as mensagens e permitir nova seleção de algoritmo.')) {
      clearMessages();
      clearCryptoKeys();
      setAlgorithmConfirmed(false);
      setAlgorithmLocked(false);
      setHasShownInitialModal(false);
      setShowAlgorithmModal(true);
      setShowCryptoPanel(true);
    }
  };

  // Formatar timestamp
  const formatTimestamp = (timestamp?: string) => {
    if (!timestamp) return '';
    return new Date(timestamp).toLocaleString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  // Função para verificar se é mensagem própria
  const isOwnMessage = (messageSender: string) => {
    const currentUserName = getCurrentUser();
    return messageSender === currentUserName;
  };

  // Exibe nome do usuário atual
  const getCurrentUserDisplay = () => {
    const currentUserName = getCurrentUser();
    return currentUserName || 'Usuário não identificado';
  };

  return (
    <div className="container-fluid vh-100 d-flex flex-column bg-light">
      {/* Modal para escolha de algoritmo - MODIFICADO */}
      {showAlgorithmModal && (
        <div className="modal fade show d-block" tabIndex={-1} style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-header bg-primary text-white">
                <h5 className="modal-title">
                  <i className="bi bi-shield-lock me-2"></i>
                  Configuração de Criptografia
                </h5>
                <button 
                  type="button" 
                  className="btn-close btn-close-white" 
                  onClick={handleCloseModal}
                  title="Fechar modal"
                ></button>
              </div>
              <div className="modal-body">
                <div className="alert alert-info">
                  <i className="bi bi-info-circle me-2"></i>
                  <strong>Bem-vindo!</strong> Antes de começar a conversar, escolha o algoritmo de criptografia no Painel E2E abaixo.
                </div>
                <p className="text-muted">
                  O algoritmo selecionado será usado para criptografar todas as suas mensagens. 
                  Esta escolha não poderá ser alterada durante a sessão.
                </p>
              </div>
              <div className="modal-footer">
                <div className="d-flex justify-content-between align-items-center w-100">
                  <div className="text-muted small">
                    <i className="bi bi-arrow-down me-1"></i>
                    Configure o algoritmo no painel abaixo e clique em "Confirmar Algoritmo"
                  </div>
                  <div className="d-flex gap-2">
                    <button 
                      type="button" 
                      className="btn btn-outline-secondary btn-sm"
                      onClick={handleCloseModal}
                    >
                      <i className="bi bi-x me-1"></i>
                      Fechar
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="row bg-primary text-white py-3 shadow-sm">
        <div className="col-12">
          <div className="d-flex justify-content-between align-items-center">
            <div className="d-flex align-items-center">
              <div>
                <h5 className="mb-0">
                  Chat com {getOtherUserName()}
                  {cryptoEnabled && cryptoInitialized && algorithmConfirmed && (
                    <i className="bi bi-shield-lock ms-2 text-warning" title="Criptografia E2E ativada"></i>
                  )}
                  {!algorithmConfirmed && (
                    <span className="badge bg-warning text-dark ms-2">
                      <i className="bi bi-gear me-1"></i>
                      Configuração pendente
                    </span>
                  )}
                </h5>
                <small className="opacity-75">
                  Logado como: {getCurrentUserDisplay()}
                  {isLoadingMessages && algorithmConfirmed && (
                    <span className="ms-2">
                      <i className="bi bi-arrow-clockwise"></i> Sincronizando...
                    </span>
                  )}
                  {cryptoInitializing && (
                    <span className="ms-2">
                      <i className="bi bi-key"></i> Inicializando criptografia...
                    </span>
                  )}
                </small>
              </div>
            </div>
            <div className="d-flex align-items-center gap-2">
              <button 
                className={`btn btn-outline-light btn-sm ${!algorithmConfirmed ? 'btn-warning text-dark' : ''}`}
                onClick={() => setShowCryptoPanel(!showCryptoPanel)}
                title="Configurações de criptografia"
              >
                {!algorithmConfirmed && <i className="bi bi-exclamation-triangle me-1"></i>}
                Painel E2E
              </button>
              <button 
                className="btn btn-outline-light btn-sm"
                onClick={handleLogout}
              >
                Sair
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Crypto Panel */}
      {showCryptoPanel && (
        <div className="row">
          <div className="col-12">
            <div className={`alert mb-0 border-0 rounded-0 ${!algorithmConfirmed ? 'alert-warning' : 'alert-info'}`}>
              <div className="d-flex flex-column">
                <div className="flex-grow-1">
                  <h6 className="mb-3">
                    <i className="bi bi-shield-lock me-2"></i>
                    Criptografia de Ponta-a-Ponta
                    {!algorithmConfirmed && (
                      <span className="badge bg-warning text-dark ms-2">
                        <i className="bi bi-gear me-1"></i>
                        Configuração necessária
                      </span>
                    )}
                  </h6>

                  {/* Seleção de Algoritmo */}
                  <div className="mb-3">
                    <label htmlFor="algorithmSelect" className="form-label fw-semibold">
                      <i className="bi bi-gear me-2"></i>
                      Algoritmo de Criptografia:
                      {!algorithmConfirmed && <span className="text-danger">*</span>}
                    </label>
                    <select 
                      id="algorithmSelect"
                      className={`form-select form-select-sm ${!algorithmConfirmed ? 'border-warning' : ''}`}
                      value={selectedAlgorithm}
                      onChange={(e) => handleAlgorithmChange(e.target.value as CryptoAlgorithm)}
                      disabled={algorithmLocked || cryptoInitializing || !cryptoEnabled}
                    >
                      {CryptoProviderFactory.getAvailableAlgorithms().map((algorithm) => (
                        <option key={algorithm} value={algorithm}>
                          {CryptoProviderFactory.getAlgorithmDisplayName(algorithm)}
                        </option>
                      ))}
                    </select>
                    
                    {/* Botão de confirmação */}
                    {!algorithmConfirmed && cryptoEnabled && (
                      <div className="mt-2">
                        <button 
                          className="btn btn-warning btn-sm fw-semibold"
                          onClick={handleConfirmAlgorithm}
                          disabled={cryptoInitializing}
                        >
                          <i className="bi bi-check-circle me-1"></i>
                          Confirmar Algoritmo
                        </button>
                      </div>
                    )}
                    
                    {algorithmLocked && algorithmConfirmed && (
                      <div className="form-text text-success">
                        <i className="bi bi-lock me-1"></i>
                        Algoritmo confirmado e bloqueado para esta sessão
                      </div>
                    )}
                  </div>

                  {/* Status da Criptografia */}
                  <div className="row g-3">
                    <div className="col-md-6">
                      <div className="d-flex align-items-center">
                        <div className={`me-2 ${
                          algorithmConfirmed 
                            ? cryptoInitialized ? 'text-success' : cryptoInitializing ? 'text-warning' : 'text-muted'
                            : 'text-secondary'
                        }`}>
                          <i className={`bi ${
                            !algorithmConfirmed ? 'bi-hourglass' :
                            cryptoInitialized ? 'bi-check-circle-fill' : 
                            cryptoInitializing ? 'bi-hourglass-split' : 'bi-x-circle'
                          }`}></i>
                        </div>
                        <div>
                          <small className="fw-semibold">Status:</small>
                          <div className="small">
                            {!algorithmConfirmed ? 'Aguardando confirmação' :
                            cryptoInitializing ? 'Inicializando...' : 
                            cryptoInitialized ? 'Ativo' : 
                            cryptoEnabled ? 'Aguardando inicialização' : 'Desativado'}
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="col-md-6">
                      <div className="d-flex align-items-center">
                        <div className="me-2 text-info">
                          <i className="bi bi-key"></i>
                        </div>
                        <div>
                          <small className="fw-semibold">Chaves em cache:</small>
                          <div className="small">
                            {algorithmConfirmed && cryptoInitialized ? getCachedKeys().length : 0} chave(s)
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Informações detalhadas quando ativo */}
                  {algorithmConfirmed && cryptoEnabled && cryptoInitialized && (
                    <div className="mt-3 p-2 bg-light rounded">
                      <div className="row g-2 small">
                        <div className="col-12">
                          <strong>Algoritmo:</strong> {CryptoProviderFactory.getAlgorithmDisplayName(selectedAlgorithm)}
                        </div>
                        <div className="col-12">
                          <strong>Destinatário:</strong> {getReceiver()}
                        </div>
                        <div className="col-12">
                          <strong>Status do cache:</strong> 
                          <span className={`ms-1 ${getCachedKeys().includes(getReceiver()) ? 'text-success' : 'text-warning'}`}>
                            {getCachedKeys().includes(getReceiver()) ? '✓ Chave carregada' : '⚠ Carregando...'}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Aviso sobre necessidade de confirmação */}
                  {!algorithmConfirmed && cryptoEnabled && (
                    <div className="alert alert-warning mt-3 mb-0 small">
                      <i className="bi bi-exclamation-triangle me-2"></i>
                      <strong>Ação necessária:</strong> Confirme o algoritmo selecionado para inicializar a criptografia e começar a conversar.
                    </div>
                  )}

                  {/* NOVO: Aviso sobre necessidade de inicialização */}
                  {algorithmConfirmed && cryptoEnabled && !cryptoInitialized && !cryptoInitializing && (
                    <div className="alert alert-info mt-3 mb-0 small">
                      <i className="bi bi-info-circle me-2"></i>
                      <strong>Ação necessária:</strong> Aperte "Inicializar Criptografia" para configurar as chaves e começar a conversar.
                    </div>
                  )}

                  {/* Aviso durante inicialização */}
                  {cryptoInitializing && (
                    <div className="alert alert-warning mt-3 mb-0 small">
                      <i className="bi bi-hourglass-split me-2"></i>
                      <strong>Aguarde:</strong> Inicializando criptografia e configurando chaves...
                    </div>
                  )}

                  {/* Erro da criptografia */}
                  {cryptoError && (
                    <div className="alert alert-danger mt-3 mb-0 small">
                      <i className="bi bi-exclamation-triangle me-2"></i>
                      <strong>Erro:</strong> {cryptoError}
                    </div>
                  )}
                </div>

                {/* Botões de Ação - MODIFICADO */}
                <div className="d-flex flex-wrap gap-2 mt-3 pt-3 border-top">
                  {/* NOVO: Botão para inicializar criptografia manualmente */}
                  {algorithmConfirmed && cryptoEnabled && !cryptoInitialized && !cryptoInitializing && (
                    <button 
                      className="btn btn-success btn-sm fw-semibold"
                      onClick={handleInitializeCryptography}
                      title="Inicializar criptografia e configurar chaves"
                    >
                      <i className="bi bi-key me-1"></i>
                      Inicializar Criptografia
                    </button>
                  )}

                  {/* Botão de status quando está inicializando */}
                  {cryptoInitializing && (
                    <button 
                      className="btn btn-warning btn-sm fw-semibold"
                      disabled
                      title="Inicializando criptografia..."
                    >
                      <i className="bi bi-hourglass-split me-1"></i>
                      Inicializando...
                    </button>
                  )}

                  {algorithmConfirmed && cryptoEnabled && cryptoInitialized && (
                    <>
                      <button 
                        className="btn btn-outline-secondary btn-sm"
                        onClick={() => {
                          const publicKey = getPublicKey();
                          if (publicKey) {
                            navigator.clipboard.writeText(publicKey);
                            alert('Chave pública copiada para clipboard!');
                          }
                        }}
                        title="Copiar minha chave pública"
                      >
                        <i className="bi bi-clipboard me-1"></i>
                        Copiar chave pública
                      </button>
                      
                      <button 
                        className="btn btn-outline-info btn-sm"
                        onClick={debugKeys}
                        title="Mostrar informações de debug das chaves"
                      >
                        <i className="bi bi-bug me-1"></i>
                        Debug chaves
                      </button>

                      <button 
                        className="btn btn-outline-primary btn-sm"
                        onClick={async () => {
                          try {
                            const receiverId = getReceiver();
                            console.log(`🔄 Recarregando chave do destinatário: ${receiverId}`);
                            const success = await preloadRecipientKey(receiverId);
                            if (success) {
                              alert(`✅ Chave do destinatário recarregada: ${receiverId}`);
                              debugKeys();
                            } else {
                              alert(`❌ Falha ao recarregar chave: ${receiverId}`);
                            }
                          } catch (err) {
                            console.error('❌ Erro ao recarregar chave:', err);
                            alert(`Erro: ${err}`);
                          }
                        }}
                        title="Recarregar chave do destinatário"
                      >
                        <i className="bi bi-arrow-clockwise me-1"></i>
                        Recarregar chaves
                      </button>
                    </>
                  )}
                  
                  {algorithmConfirmed && (
                    <button 
                      className="btn btn-outline-danger btn-sm"
                      onClick={handleRestartSession}
                      title="Reiniciar sessão"
                    >
                      <i className="bi bi-arrow-clockwise me-1"></i>
                      Reiniciar sessão
                    </button>
                  )}
                  
                  <button 
                    className="btn btn-outline-secondary btn-sm"
                    onClick={() => setShowCryptoPanel(false)}
                    title="Fechar painel"
                  >
                    <i className="bi bi-x me-1"></i>
                    Fechar
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Messages Area - MODIFICADO para mostrar aviso quando não inicializado */}
      <div className="row flex-grow-1">
        <div className="col-12 p-0">
          <div 
            className="h-100 overflow-auto p-3" 
            style={{ maxHeight: 'calc(100vh - 200px)' }}
          >
            {!algorithmConfirmed ? (
              <div className="text-center py-5">
                <i className="bi bi-gear text-warning" style={{ fontSize: '3rem' }}></i>
                <h4 className="mt-3 text-warning">Configuração Necessária</h4>
                <p className="text-muted">
                  Para começar a conversar, configure o algoritmo de criptografia no Painel E2E.
                </p>
                <button 
                  className="btn btn-warning"
                  onClick={() => setShowCryptoPanel(true)}
                >
                  <i className="bi bi-gear me-2"></i>
                  Abrir Painel E2E
                </button>
              </div>
            ) : algorithmConfirmed && !cryptoInitialized && !cryptoInitializing ? (
              // NOVO: Tela para quando algoritmo está confirmado mas não inicializado
              <div className="text-center py-5">
                <i className="bi bi-key text-info" style={{ fontSize: '3rem' }}></i>
                <h4 className="mt-3 text-info">Inicialização Necessária</h4>
                <p className="text-muted">
                  Algoritmo {CryptoProviderFactory.getAlgorithmDisplayName(selectedAlgorithm)} confirmado.
                  <br />
                  Agora inicialize a criptografia para começar a conversar.
                </p>
                <button 
                  className="btn btn-success me-2"
                  onClick={handleInitializeCryptography}
                >
                  <i className="bi bi-key me-2"></i>
                  Inicializar Criptografia
                </button>
                <button 
                  className="btn btn-outline-secondary"
                  onClick={() => setShowCryptoPanel(true)}
                >
                  <i className="bi bi-gear me-2"></i>
                  Abrir Painel E2E
                </button>
              </div>
            ) : cryptoInitializing ? (
              // NOVO: Tela durante inicialização
              <div className="text-center py-5">
                <div className="spinner-border text-warning" role="status" style={{ width: '3rem', height: '3rem' }}>
                  <span className="visually-hidden">Inicializando criptografia...</span>
                </div>
                <h4 className="mt-3 text-warning">Inicializando Criptografia</h4>
                <p className="text-muted">
                  Configurando chaves para {CryptoProviderFactory.getAlgorithmDisplayName(selectedAlgorithm)}...
                  <br />
                  <small>Isso pode levar alguns segundos.</small>
                </p>
              </div>
            ) : isLoadingMessages && messages.length === 0 ? (
              <div className="text-center py-5">
                <div className="spinner-border text-primary" role="status">
                  <span className="visually-hidden">Carregando mensagens...</span>
                </div>
                <p className="mt-2 text-muted">Carregando mensagens...</p>
              </div>
            ) : messages.length === 0 ? (
              <div className="text-center py-5">
                <i className="bi bi-chat-dots text-muted" style={{ fontSize: '3rem' }}></i>
                <p className="text-muted mt-3">Nenhuma mensagem ainda. Comece a conversar!</p>
                {cryptoEnabled && cryptoInitialized && algorithmConfirmed && (
                  <small className="text-success">
                    <i className="bi bi-shield-lock me-1"></i>
                    Suas mensagens serão criptografadas com {CryptoProviderFactory.getAlgorithmDisplayName(selectedAlgorithm)}
                  </small>
                )}
              </div>
            ) : (
              <div className="d-flex flex-column gap-2">
                {messages.map((message, index) => {
                  const isOwn = isOwnMessage(message.sender);
                  const hasDecryptionError = message.id && decryptionErrors.has(message.id);
                  
                  return (
                    <div 
                      key={message.id || index}
                      className={`d-flex ${isOwn ? 'justify-content-end' : 'justify-content-start'}`}
                    >
                      <div 
                        className={`card border-0 shadow-sm ${
                          isOwn
                            ? 'bg-primary text-white' 
                            : hasDecryptionError
                            ? 'bg-danger text-white'
                            : 'bg-white'
                        }`}
                        style={{ maxWidth: '70%' }}
                      >
                        <div className="card-body p-3">
                          <div className="d-flex align-items-start gap-2">
                            {message.encrypted && (
                              <i 
                                className="bi bi-shield-lock" 
                                title={`Mensagem criptografada com ${CryptoProviderFactory.getAlgorithmDisplayName(selectedAlgorithm)}`}
                              ></i>
                            )}
                            <div className="flex-grow-1">
                              <p className="mb-1">{message.content}</p>
                              {hasDecryptionError && (
                                <small className="text-white-50">
                                  <i className="bi bi-exclamation-triangle me-1"></i>
                                  Erro: {decryptionErrors.get(message.id!)}
                                </small>
                              )}
                            </div>
                          </div>
                          <div className="d-flex justify-content-between align-items-center mt-1">
                            <small 
                              className={`${
                                isOwn || hasDecryptionError ? 'text-white-50' : 'text-muted'
                              }`}
                            >
                              {formatTimestamp(message.timestamp)}
                            </small>
                            {message.encrypted && (
                              <small 
                                className={`${
                                  isOwn || hasDecryptionError ? 'text-white-50' : 'text-muted'
                                }`}
                                title="Mensagem protegida por criptografia pós-quântica"
                              >
                                <i className="bi bi-shield-check"></i>
                              </small>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
                <div ref={messagesEndRef} />
              </div>
            )}

            {conversationError && (
              <div className="alert alert-danger" role="alert">
                <i className="bi bi-exclamation-triangle me-2"></i>
                {conversationError}
                <button 
                  className="btn btn-sm btn-outline-danger ms-2"
                  onClick={refreshMessages}
                >
                  Tentar novamente
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Message Input - MODIFICADO para só aparecer após inicialização completa */}
      {algorithmConfirmed && cryptoInitialized && (
        <div className="row bg-white border-top">
          <div className="col-12 p-3">
            <form onSubmit={handleSendMessage}>
              <div className="input-group">
                <input
                  type="text"
                  className={`form-control ${sendError ? 'is-invalid' : ''}`}
                  placeholder={
                    cryptoEnabled && cryptoInitialized 
                      ? `Digite sua mensagem (será criptografada com ${CryptoProviderFactory.getAlgorithmDisplayName(selectedAlgorithm)})...` 
                      : "Digite sua mensagem..."
                  }
                  value={messageContent}
                  onChange={(e) => setMessageContent(e.target.value)}
                  disabled={isSending}
                  maxLength={500}
                />
                <button
                  type="submit"
                  className={`btn px-4 ${
                    cryptoEnabled && cryptoInitialized 
                      ? 'btn-success' 
                      : 'btn-primary'
                  }`}
                  disabled={isSending || !messageContent.trim()}
                >
                  {isSending ? (
                    <>
                      <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                      Enviando...
                    </>
                  ) : (
                    <>
                      <i className={`bi ${
                        cryptoEnabled && cryptoInitialized 
                          ? 'bi-shield-lock' 
                          : 'bi-send'
                      } me-2`}></i>
                      {cryptoEnabled && cryptoInitialized ? 'Enviar (E2E)' : 'Enviar'}
                    </>
                  )}
                </button>
              </div>
              
              {sendError && (
                <div className="text-danger mt-2">
                  <small>
                    <i className="bi bi-exclamation-circle me-1"></i>
                    {sendError}
                  </small>
                </div>
              )}
              
              <div className="d-flex justify-content-between align-items-center mt-2">
                <small className="text-muted">
                  {messageContent.length}/500 caracteres
                </small>
                
                <div className="d-flex align-items-center gap-3">
                  {cryptoEnabled && algorithmConfirmed && (
                    <small className={`${cryptoInitialized ? 'text-success' : 'text-warning'}`}>
                      <i className="bi bi-shield-lock me-1"></i>
                      {cryptoInitialized ? `E2E Ativo (${CryptoProviderFactory.getAlgorithmDisplayName(selectedAlgorithm)})` : 'Inicializando...'}
                    </small>
                  )}
                  
                  {!cryptoEnabled && (
                    <small className="text-muted">
                      <i className="bi bi-shield-slash me-1"></i>
                      Sem criptografia
                    </small>
                  )}
                </div>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default MessagePage;