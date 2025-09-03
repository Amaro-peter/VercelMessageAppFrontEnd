import type { EncryptedMessage, ICryptoProvider, KeyPair } from "../interface/ICryptoProvider";

/**
 * Converters base64 <-> Uint8Array
 */
function uint8ArrayToBase64(bytes: Uint8Array): string {
  try {
    if (typeof btoa !== "undefined") {
      // Browser environment
      let binary = "";
      const len = bytes.byteLength;
      for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    }
    // Node environment
    return Buffer.from(bytes).toString("base64");
  } catch (error) {
    console.error("Erro ao converter Uint8Array para Base64:", error);
    throw new Error(`Falha na codificação Base64: ${error}`);
  }
}

function base64ToUint8Array(base64: string): Uint8Array {
  try {
    // Validar entrada
    if (!base64 || typeof base64 !== 'string') {
      throw new Error("String Base64 inválida ou vazia");
    }

    // Limpar string Base64 (remover espaços, quebras de linha, etc.)
    const cleanBase64 = base64.replace(/[\s\r\n]/g, '');
    
    // Validar formato Base64
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(cleanBase64)) {
      throw new Error("Formato Base64 inválido");
    }

    if (typeof atob !== "undefined") {
      // Browser environment
      const binary = atob(cleanBase64);
      const len = binary.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    }
    
    // Node environment
    return Uint8Array.from(Buffer.from(cleanBase64, "base64"));
  } catch (error) {
    console.error("Erro ao converter Base64 para Uint8Array:", error);
    console.error("String Base64 problemática:", base64?.substring(0, 100) + "...");
    throw new Error(`Falha na decodificação Base64: ${error}`);
  }
}

/**
 * Secure random bytes
 */
function cryptoGetRandomBytes(n: number): Uint8Array {
  const gcrypto: any = (globalThis as any).crypto;
  if (gcrypto && typeof gcrypto.getRandomValues === "function") {
    const b = new Uint8Array(n);
    gcrypto.getRandomValues(b);
    return b;
  }

  // Node fallback
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const nodeCrypto = require("crypto");
    if (typeof nodeCrypto.randomBytes === "function") {
      return new Uint8Array(nodeCrypto.randomBytes(n));
    }
  } catch (_) {
    // ignore
  }

  throw new Error("Nenhuma fonte segura de aleatoriedade disponível (crypto.getRandomValues / node crypto.randomBytes).");
}

/**
 * Validar EncryptedMessage
 */
function validateEncryptedMessage(encryptedMessage: EncryptedMessage): void {
  if (!encryptedMessage) {
    throw new Error("EncryptedMessage é null ou undefined");
  }

  const requiredFields = ['encryptedContent', 'encryptedSymmetricKey', 'nonce'];
  for (const field of requiredFields) {
    if (!encryptedMessage[field as keyof EncryptedMessage]) {
      throw new Error(`Campo obrigatório ausente: ${field}`);
    }
  }

  // Validar que os campos são strings não vazias
  if (typeof encryptedMessage.encryptedContent !== 'string' || encryptedMessage.encryptedContent.length === 0) {
    throw new Error("encryptedContent deve ser uma string não vazia");
  }
  
  if (typeof encryptedMessage.encryptedSymmetricKey !== 'string' || encryptedMessage.encryptedSymmetricKey.length === 0) {
    throw new Error("encryptedSymmetricKey deve ser uma string não vazia");
  }
  
  if (typeof encryptedMessage.nonce !== 'string' || encryptedMessage.nonce.length === 0) {
    throw new Error("nonce deve ser uma string não vazia");
  }
}

/**
 * RSAProvider usando WebCrypto API
 * Implementa criptografia híbrida: RSA-OAEP (para chave simétrica) + AES-GCM (para dados)
 */
class RSAProvider implements ICryptoProvider {
  private readonly AES_IV_BYTES = 12; // AES-GCM nonce
  private readonly AES_KEY_BYTES = 32; // AES-256
  private readonly RSA_KEY_SIZE = 2048; // Tamanho da chave RSA em bits
  private readonly ALGO_NAME = "RSA-OAEP-2048 + AES-GCM";

  constructor() {}

  getAlgorithmName(): string {
    return this.ALGO_NAME;
  }

  /**
   * Gera par de chaves RSA (2048 bits) usando WebCrypto
   */
  public async generateKeyPair(): Promise<KeyPair> {
    try {
      const subtle = (globalThis as any).crypto?.subtle;
      if (!subtle) {
        throw new Error("WebCrypto (crypto.subtle) não disponível no runtime.");
      }

      console.log(`🔑 Gerando par de chaves RSA-${this.RSA_KEY_SIZE}...`);

      const cryptoKeyPair = await subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: this.RSA_KEY_SIZE,
          publicExponent: new Uint8Array([1, 0, 1]), // 65537
          hash: "SHA-256",
        },
        true, // extractable
        ["encrypt", "decrypt"]
      );

      // Exportar chaves para raw bytes
      const publicKeyBuffer = await subtle.exportKey("spki", cryptoKeyPair.publicKey);
      const privateKeyBuffer = await subtle.exportKey("pkcs8", cryptoKeyPair.privateKey);

      const publicKey = new Uint8Array(publicKeyBuffer);
      const privateKey = new Uint8Array(privateKeyBuffer);
      
      console.log(`🔑 RSA KeyPair gerado - PK: ${publicKey.length} bytes, SK: ${privateKey.length} bytes`);
      
      return { publicKey, privateKey };
    } catch (error) {
      console.error("Erro ao gerar par de chaves RSA:", error);
      throw new Error(`Falha na geração de chaves: ${error}`);
    }
  }

  /**
   * Encrypt: Gera chave AES aleatória -> RSA-OAEP(chave AES) + AES-GCM(mensagem)
   */
  public async encrypt(message: string, recipientPublicKey: Uint8Array): Promise<EncryptedMessage> {
    try {
      const subtle = (globalThis as any).crypto?.subtle;
      if (!subtle) {
        throw new Error("WebCrypto (crypto.subtle) não disponível no runtime.");
      }

      // Validar entradas
      if (!message || typeof message !== 'string') {
        throw new Error("Mensagem deve ser uma string não vazia");
      }
      
      if (!recipientPublicKey || recipientPublicKey.length === 0) {
        throw new Error("Chave pública do destinatário inválida");
      }

      console.log(`🔒 Iniciando criptografia RSA - Mensagem: ${message.length} chars, PK: ${recipientPublicKey.length} bytes`);

      // 1. Importar chave pública RSA
      const rsaPublicKey = await subtle.importKey(
        "spki",
        recipientPublicKey.buffer,
        {
          name: "RSA-OAEP",
          hash: "SHA-256",
        },
        false,
        ["encrypt"]
      );

      // 2. Gerar chave simétrica AES-256 aleatória
      const aesKeyBytes = cryptoGetRandomBytes(this.AES_KEY_BYTES);
      const aesKey = await subtle.importKey(
        "raw",
        aesKeyBytes.buffer,
        "AES-GCM",
        false,
        ["encrypt"]
      );

      console.log(`🔐 Chave AES-256 gerada: ${aesKeyBytes.length} bytes`);

      // 3. Criptografar a chave AES com RSA-OAEP
      const encryptedAesKeyBuffer = await subtle.encrypt(
        {
          name: "RSA-OAEP"
        },
        rsaPublicKey,
        aesKeyBytes.buffer
      );
      const encryptedAesKey = new Uint8Array(encryptedAesKeyBuffer);

      console.log(`🔐 Chave AES criptografada com RSA: ${encryptedAesKey.length} bytes`);

      // 4. Criptografar mensagem com AES-GCM
      const iv = cryptoGetRandomBytes(this.AES_IV_BYTES);
      const encoder = new TextEncoder();
      const plaintext = encoder.encode(message);

      const encryptedBuffer = await subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        plaintext
      );
      const encryptedBytes = new Uint8Array(encryptedBuffer);

      console.log(`🔐 AES-GCM encrypt concluído - Encrypted: ${encryptedBytes.length} bytes, IV: ${iv.length} bytes`);

      const result: EncryptedMessage = {
        algorithm: this.ALGO_NAME,
        timestamp: new Date().toISOString(),
        encryptedContent: uint8ArrayToBase64(encryptedBytes),
        encryptedSymmetricKey: uint8ArrayToBase64(encryptedAesKey),
        nonce: uint8ArrayToBase64(iv),
      };

      console.log(`✅ Criptografia RSA concluída com sucesso`);
      return result;
      
    } catch (error) {
      console.error("Erro na criptografia RSA:", error);
      throw new Error(`Falha na criptografia: ${error}`);
    }
  }

  /**
   * Decrypt: RSA-OAEP decrypt(chave simétrica) -> AES-GCM decrypt(mensagem)
   */
  public async decrypt(encryptedMessage: EncryptedMessage, privateKey: Uint8Array): Promise<string> {
    try {
      const subtle = (globalThis as any).crypto?.subtle;
      if (!subtle) {
        throw new Error("WebCrypto (crypto.subtle) não disponível no runtime.");
      }

      // Validar entrada
      validateEncryptedMessage(encryptedMessage);
      
      if (!privateKey || privateKey.length === 0) {
        throw new Error("Chave privada inválida");
      }

      console.log(`🔓 Iniciando descriptografia RSA - Algorithm: ${encryptedMessage.algorithm}`);

      // Decodificar dados Base64
      const encryptedAesKey = base64ToUint8Array(encryptedMessage.encryptedSymmetricKey);
      const iv = base64ToUint8Array(encryptedMessage.nonce);
      const cipherBytes = base64ToUint8Array(encryptedMessage.encryptedContent);

      console.log(`🔐 Dados decodificados - RSA CT: ${encryptedAesKey.length} bytes, IV: ${iv.length} bytes, Cipher: ${cipherBytes.length} bytes`);

      // 1. Importar chave privada RSA
      const rsaPrivateKey = await subtle.importKey(
        "pkcs8",
        privateKey.buffer,
        {
          name: "RSA-OAEP",
          hash: "SHA-256",
        },
        false,
        ["decrypt"]
      );

      // 2. Descriptografar chave AES com RSA-OAEP
      let aesKeyBuffer: ArrayBuffer;
      try {
        aesKeyBuffer = await subtle.decrypt(
          {
            name: "RSA-OAEP"
          },
          rsaPrivateKey,
          encryptedAesKey.buffer
        );
      } catch (e) {
        console.error("Erro no RSA-OAEP decrypt:", e);
        throw new Error("Falha ao descriptografar chave simétrica: chave privada incorreta ou dados corrompidos.");
      }

      const aesKeyBytes = new Uint8Array(aesKeyBuffer);
      console.log(`🔐 Chave AES recuperada: ${aesKeyBytes.length} bytes`);

      // 3. Importar chave AES
      const aesKey = await subtle.importKey(
        "raw",
        aesKeyBytes.buffer,
        "AES-GCM",
        false,
        ["decrypt"]
      );

      // 4. Descriptografar mensagem com AES-GCM
      let plainBuffer: ArrayBuffer;
      try {
        plainBuffer = await subtle.decrypt(
          { name: "AES-GCM", iv },
          aesKey,
          cipherBytes.buffer
        );
      } catch (e) {
        console.error("Erro no AES-GCM decrypt:", e);
        throw new Error("Falha ao descriptografar: integridade inválida ou chave incorreta.");
      }

      const decoder = new TextDecoder();
      const result = decoder.decode(plainBuffer);
      
      console.log(`✅ Descriptografia RSA concluída com sucesso - Mensagem: ${result.length} chars`);
      return result;
      
    } catch (error) {
      console.error("Erro na descriptografia RSA:", error);
      throw new Error(`Falha na descriptografia: ${error}`);
    }
  }

  /**
   * Export/import helpers (base64)
   */
  public exportPublicKey(pk: Uint8Array): string {
    try {
      return uint8ArrayToBase64(pk);
    } catch (error) {
      throw new Error(`Erro ao exportar chave pública: ${error}`);
    }
  }
  
  public importPublicKey(s: string): Uint8Array {
    try {
      return base64ToUint8Array(s);
    } catch (error) {
      throw new Error(`Erro ao importar chave pública: ${error}`);
    }
  }

  public exportPrivateKey(sk: Uint8Array): string {
    try {
      return uint8ArrayToBase64(sk);
    } catch (error) {
      throw new Error(`Erro ao exportar chave privada: ${error}`);
    }
  }
  
  public importPrivateKey(s: string): Uint8Array {
    try {
      return base64ToUint8Array(s);
    } catch (error) {
      throw new Error(`Erro ao importar chave privada: ${error}`);
    }
  }
}

export { RSAProvider };