// CrystalKybeMlKem768Provider.ts
// Implementação Kyber (crystals-kyber-js) MlKem768 + AES-GCM (WebCrypto) — Hybrid Encryption (KEM + AEAD).
// Requer: npm install crystals-kyber-js
//
// Notas de segurança:
// - Kyber MlKem768 é um KEM com tamanho de chave intermediário entre MlKem512 e MlKem1024
// - Usamos encap/decap para obter shared secret (DEK) e AES-GCM para cifrar dados.
// - Não armazene privateKey em local inseguro.
// - Certifique-se de ter WebCrypto disponível: globalThis.crypto.subtle (Node: set globalThis.crypto = require('node:crypto').webcrypto)

import { MlKem768 } from "crystals-kyber-js";
import type { EncryptedMessage, ICryptoProvider, KeyPair } from "../interface/ICryptoProvider";

/**
 * Converters base64 <-> Uint8Array - MELHORADOS
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
 * Secure random bytes (browser or node)
 */
function cryptoGetRandomBytes(n: number): Uint8Array {
  // browser or Node with globalThis.crypto.getRandomValues
  const gcrypto: any = (globalThis as any).crypto;
  if (gcrypto && typeof gcrypto.getRandomValues === "function") {
    const b = new Uint8Array(n);
    gcrypto.getRandomValues(b);
    return b;
  }

  // Node fallback: require('crypto').randomBytes
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
 * CrystalKyberProvider usando MlKem768 de crystals-kyber-js
 */
class CrystalKybeMlKem768Provider implements ICryptoProvider {
  private readonly kem = new MlKem768(); // usa Kyber-768
  private readonly AES_IV_BYTES = 12; // AES-GCM nonce
  private readonly ALGO_NAME = "CRYSTALS-KYBER (MlKem768) + AES-GCM";

  constructor() {}

  getAlgorithmName(): string {
    return this.ALGO_NAME;
  }

  /**
   * Gera par de chaves Kyber (pk, sk) como Uint8Array
   */
  public async generateKeyPair(): Promise<KeyPair> {
    try {
      // generateKeyPair() retorna [pk, sk] conforme docs.
      const [pk, sk] = await this.kem.generateKeyPair();
      // garantir Uint8Array
      const pub = pk instanceof Uint8Array ? pk : new Uint8Array(pk as ArrayBuffer);
      const priv = sk instanceof Uint8Array ? sk : new Uint8Array(sk as ArrayBuffer);
      
      console.log(`🔑 Kyber MlKem768 KeyPair gerado - PK: ${pub.length} bytes, SK: ${priv.length} bytes`);
      
      return { publicKey: pub, privateKey: priv };
    } catch (error) {
      console.error("Erro ao gerar par de chaves Kyber MlKem768:", error);
      throw new Error(`Falha na geração de chaves: ${error}`);
    }
  }

  /**
   * Encrypt: encap(publicKey) -> [ct, sharedSecret]; derivar AES key -> AES-GCM encrypt(message)
   * Retorna EncryptedMessage (tipagem assumida em ICryptoProvider)
   */
  public async encrypt(message: string, recipientPublicKey: Uint8Array): Promise<EncryptedMessage> {
    try {
      const subtle = (globalThis as any).crypto?.subtle;
      if (!subtle) {
        throw new Error("WebCrypto (crypto.subtle) não disponível no runtime. Em Node: globalThis.crypto = require('node:crypto').webcrypto");
      }

      // Validar entradas
      if (!message || typeof message !== 'string') {
        throw new Error("Mensagem deve ser uma string não vazia");
      }
      
      if (!recipientPublicKey || recipientPublicKey.length === 0) {
        throw new Error("Chave pública do destinatário inválida");
      }

      console.log(`🔒 Iniciando criptografia Kyber MlKem768 - Mensagem: ${message.length} chars, PK: ${recipientPublicKey.length} bytes`);

      // encap: retorna [ct, sharedSecret]
      const [ct, shared] = await this.kem.encap(recipientPublicKey);
      const ciphertextKEM = ct instanceof Uint8Array ? ct : new Uint8Array(ct as ArrayBuffer);
      const sharedSecret = shared instanceof Uint8Array ? shared : new Uint8Array(shared as ArrayBuffer);

      console.log(`🔐 Kyber MlKem768 encap concluído - CT: ${ciphertextKEM.length} bytes, Shared: ${sharedSecret.length} bytes`);

      // Derivar/obter chave AES-256 (32 bytes) a partir do sharedSecret
      const aesKeyRaw = await this.deriveAesKeyRaw(sharedSecret); // Uint8Array(32)

      // Import raw key to WebCrypto
      const cryptoKey = await subtle.importKey("raw", aesKeyRaw.buffer, "AES-GCM", false, ["encrypt"]);

      // Encrypt plaintext
      const iv = cryptoGetRandomBytes(this.AES_IV_BYTES);
      const encoder = new TextEncoder();
      const plaintext = encoder.encode(message);

      const encryptedBuffer = await subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, plaintext);
      const encryptedBytes = new Uint8Array(encryptedBuffer);

      console.log(`🔐 AES-GCM encrypt concluído - Encrypted: ${encryptedBytes.length} bytes, IV: ${iv.length} bytes`);

      const result: EncryptedMessage = {
        algorithm: this.ALGO_NAME,
        timestamp: new Date().toISOString(),
        encryptedContent: uint8ArrayToBase64(encryptedBytes),
        encryptedSymmetricKey: uint8ArrayToBase64(ciphertextKEM),
        nonce: uint8ArrayToBase64(iv),
      };

      console.log(`✅ Criptografia MlKem768 concluída com sucesso`);
      return result;
      
    } catch (error) {
      console.error("Erro na criptografia Kyber MlKem768:", error);
      throw new Error(`Falha na criptografia: ${error}`);
    }
  }

  /**
   * Decrypt: decap(kemCiphertext, sk) -> sharedSecret -> derive AES key -> AES-GCM decrypt
   */
  public async decrypt(encryptedMessage: EncryptedMessage, privateKey: Uint8Array): Promise<string> {
    try {
      const subtle = (globalThis as any).crypto?.subtle;
      if (!subtle) {
        throw new Error("WebCrypto (crypto.subtle) não disponível no runtime. Em Node: globalThis.crypto = require('node:crypto').webcrypto");
      }

      // Validar entrada
      validateEncryptedMessage(encryptedMessage);
      
      if (!privateKey || privateKey.length === 0) {
        throw new Error("Chave privada inválida");
      }

      console.log(`🔓 Iniciando descriptografia Kyber MlKem768 - Algorithm: ${encryptedMessage.algorithm}`);

      // Decodificar dados Base64 com validação
      const kemCiphertext = base64ToUint8Array(encryptedMessage.encryptedSymmetricKey);
      const iv = base64ToUint8Array(encryptedMessage.nonce);
      const cipherBytes = base64ToUint8Array(encryptedMessage.encryptedContent);

      console.log(`🔐 Dados decodificados - KEM CT: ${kemCiphertext.length} bytes, IV: ${iv.length} bytes, Cipher: ${cipherBytes.length} bytes`);

      // decap returns sharedSecret
      const shared = await this.kem.decap(kemCiphertext, privateKey);
      const sharedSecret = shared instanceof Uint8Array ? shared : new Uint8Array(shared as ArrayBuffer);

      console.log(`🔐 Kyber MlKem768 decap concluído - Shared secret: ${sharedSecret.length} bytes`);

      const aesKeyRaw = await this.deriveAesKeyRaw(sharedSecret); // Uint8Array(32)
      const cryptoKey = await subtle.importKey("raw", aesKeyRaw.buffer, "AES-GCM", false, ["decrypt"]);

      let plainBuffer: ArrayBuffer;
      try {
        plainBuffer = await subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, cipherBytes);
      } catch (e) {
        console.error("Erro no AES-GCM decrypt:", e);
        throw new Error("Falha ao descriptografar: integridade inválida ou chave incorreta.");
      }

      const decoder = new TextDecoder();
      const result = decoder.decode(plainBuffer);
      
      console.log(`✅ Descriptografia MlKem768 concluída com sucesso - Mensagem: ${result.length} chars`);
      return result;
      
    } catch (error) {
      console.error("Erro na descriptografia Kyber MlKem768:", error);
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

  // -------------------------
  // Helpers
  // -------------------------

  /**
   * Deriva 32 bytes (AES-256) a partir do shared secret do KEM.
   * - Se sharedSecret >= 32 bytes: truncamos (sharedSecret.slice(0,32))
   * - Se <32 bytes: usamos HKDF-SHA-256 (via WebCrypto) para derivar 32 bytes.
   */
  private async deriveAesKeyRaw(sharedSecret: Uint8Array): Promise<Uint8Array> {
    try {
      const subtle = (globalThis as any).crypto?.subtle;
      if (!subtle) {
        throw new Error("WebCrypto (crypto.subtle) não disponível no runtime.");
      }

      if (sharedSecret.byteLength >= 32) {
        return new Uint8Array(sharedSecret.slice(0, 32));
      }

      // HKDF-SHA256 derive 32 bytes
      const salt = new Uint8Array([]); // opcional: usar contexto/salt real
      const info = new TextEncoder().encode("crystals-kyber-aes-key-derive");
      const baseKey = await subtle.importKey("raw", sharedSecret.buffer, "HKDF", false, ["deriveBits"]);
      const derivedBits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, baseKey, 32 * 8);
      return new Uint8Array(derivedBits);
    } catch (error) {
      console.error("Erro na derivação de chave AES:", error);
      throw new Error(`Falha na derivação de chave: ${error}`);
    }
  }
}

export { CrystalKybeMlKem768Provider };