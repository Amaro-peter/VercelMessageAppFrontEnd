import saberBuilder from "@dashlane/pqc-kem-saber-browser";
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
    if (!base64 || typeof base64 !== 'string') {
      throw new Error("String Base64 inválida ou vazia");
    }
    const cleanBase64 = base64.replace(/[\s\r\n]/g, '');
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(cleanBase64)) {
      throw new Error("Formato Base64 inválido");
    }
    if (typeof atob !== "undefined") {
      const binary = atob(cleanBase64);
      const len = binary.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    }
    return Uint8Array.from(Buffer.from(cleanBase64, "base64"));
  } catch (error) {
    console.error("Erro ao converter Base64 para Uint8Array:", error);
    throw new Error(`Falha na decodificação Base64: ${error}`);
  }
}

/**
 * Secure random bytes
 */
function cryptoGetRandomBytes(n: number): Uint8Array {
  if (n <= 0) {
    throw new Error("Número de bytes deve ser positivo");
  }
  
  const gcrypto: any = (globalThis as any).crypto;
  if (gcrypto && typeof gcrypto.getRandomValues === "function") {
    const b = new Uint8Array(n);
    gcrypto.getRandomValues(b);
    return b;
  }
  try {
    const nodeCrypto = require("crypto");
    if (typeof nodeCrypto.randomBytes === "function") {
      return new Uint8Array(nodeCrypto.randomBytes(n));
    }
  } catch (_) {
    // Silently catch require error in browser environment
  }
  throw new Error("Nenhuma fonte segura de aleatoriedade disponível.");
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
}

/**
 * SABERProvider usando SABER KEM + AES-GCM
 */
class SABERProvider implements ICryptoProvider {
  private readonly AES_IV_BYTES = 12;
  private readonly ALGO_NAME = "SABER + AES-GCM";

  private Saber: Awaited<ReturnType<typeof saberBuilder>> | null = null;
  private saberInitPromise: Promise<Awaited<ReturnType<typeof saberBuilder>>> | null = null;

  private async getSaber() {
    if (!this.Saber) {
      if (!this.saberInitPromise) {
        this.saberInitPromise = saberBuilder();
      }
      this.Saber = await this.saberInitPromise;
    }
    return this.Saber;
  }

  getAlgorithmName(): string {
    return this.ALGO_NAME;
  }

  public async generateKeyPair(): Promise<KeyPair> {
    try {
      console.log(`🔑 Gerando par de chaves SABER...`);
      const saber = await this.getSaber();
      const { publicKey, privateKey } = await saber.keypair();
      
      if (!publicKey || !privateKey) {
        throw new Error("Falha ao gerar chaves: chaves inválidas retornadas");
      }
      
      return { publicKey, privateKey };
    } catch (error) {
      console.error("Erro ao gerar par de chaves SABER:", error);
      throw new Error(`Falha na geração de chaves: ${error}`);
    }
  }

  public async encrypt(message: string, recipientPublicKey: Uint8Array): Promise<EncryptedMessage> {
    try {
      const subtle = (globalThis as any).crypto?.subtle;
      if (!subtle) throw new Error("WebCrypto (crypto.subtle) não disponível.");

      if (!message || typeof message !== 'string') {
        throw new Error("Mensagem deve ser uma string não vazia");
      }
      if (!recipientPublicKey || recipientPublicKey.length === 0) {
        throw new Error("Chave pública inválida");
      }

      const saber = await this.getSaber();
      const { sharedSecret, ciphertext } = await saber.encapsulate(recipientPublicKey);

      if (!sharedSecret || !ciphertext) {
        throw new Error("Falha no encapsulamento: dados inválidos retornados");
      }

      const aesKeyRaw = await this.deriveAesKeyRaw(sharedSecret);
      const aesKey = await subtle.importKey("raw", aesKeyRaw.buffer, "AES-GCM", false, ["encrypt"]);

      const iv = cryptoGetRandomBytes(this.AES_IV_BYTES);
      const encoder = new TextEncoder();
      const encryptedBuffer = await subtle.encrypt({ name: "AES-GCM", iv }, aesKey, encoder.encode(message));
      const encryptedBytes = new Uint8Array(encryptedBuffer);

      return {
        algorithm: this.ALGO_NAME,
        timestamp: new Date().toISOString(),
        encryptedContent: uint8ArrayToBase64(encryptedBytes),
        encryptedSymmetricKey: uint8ArrayToBase64(ciphertext),
        nonce: uint8ArrayToBase64(iv),
      };
    } catch (error) {
      console.error("Erro na criptografia SABER:", error);
      throw new Error(`Falha na criptografia: ${error}`);
    }
  }

  public async decrypt(encryptedMessage: EncryptedMessage, privateKey: Uint8Array): Promise<string> {
    try {
      const subtle = (globalThis as any).crypto?.subtle;
      if (!subtle) throw new Error("WebCrypto (crypto.subtle) não disponível.");

      validateEncryptedMessage(encryptedMessage);
      if (!privateKey || privateKey.length === 0) {
        throw new Error("Chave privada inválida");
      }

      const ciphertext = base64ToUint8Array(encryptedMessage.encryptedSymmetricKey);
      const iv = base64ToUint8Array(encryptedMessage.nonce);
      const encryptedContent = base64ToUint8Array(encryptedMessage.encryptedContent);

      if (iv.length !== this.AES_IV_BYTES) {
        throw new Error(`IV deve ter ${this.AES_IV_BYTES} bytes, mas tem ${iv.length}`);
      }

      const saber = await this.getSaber();
      const { sharedSecret } = await saber.decapsulate(ciphertext, privateKey);

      if (!sharedSecret) {
        throw new Error("Falha no desencapsulamento: segredo compartilhado inválido");
      }

      const aesKeyRaw = await this.deriveAesKeyRaw(sharedSecret);
      const aesKey = await subtle.importKey("raw", aesKeyRaw.buffer, "AES-GCM", false, ["decrypt"]);

      const plainBuffer = await subtle.decrypt({ name: "AES-GCM", iv }, aesKey, encryptedContent.buffer);
      return new TextDecoder().decode(plainBuffer);
    } catch (error) {
      console.error("Erro na descriptografia SABER:", error);
      throw new Error(`Falha na descriptografia: ${error}`);
    }
  }

  public exportPublicKey(pk: Uint8Array): string {
    if (!pk || pk.length === 0) {
      throw new Error("Chave pública inválida para exportação");
    }
    return uint8ArrayToBase64(pk);
  }

  public importPublicKey(s: string): Uint8Array {
    if (!s || typeof s !== 'string') {
      throw new Error("String da chave pública inválida para importação");
    }
    return base64ToUint8Array(s);
  }

  public exportPrivateKey(sk: Uint8Array): string {
    if (!sk || sk.length === 0) {
      throw new Error("Chave privada inválida para exportação");
    }
    return uint8ArrayToBase64(sk);
  }

  public importPrivateKey(s: string): Uint8Array {
    if (!s || typeof s !== 'string') {
      throw new Error("String da chave privada inválida para importação");
    }
    return base64ToUint8Array(s);
  }

  private async deriveAesKeyRaw(sharedSecret: Uint8Array): Promise<Uint8Array> {
    const subtle = (globalThis as any).crypto?.subtle;
    if (!subtle) throw new Error("WebCrypto (crypto.subtle) não disponível.");

    if (!sharedSecret || sharedSecret.length === 0) {
      throw new Error("Segredo compartilhado inválido para derivação de chave");
    }

    if (sharedSecret.byteLength >= 32) {
      return new Uint8Array(sharedSecret.slice(0, 32));
    }
    
    const salt = new Uint8Array(16); // Use proper salt size
    const info = new TextEncoder().encode("saber-aes-key-derive");
    const baseKey = await subtle.importKey("raw", sharedSecret.buffer, "HKDF", false, ["deriveBits"]);
    const derivedBits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, baseKey, 32 * 8);
    return new Uint8Array(derivedBits);
  }
}

export { SABERProvider };