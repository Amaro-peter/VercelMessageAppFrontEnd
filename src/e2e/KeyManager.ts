import type { ICryptoProvider, KeyPair } from './interface/ICryptoProvider';
import { CryptoProviderFactory, CryptoAlgorithm } from './factory/CryptoProviderFactory';

interface StoredKeyPair {
  publicKey: string;
  privateKey: string;
  algorithm: string;
  createdAt: string;
  userId: string;
}

export class KeyManager {
  private static readonly STORAGE_KEY_PREFIX = 'e2e_keys_';
  private cryptoProvider: ICryptoProvider;

  constructor(algorithm: CryptoAlgorithm = CryptoAlgorithm.CRYSTAL_KYBER_MLKEM512) {
    this.cryptoProvider = CryptoProviderFactory.createProvider(algorithm);
  }

  async generateAndStoreKeyPair(userId: string): Promise<KeyPair> {
    try {
      const keyPair = await this.cryptoProvider.generateKeyPair();
      
      const storedKeyPair: StoredKeyPair = {
        publicKey: this.cryptoProvider.exportPublicKey(keyPair.publicKey),
        privateKey: this.cryptoProvider.exportPrivateKey(keyPair.privateKey),
        algorithm: this.cryptoProvider.getAlgorithmName(),
        createdAt: new Date().toISOString(),
        userId
      };

      const storageKey = this.getStorageKey(userId);
      localStorage.setItem(storageKey, JSON.stringify(storedKeyPair));

      return keyPair;
    } catch (error) {
      throw new Error(`Falha ao gerar e armazenar chaves: ${error instanceof Error ? error.message : 'Erro desconhecido'}`);
    }
  }

  getStoredKeyPair(userId: string): KeyPair | null {
    try {
      const storageKey = this.getStorageKey(userId);
      const storedData = localStorage.getItem(storageKey);
      
      if (!storedData) {
        return null;
      }

      const parsed: StoredKeyPair = JSON.parse(storedData);
      
      return {
        publicKey: this.cryptoProvider.importPublicKey(parsed.publicKey),
        privateKey: this.cryptoProvider.importPrivateKey(parsed.privateKey)
      };
    } catch (error) {
      console.error('Erro ao recuperar chaves do storage:', error);
      return null;
    }
  }

  async ensureKeyPair(userId: string): Promise<KeyPair> {
    let keyPair = this.getStoredKeyPair(userId);
    
    if (!keyPair) {
      keyPair = await this.generateAndStoreKeyPair(userId);
    }
    
    return keyPair;
  }

  getPublicKeyForUser(userId: string): Uint8Array | null {
    const keyPair = this.getStoredKeyPair(userId);
    return keyPair ? keyPair.publicKey : null;
  }

  exportPublicKey(userId: string): string | null {
    const publicKey = this.getPublicKeyForUser(userId);
    return publicKey ? this.cryptoProvider.exportPublicKey(publicKey) : null;
  }

  clearKeys(userId: string): void {
    const storageKey = this.getStorageKey(userId);
    localStorage.removeItem(storageKey);
  }

  private getStorageKey(userId: string): string {
    return `${KeyManager.STORAGE_KEY_PREFIX}${userId}`;
  }
}