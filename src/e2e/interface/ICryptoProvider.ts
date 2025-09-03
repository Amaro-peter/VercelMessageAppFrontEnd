export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface EncryptedMessage {
  encryptedContent: string;
  encryptedSymmetricKey: string;
  nonce: string;
  algorithm: string;
  timestamp: string;
}

export interface ICryptoProvider {
  generateKeyPair(): Promise<KeyPair>;
  encrypt(message: string, recipientPublicKey: Uint8Array): Promise<EncryptedMessage>;
  decrypt(encryptedMessage: EncryptedMessage, privateKey: Uint8Array): Promise<string>;
  getAlgorithmName(): string;
  exportPublicKey(publicKey: Uint8Array): string;
  importPublicKey(publicKeyString: string): Uint8Array;
  exportPrivateKey(privateKey: Uint8Array): string;
  importPrivateKey(privateKeyString: string): Uint8Array;
}