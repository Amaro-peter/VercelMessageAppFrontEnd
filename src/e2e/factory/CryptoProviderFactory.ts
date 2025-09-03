import type { ICryptoProvider } from '../interface/ICryptoProvider';
import { CrystalKyBerMlKem1024Provider } from '../providers/CrystalKyBerMlKem1024Provider';
import { CrystalKyBerMlKem512Provider } from '../providers/CrystalKyberMlKem512Provider';
import { CrystalKybeMlKem768Provider } from '../providers/CrystalKybeMlKem768Provider';
import { SABERProvider } from '../providers/SABERProvider';

export const CryptoAlgorithm = {
  CRYSTAL_KYBER_MLKEM1024: 'crystal-kyber-1024',
  CRYSTAL_KYBER_MLKEM768: 'crystal-kyber-768',
  CRYSTAL_KYBER_MLKEM512: 'crystal-kyber-512',
  SABER: 'saber',
} as const;

export type CryptoAlgorithm = typeof CryptoAlgorithm[keyof typeof CryptoAlgorithm];

export class CryptoProviderFactory {
  private static providers: Map<CryptoAlgorithm, () => ICryptoProvider> = new Map<CryptoAlgorithm, () => ICryptoProvider>([
    [CryptoAlgorithm.CRYSTAL_KYBER_MLKEM1024, () => new CrystalKyBerMlKem1024Provider()],
    [CryptoAlgorithm.CRYSTAL_KYBER_MLKEM768, () => new CrystalKybeMlKem768Provider()],
    [CryptoAlgorithm.CRYSTAL_KYBER_MLKEM512, () => new CrystalKyBerMlKem512Provider()],
    [CryptoAlgorithm.SABER, () => new SABERProvider()],
  ]);

  static createProvider(algorithm: CryptoAlgorithm = CryptoAlgorithm.CRYSTAL_KYBER_MLKEM1024): ICryptoProvider {
    const providerFactory = this.providers.get(algorithm);
    
    if (!providerFactory) {
      throw new Error(`Provedor de criptografia não suportado: ${algorithm}`);
    }
    
    return providerFactory();
  }

  static registerProvider(algorithm: CryptoAlgorithm, factory: () => ICryptoProvider): void {
    this.providers.set(algorithm, factory);
  }

  static getAvailableAlgorithms(): CryptoAlgorithm[] {
    return Array.from(this.providers.keys());
  }

  static getAlgorithmDisplayName(algorithm: CryptoAlgorithm): string {
    const displayNames = {
      [CryptoAlgorithm.CRYSTAL_KYBER_MLKEM1024]: 'CRYSTALS-KYBER (MlKem1024)',
      [CryptoAlgorithm.CRYSTAL_KYBER_MLKEM768]: 'CRYSTALS-KYBER (MlKem768)',
      [CryptoAlgorithm.CRYSTAL_KYBER_MLKEM512]: 'CRYSTALS-KYBER (MlKem512)',
      [CryptoAlgorithm.SABER]: 'SABER',
    };
    
    return displayNames[algorithm] || algorithm;
  }
}