export declare class TSAClient {
  constructor(tsaUrl: string, options?: {
    username?: string;
    password?: string;
    timeout?: number;
    digestAlgorithm?: string;
  });
  timestampData(data: Buffer | string, algorithm?: string): Promise<Buffer>;
  timestampHash(hashBytes: Buffer, algorithm?: string): Promise<Buffer>;
}

export declare const DigestAlgorithm: {
  SHA256: 'sha256';
  SHA384: 'sha384';
  SHA512: 'sha512';
  SM3: 'sm3';
};

export declare function computeHash(data: Buffer | string, algorithm?: string): Buffer;

export declare const DIGEST_OID: Record<string, string>;
