export class LinkMetadataResponseDto {
  amount: string;
  memo: string | null;
  memoType: string;
  asset: string;
  privacy: boolean;
  expiresAt: Date | null;
  canonical: string;
  metadata: {
    normalized: boolean;
    warnings?: string[];
  };
}
