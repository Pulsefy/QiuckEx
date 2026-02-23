import { Injectable } from '@nestjs/common';
import { LinkConstraints, AssetCode, MemoType } from './constants';
import { LinkMetadataRequestDto, LinkMetadataResponseDto } from '../dto';
import { LinkValidationError, LinkErrorCode } from './errors';

@Injectable()
export class LinksService {
  async generateMetadata(request: LinkMetadataRequestDto): Promise<LinkMetadataResponseDto> {
    const amt = this.validateAmount(request.amount);

    const { memo, memoType } = this.validateMemo(request.memo, request.memoType);

    const asset = this.validateAsset(request.asset);
    const privacy = request.privacy ?? false;
    const expiresAt = this.calculateExpiration(request.expirationDays);

    // Validate new optional fields (handles undefined/null gracefully)
    const username = this.validateUsername(request.username);
    const destination = this.validateDestination(request.destination);
    const referenceId = this.validateReferenceId(request.referenceId);

    // Normalize asset symbol to canonical form
    const normalizedAsset = this.normalizeAssetSymbol(asset);

    const canonical = this.generateCanonicalFormat(amt, normalizedAsset, memo, username, destination, referenceId);

    const warnings: string[] = [];
    let normalized = false;

    if (request.amount.toString() !== amt) {
      warnings.push('Amount was normalized to 7 decimal places');
      normalized = true;
    }

    if (memo && request.memo !== memo) {
      warnings.push('Memo was trimmed and sanitized');
      normalized = true;
    }

    if (normalizedAsset !== asset) {
      warnings.push(`Asset symbol '${asset}' normalized to '${normalizedAsset}'`);
      normalized = true;
    }

    // Additional metadata fields for frontend
    const additionalMetadata = this.deriveAdditionalMetadata(request, normalizedAsset);

    return {
      amount: amt,
      memo,
      memoType,
      asset: normalizedAsset,
      privacy,
      expiresAt,
      canonical,
      username,
      destination,
      referenceId,
      metadata: {
        normalized,
        warnings: warnings.length > 0 ? warnings : undefined,
        ...additionalMetadata,
      },
    };
  }

  private validateAmount(amount: number): string {
    if (typeof amount !== 'number' || isNaN(amount)) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_AMOUNT,
        'Amount must be a valid number',
        'amount',
      );
    }

    if (amount < LinkConstraints.AMOUNT.MIN) {
      throw new LinkValidationError(
        LinkErrorCode.AMOUNT_TOO_LOW,
        `Amount must be at least ${LinkConstraints.AMOUNT.MIN} XLM`,
        'amount',
      );
    }

    if (amount > LinkConstraints.AMOUNT.MAX) {
      throw new LinkValidationError(
        LinkErrorCode.AMOUNT_TOO_HIGH,
        `Amount cannot exceed ${LinkConstraints.AMOUNT.MAX} XLM`,
        'amount',
      );
    }

    return this.formatAmount(amount);
  }

  private formatAmount(amount: number): string {
    return amount.toFixed(LinkConstraints.AMOUNT.DECIMALS);
  }

  private validateMemo(
    memo?: string,
    memoType?: string,
  ): { memo: string | null; memoType: MemoType } {
    if (!memo || memo.trim() === '') {
      return {
        memo: null,
        memoType: LinkConstraints.MEMO.DEFAULT_TYPE,
      };
    }

    let sanitized = memo.trim();
    sanitized = sanitized.replace(/[<>"']/g, '');

    if (sanitized.length === 0) {
      return {
        memo: null,
        memoType: LinkConstraints.MEMO.DEFAULT_TYPE,
      };
    }

    if (sanitized.length > LinkConstraints.MEMO.MAX_LENGTH) {
      throw new LinkValidationError(
        LinkErrorCode.MEMO_TOO_LONG,
        `Memo cannot exceed ${LinkConstraints.MEMO.MAX_LENGTH} characters`,
        'memo',
      );
    }

    const validatedMemoType = (memoType || LinkConstraints.MEMO.DEFAULT_TYPE) as MemoType;
    if (!LinkConstraints.MEMO.ALLOWED_TYPES.includes(validatedMemoType)) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_MEMO_TYPE,
        'Memo type must be one of: text, id, hash, return',
        'memoType',
      );
    }

    return {
      memo: sanitized,
      memoType: validatedMemoType,
    };
  }

  private validateUsername(username?: string | null): string | null {
    if (!username || username.trim() === '') {
      return null;
    }

    const trimmed = username.trim().toLowerCase();

    if (trimmed.length < 3) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_USERNAME,
        'Username must be at least 3 characters long',
        'username',
      );
    }

    if (trimmed.length > 32) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_USERNAME,
        'Username cannot exceed 32 characters',
        'username',
      );
    }

    if (!/^[a-z0-9][a-z0-9_-]{0,30}[a-z0-9]$|^[a-z0-9]{1,2}$/.test(trimmed)) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_USERNAME,
        'Username must be lowercase alphanumeric characters, may include hyphens and underscores, but cannot start or end with special characters',
        'username',
      );
    }

    const reservedWords = ['admin', 'system', 'root', 'quickex', 'null', 'undefined'];
    if (reservedWords.includes(trimmed)) {
      throw new LinkValidationError(
        LinkErrorCode.USERNAME_RESERVED,
        'Username is reserved and cannot be used',
        'username',
      );
    }

    return trimmed;
  }

  private validateDestination(destination?: string | null): string | null {
    if (!destination || destination.trim() === '') {
      return null;
    }

    const trimmed = destination.trim();

    if (!/^G[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{55}$/.test(trimmed)) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_DESTINATION,
        'Destination must be a valid Stellar public key (starts with G, 56 characters)',
        'destination',
      );
    }

    return trimmed;
  }

  private validateReferenceId(referenceId?: string | null): string | null {
    if (!referenceId || referenceId.trim() === '') {
      return null;
    }

    const trimmed = referenceId.trim();

    if (trimmed.length > 64) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_REFERENCE_ID,
        'Reference ID cannot exceed 64 characters',
        'referenceId',
      );
    }

    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(trimmed)) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_REFERENCE_ID,
        'Reference ID must be 1-64 alphanumeric characters, hyphens, or underscores',
        'referenceId',
      );
    }

    return trimmed;
  }

  private calculateExpiration(days?: number): Date | null {
    if (!days) return null;

    if (days < 1 || days > LinkConstraints.LINK.MAX_EXPIRATION_DAYS) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_EXPIRATION,
        'Expiration must be between 1 and 365 days',
        'expirationDays',
      );
    }

    const expiration = new Date();
    expiration.setDate(expiration.getDate() + days);
    return expiration;
  }

  private validateAsset(asset?: string): AssetCode {
    const assetCode = (asset || LinkConstraints.ASSET.DEFAULT) as AssetCode;

    if (!LinkConstraints.ASSET.WHITELIST.includes(assetCode)) {
      throw new LinkValidationError(
        LinkErrorCode.ASSET_NOT_WHITELISTED,
        `Asset is not supported. Supported assets: ${LinkConstraints.ASSET.WHITELIST.join(', ')}`,
        'asset',
      );
    }

    return assetCode;
  }

  private normalizeAssetSymbol(asset: string): string {
    const normalized: Record<string, string> = {
      XLM: 'XLM',
      USDC: 'USDC',
      AQUA: 'AQUA',
      yXLM: 'yXLM',
    };

    return normalized[asset] || asset;
  }

  private generateCanonicalFormat(
    amount: string,
    asset: string,
    memo: string | null,
    username?: string | null,
    destination?: string | null,
    referenceId?: string | null,
  ): string {
    const params = new URLSearchParams();
    params.set('amount', amount);
    params.set('asset', asset);

    if (memo) params.set('memo', memo);
    if (username) params.set('username', username);
    if (destination) params.set('destination', destination);
    if (referenceId) params.set('ref', referenceId);

    return params.toString();
  }

  private deriveAdditionalMetadata(request: LinkMetadataRequestDto, asset: string): Record<string, unknown> {
    const metadata: Record<string, unknown> = {};

    // Asset type and issuer
    if (asset === 'XLM') {
      metadata.assetType = 'native';
      metadata.assetIssuer = null;
    } else {
      metadata.assetType = 'credit_alphanum4';
      metadata.assetIssuer = this.getAssetIssuer(asset);
    }

    // Link type classification
    if (request.privacy) {
      metadata.linkType = 'private';
    } else if (request.username) {
      metadata.linkType = 'username';
    } else {
      metadata.linkType = 'standard';
    }

    // Expiration metadata
    if (request.expirationDays) {
      metadata.expiresInDays = request.expirationDays;
      metadata.isExpiring = true;
    } else {
      metadata.isExpiring = false;
    }

    // Security level
    metadata.securityLevel = this.calculateSecurityLevel(request);

    // Currency display info
    metadata.currencySymbol = this.getCurrencySymbol(asset);
    metadata.trustScore = this.getTrustScore(asset);

    return metadata;
  }

  private getAssetIssuer(asset: string): string | null {
    const issuers: Record<string, string> = {
      USDC: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
      AQUA: 'GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA',
      yXLM: 'GARDNV3Q7YGT4AKSDF25LT32YSCCW4EV22Y2TV3I2PU2MMXJTEDL5T55',
    };

    return issuers[asset] || null;
  }

  private getCurrencySymbol(asset: string): string {
    const symbols: Record<string, string> = {
      XLM: '₳',
      USDC: '$',
      AQUA: 'A',
      yXLM: 'y',
    };

    return symbols[asset] || asset;
  }

  private getTrustScore(asset: string): number {
    const scores: Record<string, number> = {
      XLM: 100,
      USDC: 95,
      AQUA: 85,
      yXLM: 80,
    };

    return scores[asset] || 50;
  }

  private calculateSecurityLevel(request: LinkMetadataRequestDto): 'low' | 'medium' | 'high' {
    let score = 0;

    if (request.memo) score += 1;
    if (request.expirationDays) score += 1;
    if (request.privacy) score += 1;
    if (request.destination) score += 1;

    if (score >= 3) return 'high';
    if (score >= 1) return 'medium';
    return 'low';
  }
}