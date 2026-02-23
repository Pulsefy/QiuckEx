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
    
    // Validate username if provided
    let validatedUsername: string | null = null;
    if (request.username !== undefined) {
      if (request.username !== null) {
        validatedUsername = this.validateUsername(request.username);
      }
    }
    
    // Validate destination if provided
    let validatedDestination: string | null = null;
    if (request.destination !== undefined) {
      if (request.destination !== null) {
        validatedDestination = this.validateDestination(request.destination);
      }
    }
    
    // Validate referenceId if provided
    let validatedReferenceId: string | null = null;
    if (request.referenceId !== undefined) {
      if (request.referenceId !== null) {
        validatedReferenceId = this.validateReferenceId(request.referenceId);
      }
    }
    
    const canonical = this.generateCanonicalFormat(amt, asset, memo, validatedUsername, validatedDestination, validatedReferenceId);
    
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
    
    // Normalize asset symbol
    const normalizedAsset = this.normalizeAssetSymbol(asset);
    if (normalizedAsset !== asset) {
      warnings.push(`Asset symbol '${asset}' normalized to '${normalizedAsset}'`);
      normalized = true;
    }
    
    // Derive additional metadata
    const additionalMetadata = this.deriveAdditionalMetadata(normalizedAsset, privacy, validatedUsername);
    
    return {
      amount: amt,
      memo,
      memoType,
      asset: normalizedAsset,
      privacy,
      expiresAt,
      canonical,
      username: validatedUsername,
      destination: validatedDestination,
      referenceId: validatedReferenceId,
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
    memoType?: string
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

  private validateUsername(username: string): string {
    if (!username) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_USERNAME,
        'Username cannot be empty',
        'username',
      );
    }
    
    if (!/^[a-z0-9][a-z0-9_-]{2,30}[a-z0-9]$|^[a-z0-9]{1,32}$/.test(username)) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_USERNAME,
        'Username must be 1-32 lowercase alphanumeric characters, may include hyphens and underscores, but cannot start or end with special characters',
        'username',
      );
    }
    
    // Check if username is reserved
    const reservedUsernames = ['admin', 'root', 'system', 'null', 'undefined'];
    if (reservedUsernames.includes(username.toLowerCase())) {
      throw new LinkValidationError(
        LinkErrorCode.USERNAME_RESERVED,
        'Username is reserved and cannot be used',
        'username',
      );
    }
    
    return username;
  }
  
  private validateDestination(destination: string): string {
    if (!destination) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_DESTINATION,
        'Destination cannot be empty',
        'destination',
      );
    }
    
    // Stellar public key format: starts with 'G' followed by 55 base32 characters
    if (!/^G[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{55}$/.test(destination)) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_DESTINATION,
        'Destination must be a valid Stellar public key (starts with G, 56 characters)',
        'destination',
      );
    }
    
    return destination;
  }
  
  private validateReferenceId(referenceId: string): string {
    if (!referenceId) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_REFERENCE_ID,
        'Reference ID cannot be empty',
        'referenceId',
      );
    }
    
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(referenceId)) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_REFERENCE_ID,
        'Reference ID must be 1-64 alphanumeric characters, hyphens, or underscores',
        'referenceId',
      );
    }
    
    return referenceId;
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
    
    // Whitelist validation moved to DTO level, but keeping here for business logic
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
    // Normalize asset symbols to canonical format
    const normalized: Record<string, string> = {
      'XLM': 'XLM',
      'USDC': 'USDC',
      'AQUA': 'AQUA',
      'yXLM': 'yXLM',
      // Add more mappings as needed
    };
    
    return normalized[asset] || asset;
  }

  private deriveAdditionalMetadata(asset: string, privacy: boolean, username?: string | null): Record<string, string | number | boolean> {
    // Derive additional metadata fields useful for frontend
    const metadata: Record<string, string | number | boolean> = {};
    
    // Determine asset type
    metadata.assetType = asset === 'XLM' ? 'native' : 'credit';
    
    // Determine asset issuer if not native
    if (asset !== 'XLM') {
      metadata.assetIssuer = this.getAssetIssuer(asset);
    }
    
    // Determine link type based on presence of username
    metadata.linkType = username ? 'username' : 'direct';
    
    // Determine security level based on privacy setting
    metadata.securityLevel = privacy ? 'high' : 'medium';
    
    // Add currency information
    metadata.currencySymbol = this.getCurrencySymbol(asset);
    
    // Add trustworthiness indicator
    metadata.trustScore = this.getTrustScore(asset);
    
    return metadata;
  }

  private getAssetIssuer(asset: string): string {
    // Return appropriate issuer for the asset
    const issuers: Record<string, string> = {
      'USDC': 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
      'AQUA': 'GB2I4XFQWCG3Z6PDS5VHN2RVFNHXHH56TVOLNRIRBCUHUHHRFPABXIWQ',
      'yXLM': 'GCNHFDWRYN5ISH3XFTXK5HQZDMP4WM6QOQCQ4JTJZ6Z5DBR5S2CSXHSK',
    };
    
    return issuers[asset] || 'UNKNOWN';
  }

  private getCurrencySymbol(asset: string): string {
    // Return appropriate currency symbol
    const symbols: Record<string, string> = {
      'XLM': 'â‚§',
      'USDC': '$',
      'AQUA': 'A',
      'yXLM': 'y',
    };
    
    return symbols[asset] || asset;
  }

  private getTrustScore(asset: string): number {
    // Return a trust score for the asset (0-100)
    const scores: Record<string, number> = {
      'XLM': 100,
      'USDC': 95,
      'AQUA': 85,
      'yXLM': 80,
    };
    
    return scores[asset] || 50;
  }

  private generateCanonicalFormat(
    amount: string, 
    asset: string, 
    memo: string | null,
    username?: string | null,
    destination?: string | null,
    referenceId?: string | null
  ): string {
    const params = new URLSearchParams();
    params.append('amount', amount);
    params.append('asset', asset);
    if (memo) {
      params.append('memo', memo);
    }
    if (username) {
      params.append('username', username);
    }
    if (destination) {
      params.append('destination', destination);
    }
    if (referenceId) {
      params.append('referenceId', referenceId);
    }
    
    return params.toString();
  }
}