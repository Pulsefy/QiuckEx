import { Injectable } from '@nestjs/common';
import { LinkConstraints, AssetCode, MemoType } from './constants';
import { LinkMetadataRequestDto, LinkMetadataResponseDto } from './dto';
import { LinkValidationError, LinkErrorCode } from './errors';

@Injectable()
export class LinksService {
  async generateMetadata(request: LinkMetadataRequestDto): Promise<LinkMetadataResponseDto> {
    const amt = this.validateAmount(request.amount);
    
    const { memo, memoType } = this.validateMemo(request.memo, request.memoType);
    
    const asset = this.validateAsset(request.asset);
    const privacy = request.privacy ?? false;
    const expiresAt = this.calculateExpiration(request.expirationDays);
    
    const canonical = this.generateCanonicalFormat(amt, asset, memo);
    
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
    
    return {
      amount: amt,
      memo,
      memoType,
      asset,
      privacy,
      expiresAt,
      canonical,
      metadata: {
        normalized,
        warnings: warnings.length > 0 ? warnings : undefined,
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
  
  private generateCanonicalFormat(amount: string, asset: string, memo: string | null): string {
    let canonical = `amount=${amount}&asset=${asset}`;
    if (memo) {
      canonical += `&memo=${encodeURIComponent(memo)}`;
    }
    return canonical;
  }
}
