import { Injectable } from '@nestjs/common';
import { LinkConstraints, AssetCode, MemoType } from './constants';
import { LinkMetadataRequestDto, LinkMetadataResponseDto } from './dto';

@Injectable()
export class LinksService {
  async generateMetadata(request: LinkMetadataRequestDto): Promise<LinkMetadataResponseDto> {
    const amt = this.validateAmount(request.amount);
    
    const { memo, memoType } = this.validateMemo(request.memo, request.memoType);
    
    const asset = request.asset || LinkConstraints.ASSET.DEFAULT;
    const privacy = request.privacy ?? false;
    const expiresAt = this.calculateExpiration(request.expirationDays);
    
    const canonical = this.generateCanonicalFormat(amt, asset, memo);
    
    const warnings: string[] = [];
    let normalized = false;
    
    if (this.formatAmount(request.amount) !== amt) {
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
      throw new Error('Amount must be a valid number');
    }
    
    if (amount < LinkConstraints.AMOUNT.MIN) {
      throw new Error(`Amount must be at least ${LinkConstraints.AMOUNT.MIN} XLM`);
    }
    
    if (amount > LinkConstraints.AMOUNT.MAX) {
      throw new Error(`Amount cannot exceed ${LinkConstraints.AMOUNT.MAX} XLM`);
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
    if (!memo) {
      return {
        memo: null,
        memoType: LinkConstraints.MEMO.DEFAULT_TYPE,
      };
    }
    
    let sanitized = memo.replace(/[<>"']/g, '');
    
    if (sanitized.length > LinkConstraints.MEMO.MAX_LENGTH) {
      throw new Error(`Memo cannot exceed ${LinkConstraints.MEMO.MAX_LENGTH} characters`);
    }
    
    const validatedMemoType = (memoType || LinkConstraints.MEMO.DEFAULT_TYPE) as MemoType;
    if (!LinkConstraints.MEMO.ALLOWED_TYPES.includes(validatedMemoType)) {
      throw new Error('Memo type must be one of: text, id, hash, return');
    }
    
    return {
      memo: sanitized || null,
      memoType: validatedMemoType,
    };
  }
  
  private calculateExpiration(days?: number): Date | null {
    if (!days) return null;
    
    if (days < 1 || days > LinkConstraints.LINK.MAX_EXPIRATION_DAYS) {
      throw new Error('Expiration must be between 1 and 365 days');
    }
    
    const expiration = new Date();
    expiration.setDate(expiration.getDate() + days);
    return expiration;
  }
  
  private generateCanonicalFormat(amount: string, asset: string, memo: string | null): string {
    let canonical = `amount=${amount}&asset=${asset}`;
    if (memo) {
      canonical += `&memo=${encodeURIComponent(memo)}`;
    }
    return canonical;
  }
}
