import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { randomBytes } from 'crypto';
import { SupabaseService } from '../supabase/supabase.service';

const TOKEN_PREFIX = 'qt_';
const TOKEN_BYTE_LENGTH = 24;
const DEFAULT_TTL_SECONDS = 86400;
const MAX_TTL_SECONDS = 604800;

interface TokenRow {
  token: string;
  link_id: string | null;
  owner_public_key: string | null;
  destination_public_key: string | null;
  amount: string;
  asset_code: string;
  asset_issuer: string | null;
  memo: string | null;
  memo_type: string | null;
  username: string | null;
  accepted_assets: string[] | null;
  status: string;
  created_at: string;
  expires_at: string;
  consumed_at: string | null;
  revoked_at: string | null;
  rotated_to: string | null;
}

@Injectable()
export class PaymentTokenService {
  private readonly logger = new Logger(PaymentTokenService.name);

  constructor(
    private readonly supabaseService: SupabaseService,
  ) {}

  generateTokenValue(): string {
    const bytes = randomBytes(TOKEN_BYTE_LENGTH);
    const base62 = bytes
      .reduce((acc, b) => acc + 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[b % 62], '');
    return `${TOKEN_PREFIX}${base62}`;
  }

  async generateToken(params: {
    amount: string;
    assetCode?: string;
    assetIssuer?: string | null;
    memo?: string | null;
    memoType?: string | null;
    username?: string | null;
    destinationPublicKey?: string | null;
    ownerPublicKey?: string | null;
    linkId?: string | null;
    acceptedAssets?: string[] | null;
    ttlSeconds?: number;
  }): Promise<{
    token: string;
    expiresAt: string;
    canonical: string;
  }> {
    const token = this.generateTokenValue();
    const ttl = Math.min(
      params.ttlSeconds ?? DEFAULT_TTL_SECONDS,
      MAX_TTL_SECONDS,
    );
    const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();

    const canonicalParams = new URLSearchParams();
    canonicalParams.set('token', token);
    const canonical = canonicalParams.toString();

    const { error } = await this.supabaseService.getClient()
      .from('payment_link_tokens')
      .insert({
        token,
        link_id: params.linkId ?? null,
        owner_public_key: params.ownerPublicKey ?? null,
        destination_public_key: params.destinationPublicKey ?? null,
        amount: params.amount,
        asset_code: params.assetCode ?? 'XLM',
        asset_issuer: params.assetIssuer ?? null,
        memo: params.memo ?? null,
        memo_type: params.memoType ?? 'text',
        username: params.username ?? null,
        accepted_assets: params.acceptedAssets ?? null,
        status: 'active',
        expires_at: expiresAt,
      });

    if (error) {
      this.logger.error('Failed to create payment token');
      throw new BadRequestException('Failed to generate payment token');
    }

    return { token, expiresAt, canonical };
  }

  async resolveToken(token: string): Promise<{
    paymentContext: {
      amount: string;
      asset: string;
      username: string | null;
      destinationPublicKey: string | null;
      memo: string | null;
      expiresAt: string | null;
    };
    status: string;
  }> {
    const tokenPattern = `${TOKEN_PREFIX}%`;
    if (!token.startsWith(TOKEN_PREFIX) || token.length < 16) {
      throw new NotFoundException('Invalid token format');
    }

    const { data, error } = await this.supabaseService.getClient()
      .from('payment_link_tokens')
      .select('*')
      .eq('token', token)
      .single();

    if (error || !data) {
      throw new NotFoundException('Payment token not found');
    }

    const row = data as unknown as TokenRow;

    if (row.status === 'revoked') {
      return {
        paymentContext: {
          amount: row.amount,
          asset: row.asset_code,
          username: row.username,
          destinationPublicKey: row.destination_public_key,
          memo: row.memo,
          expiresAt: row.expires_at,
        },
        status: 'revoked',
      };
    }

    if (row.status === 'consumed') {
      return {
        paymentContext: {
          amount: row.amount,
          asset: row.asset_code,
          username: row.username,
          destinationPublicKey: row.destination_public_key,
          memo: row.memo,
          expiresAt: row.expires_at,
        },
        status: 'consumed',
      };
    }

    if (row.status === 'expired' || new Date(row.expires_at) < new Date()) {
      if (row.status === 'active') {
        await this.expireToken(token);
      }
      return {
        paymentContext: {
          amount: row.amount,
          asset: row.asset_code,
          username: row.username,
          destinationPublicKey: row.destination_public_key,
          memo: row.memo,
          expiresAt: row.expires_at,
        },
        status: 'expired',
      };
    }

    return {
      paymentContext: {
        amount: row.amount,
        asset: row.asset_code,
        username: row.username,
        destinationPublicKey: row.destination_public_key,
        memo: row.memo,
        expiresAt: row.expires_at,
      },
      status: 'active',
    };
  }

  async consumeToken(token: string): Promise<void> {
    const { error } = await this.supabaseService.getClient()
      .from('payment_link_tokens')
      .update({
        status: 'consumed',
        consumed_at: new Date().toISOString(),
      })
      .eq('token', token)
      .eq('status', 'active');

    if (error) {
      this.logger.error('Failed to consume payment token');
    }
  }

  async revokeToken(token: string): Promise<void> {
    const { data: existing } = await this.supabaseService.getClient()
      .from('payment_link_tokens')
      .select('status')
      .eq('token', token)
      .single();

    if (!existing) {
      throw new NotFoundException('Token not found');
    }
    if (existing.status !== 'active') {
      throw new BadRequestException(`Token is already ${existing.status}`);
    }

    const { error } = await this.supabaseService.getClient()
      .from('payment_link_tokens')
      .update({
        status: 'revoked',
        revoked_at: new Date().toISOString(),
      })
      .eq('token', token);

    if (error) {
      this.logger.error('Failed to revoke payment token');
      throw new BadRequestException('Failed to revoke token');
    }
  }

  async rotateToken(currentToken: string): Promise<{
    newToken: string;
    expiresAt: string;
    canonical: string;
  }> {
    const { data: existing, error: fetchError } = await this.supabaseService.getClient()
      .from('payment_link_tokens')
      .select('*')
      .eq('token', currentToken)
      .single();

    if (fetchError || !existing) {
      throw new NotFoundException('Token not found');
    }

    const row = existing as unknown as TokenRow;
    if (row.status !== 'active') {
      throw new BadRequestException(`Cannot rotate token: status is ${row.status}`);
    }

    const newToken = this.generateTokenValue();
    const ttl = Math.max(
      1,
      Math.floor((new Date(row.expires_at).getTime() - Date.now()) / 1000),
    );
    const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();

    const { error: insertError } = await this.supabaseService.getClient()
      .from('payment_link_tokens')
      .insert({
        token: newToken,
        link_id: row.link_id,
        owner_public_key: row.owner_public_key,
        destination_public_key: row.destination_public_key,
        amount: row.amount,
        asset_code: row.asset_code,
        asset_issuer: row.asset_issuer,
        memo: row.memo,
        memo_type: row.memo_type,
        username: row.username,
        accepted_assets: row.accepted_assets,
        status: 'active',
        expires_at: expiresAt,
      });

    if (insertError) {
      this.logger.error('Failed to create rotated token');
      throw new BadRequestException('Failed to rotate token');
    }

    await this.supabaseService.getClient()
      .from('payment_link_tokens')
      .update({
        status: 'revoked',
        revoked_at: new Date().toISOString(),
        rotated_to: newToken,
      })
      .eq('token', currentToken);

    const canonicalParams = new URLSearchParams();
    canonicalParams.set('token', newToken);
    const canonical = canonicalParams.toString();

    return { newToken, expiresAt, canonical };
  }

  async sweepExpiredTokens(): Promise<number> {
    const { data, error } = await this.supabaseService.getClient()
      .from('payment_link_tokens')
      .update({ status: 'expired' })
      .eq('status', 'active')
      .lt('expires_at', new Date().toISOString())
      .select('token');

    if (error) {
      this.logger.error('Failed to sweep expired tokens');
      return 0;
    }

    const count = (data ?? []).length;
    if (count > 0) {
      this.logger.log(`Expired ${count} payment token(s)`);
    }
    return count;
  }

  private async expireToken(token: string): Promise<void> {
    await this.supabaseService.getClient()
      .from('payment_link_tokens')
      .update({ status: 'expired' })
      .eq('token', token);
  }
}
