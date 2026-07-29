import { Controller, Get, Post, Param, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiParam, ApiBody } from '@nestjs/swagger';
import { PaymentTokenService } from './payment-token.service';
import {
  PaymentTokenResponseDto,
  PaymentTokenResolveDto,
  PaymentTokenRotateDto,
  PaymentTokenRevokeResponseDto,
  PaymentTokenGenerateRequestDto,
} from '../dto/payment-token/payment-token-response.dto';

@ApiTags('Payment Tokens')
@Controller('payment-tokens')
export class PaymentTokenController {
  constructor(private readonly paymentTokenService: PaymentTokenService) {}

  @Post('generate')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Generate a short-lived payment token' })
  @ApiBody({ type: PaymentTokenGenerateRequestDto })
  async generate(
    @Body() body: PaymentTokenGenerateRequestDto,
  ): Promise<PaymentTokenResponseDto> {
    const result = await this.paymentTokenService.generateToken({
      amount: String(body.amount),
      assetCode: body.asset ?? 'XLM',
      username: body.username ?? null,
      destinationPublicKey: body.destination ?? null,
      memo: body.memo ?? null,
      memoType: body.memoType ?? 'text',
      acceptedAssets: body.acceptedAssets ?? null,
      ttlSeconds: body.ttlSeconds,
    });

    return {
      token: result.token,
      expiresAt: result.expiresAt,
      status: 'active',
      canonical: result.canonical,
    };
  }

  @Get('resolve/:token')
  @ApiOperation({ summary: 'Resolve a payment token to its payment context' })
  @ApiParam({ name: 'token', description: 'The payment token to resolve' })
  async resolve(@Param('token') token: string): Promise<PaymentTokenResolveDto> {
    const result = await this.paymentTokenService.resolveToken(token);

    return {
      paymentContext: {
        amount: result.paymentContext.amount,
        asset: result.paymentContext.asset,
        username: result.paymentContext.username,
        destination: result.paymentContext.destinationPublicKey,
        memo: result.paymentContext.memo,
        expiresAt: result.paymentContext.expiresAt,
      },
      status: result.status,
    };
  }

  @Post('consume/:token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Mark a payment token as consumed (one-time use)' })
  @ApiParam({ name: 'token', description: 'The payment token to consume' })
  async consume(@Param('token') token: string): Promise<{ success: boolean }> {
    await this.paymentTokenService.consumeToken(token);
    return { success: true };
  }

  @Post('revoke/:token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Revoke a payment token immediately' })
  @ApiParam({ name: 'token', description: 'The payment token to revoke' })
  async revoke(@Param('token') token: string): Promise<PaymentTokenRevokeResponseDto> {
    await this.paymentTokenService.revokeToken(token);
    return { success: true, token };
  }

  @Post('rotate/:token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Rotate a payment token (revoke current, issue new)' })
  @ApiParam({ name: 'token', description: 'The payment token to rotate' })
  async rotate(@Param('token') token: string): Promise<PaymentTokenRotateDto> {
    const result = await this.paymentTokenService.rotateToken(token);
    return {
      newToken: result.newToken,
      expiresAt: result.expiresAt,
      canonical: result.canonical,
    };
  }

  @Post('sweep')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Manually trigger expired token sweep' })
  async sweep(): Promise<{ expired: number }> {
    const count = await this.paymentTokenService.sweepExpiredTokens();
    return { expired: count };
  }
}
