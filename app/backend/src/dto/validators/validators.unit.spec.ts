import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';

import { IsUsername, IsStellarPublicKey, IsStellarAmount, IsStellarMemo, IsStellarAsset } from './index';
import { CreateUsernameDto } from '../username';

describe('Shared Validators', () => {
  describe('IsUsername', () => {
    class TestDto {
      @IsUsername()
      username!: string;
    }

    it('should accept valid usernames', async () => {
      const dto = plainToInstance(TestDto, { username: 'alice_123' });
      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should reject usernames with uppercase letters', async () => {
      const dto = plainToInstance(TestDto, { username: 'Alice_123' });
      const errors = await validate(dto);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].constraints).toBeDefined();
    });

    it('should reject usernames with special characters', async () => {
      const dto = plainToInstance(TestDto, { username: 'alice-123' });
      const errors = await validate(dto);
      expect(errors.length).toBeGreaterThan(0);
    });

    // Note: Length validation is handled by @Length() decorator in DTOs
    // The IsUsername validator only checks the pattern (lowercase alphanumeric + underscore)
  });

  describe('IsStellarPublicKey', () => {
    class TestDto {
      @IsStellarPublicKey()
      publicKey!: string;
    }

    it('should accept valid Stellar public keys', async () => {
      // Valid 56-character Stellar public key (G + 55 base32 chars)
      const validKey = 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWRABCDEFGHIJKL';
      const dto = plainToInstance(TestDto, {
        publicKey: validKey,
      });
      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should reject invalid public keys (wrong length)', async () => {
      const dto = plainToInstance(TestDto, {
        publicKey: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YW',
      });
      const errors = await validate(dto);
      expect(errors.length).toBeGreaterThan(0);
    });

    it('should reject public keys that do not start with G', async () => {
      const dto = plainToInstance(TestDto, {
        publicKey: 'ABXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
      });
      const errors = await validate(dto);
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe('IsStellarAmount', () => {
    class TestDto {
      @IsStellarAmount()
      amount!: number;
    }

    it('should accept valid amounts within range', async () => {
      const dto = plainToInstance(TestDto, { amount: 100.5 });
      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should accept minimum amount', async () => {
      const dto = plainToInstance(TestDto, { amount: 0.0000001 });
      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should accept maximum amount', async () => {
      const dto = plainToInstance(TestDto, { amount: 1000000 });
      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should reject amounts below minimum', async () => {
      const dto = plainToInstance(TestDto, { amount: 0.00000001 });
      const errors = await validate(dto);
      expect(errors.length).toBeGreaterThan(0);
    });

    it('should reject amounts above maximum', async () => {
      const dto = plainToInstance(TestDto, { amount: 2000000 });
      const errors = await validate(dto);
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe('IsStellarMemo', () => {
    class TestDto {
      @IsStellarMemo()
      memo!: string;
    }

    it('should accept valid memos within length limit', async () => {
      const dto = plainToInstance(TestDto, { memo: 'Payment for service' });
      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should accept memo at maximum length', async () => {
      const dto = plainToInstance(TestDto, { memo: 'A'.repeat(28) });
      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should reject memos exceeding length limit', async () => {
      const dto = plainToInstance(TestDto, { memo: 'A'.repeat(29) });
      const errors = await validate(dto);
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe('IsStellarAsset', () => {
    class TestDto {
      @IsStellarAsset()
      asset!: string;
    }

    it('should accept whitelisted assets', async () => {
      const validAssets = ['XLM', 'USDC', 'AQUA', 'yXLM'];
      for (const asset of validAssets) {
        const dto = plainToInstance(TestDto, { asset });
        const errors = await validate(dto);
        expect(errors).toHaveLength(0);
      }
    });

    it('should reject non-whitelisted assets', async () => {
      const dto = plainToInstance(TestDto, { asset: 'BTC' });
      const errors = await validate(dto);
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe('CreateUsernameDto integration', () => {
    it('should validate complete CreateUsernameDto', async () => {
      // Valid 56-character Stellar public key (G + 55 base32 chars)
      const validKey = 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWRABCDEFGHIJKL';
      const dto = plainToInstance(CreateUsernameDto, {
        username: 'alice_123',
        publicKey: validKey,
      });
      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should reject CreateUsernameDto with invalid username', async () => {
      const dto = plainToInstance(CreateUsernameDto, {
        username: 'Alice-123',
        publicKey: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
      });
      const errors = await validate(dto);
      expect(errors.length).toBeGreaterThan(0);
    });

    it('should reject CreateUsernameDto with invalid public key', async () => {
      const dto = plainToInstance(CreateUsernameDto, {
        username: 'alice_123',
        publicKey: 'INVALID_KEY_TOO_SHORT',
      });
      const errors = await validate(dto);
      expect(errors.length).toBeGreaterThan(0);
    });
  });
});
