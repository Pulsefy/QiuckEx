import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { LinksModule } from '../links.module';

describe('LinksController (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [LinksModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true }));
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  describe('POST /links/metadata', () => {
    it('should return 200 with valid metadata', () => {
      return request(app.getHttpServer())
        .post('/links/metadata')
        .send({
          amount: 100,
          memo: 'Test',
          asset: 'XLM',
        })
        .expect(200)
        .expect((res) => {
          expect(res.body.success).toBe(true);
          expect(res.body.data).toHaveProperty('amount');
          expect(res.body.data).toHaveProperty('canonical');
          expect(res.body.data.amount).toBe('100.0000000');
        });
    });

    it('should return 400 for invalid amount', () => {
      return request(app.getHttpServer())
        .post('/links/metadata')
        .send({
          amount: -10,
        })
        .expect(400);
    });

    it('should return 400 for long memo', () => {
      return request(app.getHttpServer())
        .post('/links/metadata')
        .send({
          amount: 10,
          memo: 'This is definitely way too long for a Stellar memo',
        })
        .expect(400)
        .expect((res) => {
          expect(res.body.success).toBe(false);
        });
    });

    it('should return 400 for non-whitelisted asset', () => {
      return request(app.getHttpServer())
        .post('/links/metadata')
        .send({
          amount: 10,
          asset: 'SCAM',
        })
        .expect(400)
        .expect((res) => {
          expect(res.body.success).toBe(false);
          expect(res.body.error.code).toBe('ASSET_NOT_WHITELISTED');
        });
    });

    it('should handle privacy flag', () => {
      return request(app.getHttpServer())
        .post('/links/metadata')
        .send({
          amount: 50,
          privacy: true,
        })
        .expect(200)
        .expect((res) => {
          expect(res.body.data.privacy).toBe(true);
        });
    });

    it('should calculate expiration date', () => {
      return request(app.getHttpServer())
        .post('/links/metadata')
        .send({
          amount: 50,
          expirationDays: 30,
        })
        .expect(200)
        .expect((res) => {
          expect(res.body.data.expiresAt).toBeDefined();
        });
    });

    it('should reject invalid DTO validation', () => {
      return request(app.getHttpServer())
        .post('/links/metadata')
        .send({
          amount: 'not a number',
        })
        .expect(400);
    });
  });
});
