import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';

import { AppModule } from './app.module';

// Environment variables are set in jest.setup.ts

describe('App endpoints', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /health returns ok', async () => {
    await request(app.getHttpServer())
      .get('/health')
      .expect(200)
      .expect({ status: 'ok' });
  });

  it('POST /username returns ok for valid payload', async () => {
    await request(app.getHttpServer())
      .post('/username')
      .send({ username: 'alice_123' })
      .expect(201)
      .expect({ ok: true });
  });

  it('POST /username returns 400 for invalid payload', async () => {
    await request(app.getHttpServer())
      .post('/username')
      .send({ username: 'A' })
      .expect(400);
  });
});
