import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { ContractRegistryService } from '../src/contracts/contract-registry.service';

describe('ContractRegistryController (e2e)', () => {
  let app: INestApplication;
  let contractRegistryService: jest.Mocked<ContractRegistryService>;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(ContractRegistryService)
      .useValue({
        getRegistry: jest.fn().mockResolvedValue({
          etag: 'test-etag',
          contracts: {},
        }),
      })
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();

    contractRegistryService = moduleRef.get(ContractRegistryService) as any;
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /contracts/registry should return the registry', async () => {
    const response = await request(app.getHttpServer())
      .get('/contracts/registry')
      .expect(200);

    expect(response.body).toEqual({
      etag: 'test-etag',
      contracts: {},
    });
    expect(response.headers['etag']).toBe('test-etag');
  });

  it('GET /api/contracts/registry should return the registry via alias', async () => {
    const response = await request(app.getHttpServer())
      .get('/api/contracts/registry')
      .expect(200);

    expect(response.body).toEqual({
      etag: 'test-etag',
      contracts: {},
    });
    expect(response.headers['etag']).toBe('test-etag');
  });

  it('GET /api/mobile/contracts/registry should return the registry via mobile alias', async () => {
    const response = await request(app.getHttpServer())
      .get('/api/mobile/contracts/registry')
      .expect(200);

    expect(response.body).toEqual({
      etag: 'test-etag',
      contracts: {},
    });
    expect(response.headers['etag']).toBe('test-etag');
  });
});

