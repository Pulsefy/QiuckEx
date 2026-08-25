import { Test, TestingModule } from "@nestjs/testing";
import {
  BadRequestException,
  INestApplication,
  ValidationPipe,
} from "@nestjs/common";
import { EventEmitterModule } from "@nestjs/event-emitter";
import { ThrottlerModule } from "@nestjs/throttler";
import * as request from "supertest";
import { LinksModule } from "../src/links/links.module";
import { LinksService } from "../src/links/links.service";
import { mapValidationErrors } from "../src/common/utils/validation-error.mapper";
import { AppConfigService } from "../src/config";
import { GlobalHttpExceptionFilter } from "../src/common/filters/global-http-exception.filter";

const KEY_HEADER = "Idempotency-Key";

describe("Idempotency keys (BE-109, e2e)", () => {
  let app: INestApplication;
  let generateMetadataSpy: jest.SpyInstance;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        EventEmitterModule.forRoot(),
        ThrottlerModule.forRoot([
          {
            ttl: 60000,
            limit: 20,
          },
        ]),
        LinksModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        exceptionFactory: (errors) => {
          const mapped = mapValidationErrors(errors);

          return new BadRequestException({
            code: "VALIDATION_ERROR",
            message: mapped.message,
            fields: mapped.fields,
          });
        },
      }),
    );

    app.useGlobalFilters(
      new GlobalHttpExceptionFilter({
        isProduction: false,
      } as AppConfigService),
    );
    await app.init();

    const linksService = app.get(LinksService);
    generateMetadataSpy = jest.spyOn(linksService, "generateMetadata");
  });

  afterEach(async () => {
    if (app) {
      await app.close();
    }
  });

  describe("POST /links/metadata with Idempotency-Key", () => {
    const payload = { amount: 100, memo: "Idem", asset: "XLM" };

    it("replays the original response without re-executing on retry", async () => {
      const first = await request(app.getHttpServer())
        .post("/links/metadata")
        .set(KEY_HEADER, "e2e-key-1")
        .send(payload)
        .expect(200);
      expect(first.body.success).toBe(true);
      expect(generateMetadataSpy).toHaveBeenCalledTimes(1);

      const replay = await request(app.getHttpServer())
        .post("/links/metadata")
        .set(KEY_HEADER, "e2e-key-1")
        .send(payload)
        .expect(200);

      // Identical response body, but the handler ran only once.
      expect(replay.body).toEqual(first.body);
      expect(generateMetadataSpy).toHaveBeenCalledTimes(1);
    });

    it("rejects the same key used with a different body (409)", async () => {
      await request(app.getHttpServer())
        .post("/links/metadata")
        .set(KEY_HEADER, "e2e-conflict-1")
        .send(payload)
        .expect(200);

      const conflict = await request(app.getHttpServer())
        .post("/links/metadata")
        .set(KEY_HEADER, "e2e-conflict-1")
        .send({ amount: 999, memo: "Different", asset: "XLM" })
        .expect(409);

      expect(conflict.body.error?.code).toBe("IDEMPOTENCY_KEY_REUSED");
      // The conflicting request never reached the handler.
      expect(generateMetadataSpy).toHaveBeenCalledTimes(1);
    });

    it("treats requests without a key as ordinary mutations", async () => {
      await request(app.getHttpServer())
        .post("/links/metadata")
        .send(payload)
        .expect(200);
      await request(app.getHttpServer())
        .post("/links/metadata")
        .send(payload)
        .expect(200);
      // No key — both executions are expected.
      expect(generateMetadataSpy).toHaveBeenCalledTimes(2);
    });

    it("rejects an empty Idempotency-Key header with 400", async () => {
      const res = await request(app.getHttpServer())
        .post("/links/metadata")
        .set(KEY_HEADER, "   ")
        .send(payload)
        .expect(400);
      expect(res.body.error?.code).toBe("IDEMPOTENCY_KEY_INVALID");
    });
  });
});
