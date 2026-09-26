import {
  BadRequestException,
  INestApplication,
  ValidationPipe,
} from "@nestjs/common";
import { Test } from "@nestjs/testing";
import * as request from "supertest";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";

import { GlobalHttpExceptionFilter } from "../src/common/filters/global-http-exception.filter";
import { AppConfigService } from "../src/config";
import { AppModule } from "../src/app.module";
import { mapValidationErrors } from "../src/common/utils/validation-error.mapper";
import { ApiKeyGuard } from "../src/auth/guards/api-key.guard";
import { CustomThrottlerGuard } from "../src/auth/guards/custom-throttler.guard";

/**
 * Boot-time guard for the manifests route.
 *
 * `ManifestsModule` used to be defined but never imported into `AppModule`,
 * so `POST /manifests/diff` 404'd while the pure unit tests stayed green.
 * Booting the real `AppModule` here means any future de-registration makes
 * this suite fail instead of silently killing the API.
 */
describe("ManifestsModule wiring", () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideGuard(ApiKeyGuard)
      .useValue({ canActivate: jest.fn().mockReturnValue(true) })
      .overrideGuard(CustomThrottlerGuard)
      .useValue({ canActivate: jest.fn().mockReturnValue(true) })
      .compile();

    app = moduleRef.createNestApplication();

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

    const configService = moduleRef.get(AppConfigService);
    app.useGlobalFilters(new GlobalHttpExceptionFilter(configService));

    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it("serves POST /manifests/diff on the booted app", async () => {
    const response = await request(app.getHttpServer())
      .post("/manifests/diff")
      .send({
        baseManifest: {
          urls: { api: "https://api.testnet.internal" },
          featureFlags: { enableDisputes: true },
        },
        targetManifest: {
          urls: { api: "https://api.preview.internal" },
          featureFlags: { enableDisputes: true, newFeature: true },
        },
      })
      .expect(200);

    expect(response.body.urls.api.status).toBe("modified");
    expect(response.body.featureFlags.enableDisputes.status).toBe("unchanged");
    expect(response.body.featureFlags.newFeature.status).toBe("added");
  });

  it("returns 404 for a route that does not exist (sanity check)", async () => {
    await request(app.getHttpServer()).get("/manifests/nope").expect(404);
  });

  it("includes the manifests routes in the Swagger/OpenAPI document", () => {
    const document = SwaggerModule.createDocument(
      app,
      new DocumentBuilder().setTitle("test").build(),
    );

    expect(Object.keys(document.paths)).toContain("/manifests/diff");
  });
});
