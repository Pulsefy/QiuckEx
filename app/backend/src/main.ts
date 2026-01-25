import 'reflect-metadata';

import { Logger, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

import { AppModule } from './app.module';
import { AppConfigService } from './config';

async function bootstrap() {
  const logger = new Logger('Bootstrap');

  const app = await NestFactory.create(AppModule, {
    logger: ['log', 'error', 'warn', 'debug', 'verbose'],
  });

  const configService = app.get(AppConfigService);

  app.enableCors({
    origin: true,
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Swagger/OpenAPI documentation setup
  const swaggerConfig = new DocumentBuilder()
    .setTitle('QuickEx Backend')
    .setDescription(
      'QuickEx API documentation - A Stellar-based exchange platform. ' +
        `Currently connected to: ${configService.network}`,
    )
    .setVersion('v1')
    .addTag('health', 'Health check endpoints')
    .addTag('usernames', 'Username management endpoints')
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
  });

  const port = configService.port;
  await app.listen(port);

  logger.log(`Backend listening on http://localhost:${port}`);
  logger.log(`Swagger docs available at http://localhost:${port}/docs`);
  logger.log(`Network: ${configService.network}`);
}

void bootstrap();
