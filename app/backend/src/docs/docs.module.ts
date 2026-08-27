import { Module } from "@nestjs/common";
import { DocsController } from "./docs.controller";

/**
 * Provides the POST /docs/json endpoint that exports the validated OpenAPI
 * specification (used by the CI spec-divergence check).
 */
@Module({
  controllers: [DocsController],
})
export class DocsModule {}
