import { SetMetadata } from "@nestjs/common";

export const REQUIRE_INDEXER_LAG_CHECK_KEY = "REQUIRE_INDEXER_LAG_CHECK";
export const RequiresIndexerLagCheck = () =>
  SetMetadata(REQUIRE_INDEXER_LAG_CHECK_KEY, true);
