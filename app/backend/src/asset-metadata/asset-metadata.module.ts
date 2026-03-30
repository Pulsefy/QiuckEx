import { Module, forwardRef } from '@nestjs/common';

import { StellarModule } from '../stellar/stellar.module';
import { ApiKeysModule } from '../api-keys/api-keys.module';
import { AssetMetadataController } from './asset-metadata.controller';
import { AssetMetadataService } from './asset-metadata.service';
import { AssetMetadataCache } from './cache/asset-metadata.cache';
import { TomlFetcherService } from './toml-fetcher.service';

@Module({
  imports: [forwardRef(() => StellarModule), ApiKeysModule],
  controllers: [AssetMetadataController],
  providers: [AssetMetadataService, AssetMetadataCache, TomlFetcherService],
  exports: [AssetMetadataService, AssetMetadataCache],
})
export class AssetMetadataModule {}
