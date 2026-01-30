import { Injectable } from '@nestjs/common';

import {
  AssetInput,
  NormalizedAsset,
  assertSupportedAsset,
} from '../config/stellar.config';

@Injectable()
export class LinkService {
  validateAsset(input: AssetInput): NormalizedAsset {
    return assertSupportedAsset(input);
  }
}
