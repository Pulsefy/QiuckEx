import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';

import { Network, stellarConfig } from '../config/stellar.config';

@Injectable()
export class HorizonService {
  constructor(
    @Inject(stellarConfig.KEY)
    private readonly config: ConfigType<typeof stellarConfig>,
  ) {}

  getNetwork(): Network {
    return this.config.network;
  }

  getBaseUrl(): string {
    return this.config.horizonBaseUrl;
  }
}
