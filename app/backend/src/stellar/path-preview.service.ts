import {
  BadRequestException,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from "@nestjs/common";

import { AppConfigService } from "../config/app-config.service";
import {
  findVerifiedAsset,
  type VerifiedAssetRecord,
} from "./verified-assets.constant";
import type {
  PathAssetRefDto,
  PathPreviewRequestDto,
  StrictSendPathPreviewRequestDto,
} from "./dto/path-preview.dto";

type HorizonPathRecord = {
  source_asset_type: string;
  source_asset_code?: string;
  source_asset_issuer?: string;
  source_amount: string;
  destination_asset_type: string;
  destination_asset_code?: string;
  destination_asset_issuer?: string;
  destination_amount: string;
  path?: Array<{
    asset_type: string;
    asset_code?: string;
    asset_issuer?: string;
  }>;
};

type HorizonPathsResponse = {
  _embedded?: { records: HorizonPathRecord[] };
};

function toAssetStroops(amountStr: string, decimals: number): string {
  const normalized = amountStr.trim();
  const [wholePart, fracPart = ""] = normalized.split(".");
  if (!/^\d+$/.test(wholePart)) {
    throw new BadRequestException("Invalid destination amount");
  }
  if (fracPart && !/^\d+$/.test(fracPart)) {
    throw new BadRequestException("Invalid destination amount");
  }
  const paddedFrac = (fracPart + "0".repeat(decimals)).slice(0, decimals);
  const whole = BigInt(wholePart);
  const frac =
    paddedFrac.length > 0 ? BigInt(paddedFrac.padEnd(decimals, "0")) : 0n;
  const factor = BigInt(10) ** BigInt(decimals);
  return (whole * factor + frac).toString();
}

function toHorizonSourceAssetParam(asset: VerifiedAssetRecord): string {
  if (asset.type === "native") {
    return "native";
  }
  return `${asset.code}:${asset.issuer}`;
}

function horizonSourceParams(asset: VerifiedAssetRecord): Record<string, string> {
  if (asset.type === "native") {
    return { source_asset_type: "native" };
  }
  return {
    source_asset_type: asset.type,
    source_asset_code: asset.code,
    source_asset_issuer: asset.issuer ?? "",
  };
}

function horizonDestinationParams(asset: VerifiedAssetRecord): Record<string, string> {
  if (asset.type === "native") {
    return { destination_asset_type: "native" };
  }
  return {
    destination_asset_type: asset.type,
    destination_asset_code: asset.code,
    destination_asset_issuer: asset.issuer ?? "",
  };
}

function formatAssetLabel(
  type: string,
  code?: string,
  issuer?: string,
): string {
  if (type === "native") {
    return "XLM";
  }
  if (code && issuer) {
    return `${code}:${issuer.slice(0, 4)}…${issuer.slice(-4)}`;
  }
  return code ?? type;
}

@Injectable()
export class PathPreviewService {
  private readonly logger = new Logger(PathPreviewService.name);

  constructor(private readonly appConfig: AppConfigService) {}

  private resolveHorizonBaseUrl(): string {
    return this.appConfig.isMainnet
      ? "https://horizon.stellar.org"
      : "https://horizon-testnet.stellar.org";
  }

  private assertVerified(ref: PathAssetRefDto): VerifiedAssetRecord {
    const verified = findVerifiedAsset(ref.code);
    if (!verified) {
      throw new BadRequestException(`Unknown or unverified asset: ${ref.code}`);
    }
    if (verified.type === "native") {
      return verified;
    }
    const issuer = (ref.issuer ?? verified.issuer ?? "").trim();
    if (!issuer || issuer !== verified.issuer) {
      throw new BadRequestException(
        `Issuer does not match verified ${verified.code} asset`,
      );
    }
    return verified;
  }

  async previewPaths(
    body: PathPreviewRequestDto,
  ): Promise<{ paths: PathPreviewRow[]; horizonUrl: string }> {
    const destination = this.assertVerified(body.destinationAsset);
    const sources = body.sourceAssets.map((s) => this.assertVerified(s));

    const destStroops = toAssetStroops(
      body.destinationAmount,
      destination.decimals,
    );

    const source_assets = sources.map(toHorizonSourceAssetParam).join(",");
    const destParams = horizonDestinationParams(destination);

    const params = new URLSearchParams({
      source_assets,
      destination_amount: destStroops,
      ...destParams,
    });

    const base = this.resolveHorizonBaseUrl();
    const url = `${base}/paths/strict-receive?${params.toString()}`;

    let json: HorizonPathsResponse;
    try {
      const res = await fetch(url);
      if (!res.ok) {
        const text = await res.text();
        this.logger.warn(
          `Horizon strict-receive failed ${res.status}: ${text.slice(0, 500)}`,
        );
        throw new ServiceUnavailableException(
          "Unable to fetch path estimates from Horizon.",
        );
      }
      json = (await res.json()) as HorizonPathsResponse;
    } catch (err) {
      if (
        err instanceof BadRequestException ||
        err instanceof ServiceUnavailableException
      ) {
        throw err;
      }
      this.logger.error("Horizon path preview network error", err);
      throw new ServiceUnavailableException(
        "Unable to reach Stellar Horizon for path preview.",
      );
    }

    const records = json._embedded?.records ?? [];
    const paths: PathPreviewRow[] = records.map((r) => ({
      sourceAmount: r.source_amount,
      sourceAsset: formatAssetLabel(
        r.source_asset_type,
        r.source_asset_code,
        r.source_asset_issuer,
      ),
      destinationAmount: r.destination_amount,
      destinationAsset: formatAssetLabel(
        r.destination_asset_type,
        r.destination_asset_code,
        r.destination_asset_issuer,
      ),
      hopCount: Array.isArray(r.path) ? r.path.length : 0,
      pathHops: (r.path ?? []).map((hop) =>
        formatAssetLabel(hop.asset_type, hop.asset_code, hop.asset_issuer),
      ),
      /** Ratio of destination_amount : source_amount in smallest units (informative) */
      rateDescription: formatStroopsRatio(
        r.source_amount,
        r.destination_amount,
      ),
    }));

    return { paths, horizonUrl: base };
  }

  async strictSendPaths(
    body: StrictSendPathPreviewRequestDto,
  ): Promise<{ paths: PathPreviewRow[]; horizonUrl: string }> {
    const source = this.assertVerified(body.sourceAsset);
    const destinations = body.destinationAssets.map((d) =>
      this.assertVerified(d),
    );

    const srcStroops = toAssetStroops(body.sourceAmount, source.decimals);
    const srcParams = horizonSourceParams(source);
    const destination_assets = destinations
      .map(toHorizonSourceAssetParam)
      .join(",");

    const params = new URLSearchParams({
      ...srcParams,
      source_amount: srcStroops,
      destination_assets,
    });

    const base = this.resolveHorizonBaseUrl();
    const url = `${base}/paths/strict-send?${params.toString()}`;

    let json: HorizonPathsResponse;
    try {
      const res = await fetch(url);
      if (!res.ok) {
        const text = await res.text();
        this.logger.warn(
          `Horizon strict-send failed ${res.status}: ${text.slice(0, 500)}`,
        );
        throw new ServiceUnavailableException(
          "Unable to fetch path estimates from Horizon.",
        );
      }
      json = (await res.json()) as HorizonPathsResponse;
    } catch (err) {
      if (
        err instanceof BadRequestException ||
        err instanceof ServiceUnavailableException
      ) {
        throw err;
      }
      this.logger.error("Horizon strict-send path preview network error", err);
      throw new ServiceUnavailableException(
        "Unable to reach Stellar Horizon for path preview.",
      );
    }

    const records = json._embedded?.records ?? [];
    const paths: PathPreviewRow[] = records.map((r) => ({
      sourceAmount: r.source_amount,
      sourceAsset: formatAssetLabel(
        r.source_asset_type,
        r.source_asset_code,
        r.source_asset_issuer,
      ),
      destinationAmount: r.destination_amount,
      destinationAsset: formatAssetLabel(
        r.destination_asset_type,
        r.destination_asset_code,
        r.destination_asset_issuer,
      ),
      hopCount: Array.isArray(r.path) ? r.path.length : 0,
      pathHops: (r.path ?? []).map((hop) =>
        formatAssetLabel(hop.asset_type, hop.asset_code, hop.asset_issuer),
      ),
      rateDescription: formatStroopsRatio(
        r.source_amount,
        r.destination_amount,
      ),
    }));

    return { paths, horizonUrl: base };
  }
}

function formatStroopsRatio(source: string, dest: string): string {
  const src = Number(source);
  const dst = Number(dest);
  if (!src || !Number.isFinite(src) || !Number.isFinite(dst)) {
    return "—";
  }
  return `${(dst / src).toFixed(6)} (dest/source in smallest units)`;
}

export type PathPreviewRow = {
  sourceAmount: string;
  sourceAsset: string;
  destinationAmount: string;
  destinationAsset: string;
  hopCount: number;
  pathHops: string[];
  rateDescription: string;
};
