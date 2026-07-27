import { createHash } from 'crypto';
import { execFileSync } from 'child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import * as path from 'path';

interface Args {
  network: 'testnet' | 'mainnet';
  source: string;
  admin?: string;
  wasm: string;
  contractName: string;
  dryRun: boolean;
  registryUrl?: string;
  apiKey?: string;
}

function parseArgs(argv: string[]): Args {
  const map = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) {
      map.set(key, 'true');
    } else {
      map.set(key, next);
      index += 1;
    }
  }

  const network = (map.get('network') ?? 'testnet') as 'testnet' | 'mainnet';
  const source = map.get('source');
  const wasm = map.get('wasm') ?? 'app/contract/target/wasm32-unknown-unknown/release/quickex.wasm';
  const contractName = map.get('contract-name') ?? 'quickex';
  if (!source) {
    throw new Error('--source is required');
  }

  return {
    network,
    source,
    admin: map.get('admin'),
    wasm,
    contractName,
    dryRun: map.get('dry-run') === 'true',
    registryUrl: map.get('registry-url'),
    apiKey: map.get('api-key'),
  };
}

function run(command: string, args: string[], dryRun: boolean): string {
  if (dryRun) return [command, ...args].join(' ');
  return execFileSync(command, args, { encoding: 'utf8' }).trim();
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const wasmPath = path.resolve(args.wasm);
  if (!existsSync(wasmPath)) {
    throw new Error(`WASM file not found at ${wasmPath}`);
  }

  const networkPassphrase =
    args.network === 'mainnet'
      ? 'Public Global Stellar Network ; September 2015'
      : 'Test SDF Network ; September 2015';
  const wasmHash = createHash('sha256').update(readFileSync(wasmPath)).digest('hex');
  const installCommand = ['contract', 'install', '--network', args.network, '--source', args.source, '--wasm', wasmPath];
  const deployCommand = ['contract', 'deploy', '--network', args.network, '--source', args.source, '--wasm-hash', wasmHash];

  const installResult = run('soroban', installCommand, args.dryRun);
  const contractId = run('soroban', deployCommand, args.dryRun) || '<contract-id>';

  let initResult: string | null = null;
  if (args.admin) {
    initResult = run(
      'soroban',
      ['contract', 'invoke', '--network', args.network, '--source', args.source, '--id', contractId, '--', 'initialize', args.admin],
      args.dryRun,
    );
  }

  const artifact = {
    deployedAt: new Date().toISOString(),
    network: args.network,
    networkPassphrase,
    contractName: args.contractName,
    contractId,
    wasmHash,
    installResult,
    initResult,
  };

  const outputDir = path.resolve('app/backend/deployments');
  mkdirSync(outputDir, { recursive: true });
  const artifactPath = path.join(outputDir, `${args.network}-${args.contractName}.json`);
  writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));

  if (args.registryUrl) {
    const response = await fetch(`${args.registryUrl.replace(/\/$/, '')}/contracts/registry/publish`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(args.apiKey ? { 'X-API-Key': args.apiKey } : {}),
      },
      body: JSON.stringify({
        networkPassphrase,
        deploymentId: `${args.network}-${args.contractName}-${Date.now()}`,
        contracts: [
          {
            name: args.contractName,
            contractId,
            wasmHash,
            contractVersion: 1,
            metadata: {
              artifactPath,
              dryRun: args.dryRun,
            },
          },
        ],
      }),
    });

    if (!response.ok) {
      throw new Error(`Registry publish failed with status ${response.status}`);
    }
  }

  process.stdout.write(`${JSON.stringify({ artifactPath, artifact }, null, 2)}\n`);
}

void main();
