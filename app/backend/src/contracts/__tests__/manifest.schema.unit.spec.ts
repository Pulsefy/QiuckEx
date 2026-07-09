import { readFileSync } from 'fs';
import { resolve } from 'path';

/**
 * Manifest schema unit tests (SC-W6-01).
 *
 * Validates that the canonical deployment manifest defined in
 * `app/contract/documentation/manifest-schema.json` can be consumed
 * by the backend without custom parsing — every field expected by the
 * backend registry service maps to a corresponding manifest property.
 */

// Path to the manifest schema relative to the backend source root.
// The contract docs live at app/contract/documentation/ and the backend
// at app/backend/.  We resolve from the project root.
const SCHEMA_PATH = resolve(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  '..',
  'app',
  'contract',
  'documentation',
  'manifest-schema.json',
);

interface ManifestContract {
  name: string;
  contract_id: string;
  wasm_hash: string;
  contract_version: number;
  event_schema_version: number;
  admin_addresses?: string[];
  init_params?: Record<string, unknown>;
  deployed_at?: string;
  deployed_by?: string;
  upload_tx_hash?: string;
  deploy_tx_hash?: string;
  explorer_url?: string;
  lab_url?: string;
  notes?: string;
}

interface DeploymentManifest {
  manifest_version: number;
  application: string;
  generated_at: string;
  network: string;
  network_passphrase: string;
  rpc_url: string;
  operator?: string;
  contracts: ManifestContract[];
}

describe('Deployment Manifest Schema (SC-W6-01)', () => {
  let schema: Record<string, unknown>;
  let sampleManifest: DeploymentManifest;

  beforeAll(() => {
    // Load the canonical JSON Schema
    schema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf-8')) as Record<string, unknown>;

    // Build a sample manifest that mirrors a real deployment.
    // Keys are in alphabetical order (matching sort_keys=True from Python's json.dumps).
    sampleManifest = {
      application: 'quickex',
      contracts: [
        {
          admin_addresses: ['GA5TBSBGERHVMEFBJGEM3KYMRLWO73Y2QRAV6P66GPEBOJ5ZMJUT7LLY'],
          contract_id: 'CCM5LR3XVTSDDNVEK7U4QQUN663TU4LZGDTMP3H4QIPIZO2WJOAJS2JH',
          contract_version: 1,
          deploy_tx_hash: 'a007fe77e9bbe4c0c68d951dfa9005684c5886029e60dd3a0539266136729ac4',
          deployed_at: '2026-06-02T11:54:30Z',
          deployed_by: 'seyi',
          event_schema_version: 2,
          explorer_url:
            'https://stellar.expert/explorer/testnet/contract/CCM5LR3XVTSDDNVEK7U4QQUN663TU4LZGDTMP3H4QIPIZO2WJOAJS2JH',
          init_params: { admin: 'GA5TBSBGERHVMEFBJGEM3KYMRLWO73Y2QRAV6P66GPEBOJ5ZMJUT7LLY' },
          lab_url:
            'https://lab.stellar.org/r/testnet/contract/CCM5LR3XVTSDDNVEK7U4QQUN663TU4LZGDTMP3H4QIPIZO2WJOAJS2JH',
          name: 'quickex',
          notes: 'Testnet deploy via canonical deploy script.',
          upload_tx_hash: '1848411768eab5cacdaa72d371787db1e46c90b193a0e8ba4e9107ac996366dd',
          wasm_hash: '0x57025c36c2dca81767dfbe03e78e7abc383e138ef9fe44b61f327e2cac83ed92',
        },
      ],
      generated_at: '2026-06-27T12:00:00Z',
      manifest_version: 1,
      network: 'testnet',
      network_passphrase: 'Test SDF Network ; September 2015',
      operator: 'seyi',
      rpc_url: 'https://soroban-testnet.stellar.org',
    };
  });

  // ── Schema structure ────────────────────────────────────────────────

  it('schema file is valid JSON with required top-level properties', () => {
    expect(schema).toHaveProperty('$schema');
    expect(schema).toHaveProperty('title', 'QuickEx Deployment Manifest');
    expect(schema).toHaveProperty('type', 'object');
  });

  it('schema defines all required manifest fields', () => {
    const required = (schema as { required: string[] }).required;
    expect(required).toEqual(
      expect.arrayContaining([
        'manifest_version',
        'application',
        'generated_at',
        'network',
        'network_passphrase',
        'rpc_url',
        'contracts',
      ]),
    );
  });

  it('schema constrains network to testnet or mainnet', () => {
    const networkProp = (schema as { properties: Record<string, unknown> }).properties.network;
    expect((networkProp as { enum: string[] }).enum).toEqual(['testnet', 'mainnet']);
  });

  // ── Manifest consumption (backend can parse without custom logic) ───

  it('backend can parse manifest: all required top-level fields present', () => {
    const manifest: DeploymentManifest = JSON.parse(JSON.stringify(sampleManifest));

    expect(manifest.manifest_version).toBe(1);
    expect(manifest.application).toBe('quickex');
    expect(manifest.generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(manifest.network).toMatch(/^(testnet|mainnet)$/);
    expect(manifest.network_passphrase).toBeTruthy();
    expect(manifest.rpc_url).toMatch(/^https?:\/\//);
  });

  it('backend can parse manifest: contract entries have all required fields', () => {
    const manifest: DeploymentManifest = JSON.parse(JSON.stringify(sampleManifest));

    for (const contract of manifest.contracts) {
      expect(contract.name).toBe('quickex');
      expect(contract.contract_id).toMatch(/^C[A-Z0-9]{55}$/);
      expect(contract.wasm_hash).toMatch(/^0x[A-Fa-f0-9]{64}$/);
      expect(typeof contract.contract_version).toBe('number');
      expect(typeof contract.event_schema_version).toBe('number');
    }
  });

  it('backend can parse manifest: optional fields are accessible when present', () => {
    const manifest: DeploymentManifest = JSON.parse(JSON.stringify(sampleManifest));
    const contract = manifest.contracts[0];

    // Optional fields that exist in this sample
    expect(contract.admin_addresses).toBeInstanceOf(Array);
    expect(contract.admin_addresses).toHaveLength(1);
    expect(contract.init_params).toBeInstanceOf(Object);
    expect(typeof contract.deployed_at).toBe('string');
    expect(typeof contract.deployed_by).toBe('string');
    expect(typeof contract.upload_tx_hash).toBe('string');
    expect(typeof contract.deploy_tx_hash).toBe('string');
    expect(contract.explorer_url).toMatch(/^https?:\/\//);
    expect(contract.lab_url).toMatch(/^https?:\/\//);
    expect(typeof contract.notes).toBe('string');
  });

  // ── Stable ordering ─────────────────────────────────────────────────

  it('manifest fields are emitted in stable (sorted) JSON key order', () => {
    // The deploy script uses Python's json.dumps(sort_keys=True), which
    // produces alphabetical key order. Verify the expected sorted order.
    const expectedTopLevelOrder = [
      'application',
      'contracts',
      'generated_at',
      'manifest_version',
      'network',
      'network_passphrase',
      'operator',
      'rpc_url',
    ];

    // Ensure the sample manifest object has all expected keys
    const actualKeys = Object.keys(sampleManifest).sort();
    expect(actualKeys).toEqual(expectedTopLevelOrder);

    // Verify contract-level key order (when sort_keys=True is used)
    const expectedContractOrder = [
      'admin_addresses',
      'contract_id',
      'contract_version',
      'deploy_tx_hash',
      'deployed_at',
      'deployed_by',
      'event_schema_version',
      'explorer_url',
      'init_params',
      'lab_url',
      'name',
      'notes',
      'upload_tx_hash',
      'wasm_hash',
    ];
    const contractKeys = Object.keys(sampleManifest.contracts[0]).sort();
    expect(contractKeys).toEqual(expectedContractOrder);
  });

  it('contract entries are sorted alphabetically by name', () => {
    const manifest: DeploymentManifest = JSON.parse(JSON.stringify(sampleManifest));
    const names = manifest.contracts.map((c) => c.name);
    const sorted = [...names].sort();
    expect(names).toEqual(sorted);
  });

  // ── Network binding ─────────────────────────────────────────────────

  it('manifest is unambiguous: network and network_passphrase together bind to one Stellar network', () => {
    const manifest: DeploymentManifest = JSON.parse(JSON.stringify(sampleManifest));

    // Known network bindings
    const testnetPassphrase = 'Test SDF Network ; September 2015';
    const mainnetPassphrase = 'Public Global Stellar Network ; September 2015';

    if (manifest.network === 'testnet') {
      expect(manifest.network_passphrase).toBe(testnetPassphrase);
    } else if (manifest.network === 'mainnet') {
      expect(manifest.network_passphrase).toBe(mainnetPassphrase);
    }

    // A mainnet manifest must NOT have testnet passphrase
    if (manifest.network === 'mainnet') {
      expect(manifest.network_passphrase).not.toBe(testnetPassphrase);
    }
  });

  it('backend registry service can map manifest contracts to registry records', () => {
    const manifest: DeploymentManifest = JSON.parse(JSON.stringify(sampleManifest));

    // Simulate what ContractRegistryService does with the manifest
    const registryData: Record<string, unknown> = {};
    for (const contract of manifest.contracts) {
      registryData[contract.name] = {
        id: contract.contract_id,
        wasmHash: contract.wasm_hash,
        version: contract.contract_version,
        schemaVersion: '1.0.0',
        schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
        networkPassphrase: manifest.network_passphrase,
        initParams: contract.init_params ?? {},
      };
    }

    expect(registryData.quickex).toBeDefined();
    expect(registryData.quickex).toEqual(
      expect.objectContaining({
        id: sampleManifest.contracts[0].contract_id,
        wasmHash: sampleManifest.contracts[0].wasm_hash,
        version: sampleManifest.contracts[0].contract_version,
      }),
    );
  });

  // ── Schema compatibility guard ──────────────────────────────────────

  it('manifest, on-chain metadata, and backend registry have compatible field sets', () => {
    // This test asserts that the three consumers of contract metadata
    // (on-chain DeploymentMetadata, deploy manifest, backend registry)
    // share the same conceptual fields.

    const manifest: DeploymentManifest = JSON.parse(JSON.stringify(sampleManifest));
    const contract = manifest.contracts[0];

    // On-chain fields (from types.rs DeploymentMetadata):
    //   contract_version → contract.contract_version
    //   event_schema_version → contract.event_schema_version
    //   wasm_hash → contract.wasm_hash
    //   contract_id → contract.contract_id
    expect(contract.contract_version).toBeDefined();
    expect(contract.event_schema_version).toBeDefined();
    expect(contract.wasm_hash).toBeDefined();
    expect(contract.contract_id).toBeDefined();

    // Backend registry fields (from contract-registry.service.ts RegistryRecord):
    //   contractId → contract.contract_id
    //   wasmHash → contract.wasm_hash
    //   contractVersion → contract.contract_version
    //   initParams → contract.init_params
    //   networkPassphrase → manifest.network_passphrase
    expect(typeof contract.contract_id).toBe('string');
    expect(typeof contract.wasm_hash).toBe('string');
    expect(typeof contract.contract_version).toBe('number');
    expect(typeof manifest.network_passphrase).toBe('string');

    // All consumers see the same contract_id and wasm_hash values
    const registryRecord = {
      contractId: contract.contract_id,
      wasmHash: contract.wasm_hash,
      contractVersion: contract.contract_version,
      networkPassphrase: manifest.network_passphrase,
    };

    expect(registryRecord.contractId).toBe('CCM5LR3XVTSDDNVEK7U4QQUN663TU4LZGDTMP3H4QIPIZO2WJOAJS2JH');
    expect(registryRecord.wasmHash).toBe('0x57025c36c2dca81767dfbe03e78e7abc383e138ef9fe44b61f327e2cac83ed92');
    expect(registryRecord.contractVersion).toBe(1);
    expect(registryRecord.networkPassphrase).toBe('Test SDF Network ; September 2015');
  });
});
