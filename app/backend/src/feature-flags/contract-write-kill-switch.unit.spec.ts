import { GUARDS_METADATA } from '@nestjs/common/constants';

import { StellarController } from '../stellar/stellar.controller';
import { TransactionsController } from '../transactions/transactions.controller';
import { NetworkSafetyGuard } from './network-safety.guard';
import { REQUIRES_FLAG_KEY } from './requires-flag.decorator';
import { TESTNET_CONTRACT_WRITES_FLAG } from './contract-write-kill-switch.constants';

function handlerMetadata(controller: object, methodName: string) {
  const descriptor = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(controller),
    methodName,
  );

  if (!descriptor?.value) {
    throw new Error(`Missing handler ${methodName}`);
  }

  return {
    flag: Reflect.getMetadata(REQUIRES_FLAG_KEY, descriptor.value),
    guards: Reflect.getMetadata(GUARDS_METADATA, descriptor.value) ?? [],
  };
}

describe('contract write kill switch route coverage', () => {
  const transactionController = Object.create(TransactionsController.prototype);
  const stellarController = Object.create(StellarController.prototype);

  it.each([
    { controller: transactionController, methodName: 'compose' },
    { controller: transactionController, methodName: 'buildUnsignedXdr' },
    { controller: stellarController, methodName: 'sorobanPreflight' },
  ])('guards $methodName with the testnet contract-write flag', ({ controller, methodName }) => {
    const metadata = handlerMetadata(controller, methodName);

    expect(metadata.flag).toBe(TESTNET_CONTRACT_WRITES_FLAG);
    expect(metadata.guards).toContain(NetworkSafetyGuard);
  });

  it.each([
    { controller: transactionController, methodName: 'getTransactions' },
    { controller: stellarController, methodName: 'getVerifiedAssets' },
    { controller: stellarController, methodName: 'pathPreview' },
    { controller: stellarController, methodName: 'strictSendPathPreview' },
    { controller: stellarController, methodName: 'createQuote' },
    { controller: stellarController, methodName: 'getQuote' },
  ])('leaves read-only route $methodName outside the write kill switch', ({ controller, methodName }) => {
    const metadata = handlerMetadata(controller, methodName);

    expect(metadata.flag).toBeUndefined();
    expect(metadata.guards).not.toContain(NetworkSafetyGuard);
  });
});
