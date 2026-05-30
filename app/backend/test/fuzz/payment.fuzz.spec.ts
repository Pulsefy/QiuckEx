import fc from 'fast-check';
import { Test, TestingModule } from '@nestjs/testing';
import { PaymentService } from '../src/payments/payment.service';
import { PaymentRepository } from '../src/payments/payment.repository';

// ─── 1. Pure Model (Reference Implementation) ────────────────────────────
// This is the "source of truth" for how the state machine SHOULD behave.

enum PaymentState {
    Created = 'Created',
    Funded = 'Funded',
    Fulfilled = 'Fulfilled',
    Refunded = 'Refunded',
    Disputed = 'Disputed',
}

class PaymentModel {
    payments: Map<string, { state: PaymentState; creator: string; merchant: string }> = new Map();
    usedNonces: Set<string> = new Set();

    createPayment(id: string, creator: string, merchant: string, nonce: string): boolean {
        if (this.usedNonces.has(nonce)) return false; // INV-07: Nonce uniqueness
        this.payments.set(id, { state: PaymentState.Created, creator, merchant });
        this.usedNonces.add(nonce);
        return true;
    }

    fundPayment(id: string): boolean {
        const p = this.payments.get(id);
        if (!p || p.state !== PaymentState.Created) return false; // INV-05
        p.state = PaymentState.Funded;
        return true;
    }

    fulfillPayment(id: string, caller: string): boolean {
        const p = this.payments.get(id);
        if (!p || p.state !== PaymentState.Funded) return false; // INV-05
        if (caller !== p.merchant) return false; // INV-08: Unauthorized
        p.state = PaymentState.Fulfilled;
        return true;
    }

    refundPayment(id: string, caller: string): boolean {
        const p = this.payments.get(id);
        if (!p || p.state !== PaymentState.Funded) return false;
        if (caller !== p.creator) return false; // INV-08: Unauthorized
        p.state = PaymentState.Refunded;
        return true;
    }
}

// ─── 2. Commands (Stateful Fuzzing Actions) ──────────────────────────────
// Each command tries to do something to BOTH the Model and the Real NestJS Service.

const USERS = ['alice', 'bob', 'carol'];

class CreatePaymentCommand implements fc.Command<PaymentModel, PaymentService> {
    constructor(readonly creator: string, readonly merchant: string, readonly nonce: string) {}

    check(): boolean { return true; }

    async run(m: PaymentModel, real: PaymentService): Promise<void> {
        const id = `payment_${this.nonce}`; // Simplified ID generation

        const modelSuccess = m.createPayment(id, this.creator, this.merchant, this.nonce);

        try {
            // Call your ACTUAL NestJS service method
            const result = await real.createPayment({
                creator: this.creator,
                merchant: this.merchant,
                nonce: this.nonce,
                amount: '100', // simplified for fuzzing logic
            });

            // INV-07 & INV-05: Model and Real must agree on success/failure
            expect(result.success).toBe(modelSuccess);
        } catch (e) {
            // If the real service throws, the model must have failed too
            expect(modelSuccess).toBe(false);
        }
    }

    toString(): string { return `Create(${this.creator}, ${this.merchant}, nonce=${this.nonce})`; }
}

class FulfillPaymentCommand implements fc.Command<PaymentModel, PaymentService> {
    constructor(readonly caller: string, readonly nonce: string) {}

    check(m: Readonly<PaymentModel>): boolean {
        return m.payments.has(`payment_${this.nonce}`);
    }

    async run(m: PaymentModel, real: PaymentService): Promise<void> {
        const id = `payment_${this.nonce}`;
        const modelSuccess = m.fulfillPayment(id, this.caller);

        try {
            const result = await real.fulfillPayment(this.caller, id);
            expect(result.success).toBe(modelSuccess);
        } catch (e) {
            expect(modelSuccess).toBe(false);
        }
    }

    toString(): string { return `Fulfill(${this.caller}, nonce=${this.nonce})`; }
}

// ... You would add RefundCommand, DisputeCommand similarly ...

// ─── 3. The NestJS Test Suite ────────────────────────────────────────────

describe('Payment State Machine Fuzzing', () => {
    let service: PaymentService;

    beforeAll(async () => {
        // Set up the NestJS testing module just like you do in unit tests
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                PaymentService,
                {
                    provide: PaymentRepository,
                    useValue: {
                        // Mock your DB methods here so the fuzzer runs purely in memory
                        save: jest.fn(),
                        findOne: jest.fn(),
                    },
                },
            ],
        }).compile();

        service = module.get<PaymentService>(PaymentService);
    });

    it('should satisfy all invariants across random command sequences', async () => {
        const arbCommands = fc.commands([
            fc.record({
                creator: fc.constantFrom(...USERS),
                merchant: fc.constantFrom(...USERS),
                nonce: fc.string({ minLength: 1, maxLength: 5 }),
            }).map(r => new CreatePaymentCommand(r.creator, r.merchant, r.nonce)),

            fc.record({
                caller: fc.constantFrom(...USERS),
                nonce: fc.string({ minLength: 1, maxLength: 5 }),
            }).map(r => new FulfillPaymentCommand(r.caller, r.nonce)),

            // Add other commands here
        ]);

        // Run the stateful test
        await fc.assert(
            fc.asyncProperty(arbCommands, async (commands) => {
                const m = new PaymentModel();

                for (const cmd of commands) {
                    if (cmd.check(m)) {
                        await cmd.run(m, service);
                        // Invariant checks run after EVERY command
                    }
                }
            }),
            {
                numRuns: 1000, // Run 1000 random sequences in CI
                verbose: true,  // Print the sequence if it fails so you can debug
            }
        );
    });
});