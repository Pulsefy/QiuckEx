import fc from 'fast-check';

describe('Fuzz Setup Verification', () => {
    it('should be able to run fast-check', () => {
        fc.assert(
            fc.property(fc.integer(), (num) => {
                // A simple invariant: a number is always equal to itself
                expect(num).toBe(num);
            }),
            { numRuns: 100 }
        );
    });
});