import type { PaymentLinkForm } from '../usePaymentLinkForm';

export function LinkCreationStep({ form }: { form: PaymentLinkForm }) {
  return (
    <section>
      <h2>Link Details</h2>
      <label>
        Link name
        <input aria-label='Link name' value={form.state.linkName} onChange={(e) => form.updateLink({ linkName: e.target.value })} />
      </label>
    </section>
  );
}
