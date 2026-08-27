import type { PaymentLinkForm } from '../usePaymentLinkForm';

export function CustomerDetailsStep({ form }: { form: PaymentLinkForm }) {
  return (
    <section>
      <h2>Customer Details</h2>
      <input aria-label='Customer name' value={form.state.customer.name} onChange={(e) => form.updateCustomer( { name: e.target.value })} />
      <input aria-label='Customer email' value={form.state.customer.email} onChange={(e) => form.updateCustomer( { email: e.target.value })} />
    </section>
  );
}
