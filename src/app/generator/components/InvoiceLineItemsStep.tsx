import type { PaymentLinkForm } from '../usePaymentLinkForm';

export function InvoiceLineItemsStep({ form }: { form: PaymentLinkForm }) {
  return (
    <section>
      <h2>Invoice Line Items</h2>
      {form.state.lineItems.map((item, index) => (
        <div key={item.id}>
          <input aria-label={`Item ${index + 1} description`} value={item.description} onChange={(e) => form.updateLineItem(item.id, { description: e.target.value })} />
          <input aria-label={`Item ${index + 1} quantity`} type='number' value={item.quantity} onChange={(e) => form.updateLineItem(item.id, { quantity: Number(e.target.value) })} />
          <input aria-label={`Item ${index + 1} rate} type='number' value={item.rate} onChange={(e) => form.updateLineItem(item.id, { rate: Number(e.target.value) })} />
          <button type='button' onClick={() => form.removeLineItem(item.id)}>Remove</button>
        </div>
      ))}
      <button type='button' onClick={form.addLineItem}>Add line item</button>
    </section>
  );
}
