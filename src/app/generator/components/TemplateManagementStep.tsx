import type { PaymentLinkForm } from '../usePaymentLinkForm';

export function TemplateManagementStep({ form }: { form: PaymentLinkForm }) {
  return (
    <section>
      <h2>Templates</h2>
      <select aria-label='Template' value={form.state.templateId} onChange={(e) => form.selectTemplate(e.target.value)}>
        {form.state.templates.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
      </select>
    </section>
  );
}
