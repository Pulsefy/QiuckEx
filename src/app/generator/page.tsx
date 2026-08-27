import { usePaymentLinkForm } from './usePaymentLinkForm';
import { LinkCreationStep, TemplateManagementStep, InvoiceLineItemsStep, CustomerDetailsStep } from './components';
export default function GeneratorPage() {
  const f = usePaymentLinkForm();
  return (
    <main>
      <LinkCreationStep form={f} />
      <TemplateManagementStep form={f} />
      <InvoiceLineItemsStep form={f} />
      <CustomerDetailsStep form={f} />
    </main>
  );
}
