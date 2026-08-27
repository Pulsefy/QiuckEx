import { fireEvent, render, screen } from '@testing-library/react';
import { LinkCreationStep } from '../LinkCreationStep';
import { TemplateManagementStep } from '../TemplateManagementStep';
import { InvoiceLineItemsStep } from '../InvoiceLineItemsStep';
import { CustomerDetailsStep } from '../CustomerDetailsStep';
import type { PaymentLinkForm } from '../../usePaymentLinkForm';

function makeForm(overrides: any = {}): PaymentLinkForm {
  const base = {
    state: {
      linkName: '',
      linkDescription: '',
      amount: '',
      currency: 'USD',
      templateId: 'simple',
      templates: [{ id: 'simple', name: 'Simple', body: '' }],
      lineItems: [{ id: '1', description: '', quantity: 1, rate: 0 }],
      customer: { name: '', email: '', company: '', notes: '' },
    },
    updateLink: jest.fn(),
    selectTemplate: jest.fn(),
    addTemplate: jest.fn(),
    updateTemplate: jest.fn(),
    deleteTemplate: jest.fn(),
    addLineItem: jest.fn(),
    updateLineItem: jest.fn(),
    removeLineItem: jest.fn(),
    updateCustomer: jest.fn(),
  };
  return { ...base, ...overrides } as unknown as PaymentLinkForm;
}

test('LinkCreationStep updates link name', () => {
  const form = makeForm();
  render(<LinkCreationStep form={form} />);
  fireEvent.change(screen.getByLabel(/link name/i), { target: { value: 'Custom' } });
  expect(form.updateLink).toHaveBeenCalledWith({ linkName: 'Custom' });
});

test('TemplateManagementStep selects template', () => {
  const form = makeForm();
  render(<TemplateManagementStep form={form} />);
  fireEvent.change(screen.getByLabel(/template/i), { target: { value: 'simple' } });
  expect(form.selectTemplate).toHaveBeenCalledWith('simple');
});

test('InvoiceLineItemsStep removes a line item', () => {
  const form = makeForm({
    state: { ...makeForm().state, lineItems: [
      { id: '1', description: 'A', quantity: 1, rate: 10 },
      { id: '2', description: 'B', quantity: 2, rate: 20 },
    ] },
  });
  render(<InvoiceLineItemsStep form={form} />);
  const buttons = screen.getAllByRole('button', { name: /remove/i });
  fireEvent.click(buttons[0]);
  expect(form.removeLineItem).toHaveBeenCalledWith('1');
});

test('CustomerDetailsStep updates customer name', () => {
  const form = makeForm();
  render(<CustomerDetailsStep form={form} />);
  fireEvent.change(screen.getByLabel(/customer name/i), { target: { value: 'Jane' } });
  expect(form.updateCustomer).toHaveBeenCalledWith({ name: 'Jane' });
});
