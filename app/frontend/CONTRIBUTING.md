# Contributing to QuickEx Frontend

Thank you for your interest in contributing to the QuickEx frontend!

## Development Workflow

1.  **Branching**: Create a feature branch for your changes (e.g., `feat/add-wallet-connect`).
2.  **Code Style**: We use ESLint and Prettier. Run `pnpm lint` before committing.
3.  **Type Safety**: Ensure all changes pass TypeScript checks with `pnpm type-check`.
4.  **Testing**: Add unit tests for new components or logic where applicable.

## Pull Request Checklist

- [ ] Branch is up-to-date with `main`.
- [ ] No linting or type-check errors.
- [ ] All tests pass locally.
- [ ] README is updated if necessary.
- [ ] Descriptive commit messages.

## UI Guidelines

- Use **Tailwind CSS** for all styling.
- Follow the **vibrant dark theme** (neutral-950 background, indigo-500 accents).
- Ensure all interactive elements have hover and focus states.
- Maintain a **premium, clean aesthetic** with consistent spacing and typography.

## Accessibility

Payments and QR flows are how money moves, so a user relying on a screen
reader or keyboard must be able to complete them. When you touch UI code:

- Every interactive element (buttons, links, form controls) needs an
  accessible name — visible text, `aria-label`, or a `<label>` properly
  associated with its control (`htmlFor`/`id`, or nesting where the control
  is directly inside the `<label>`).
- Decorative icons/SVGs get `aria-hidden="true"`; icons that convey meaning
  on their own need an accessible label.
- Custom interactive elements (a `<div>` with `onClick`) need a real
  `role`, `tabIndex`, and keyboard handlers, or — preferably — should just
  be a `<button>`.
- Don't rely on color alone to convey state (error/success/expired); pair
  it with text or an icon.
- Preserve `focus-visible` ring styles on interactive elements; don't
  suppress the browser's default focus outline without replacing it.

**Enforcement**: `eslint-plugin-jsx-a11y` runs in CI. It's a hard error
(`--max-warnings 0`) for the QR/payment flow — `src/app/generator/**`,
`src/app/pay/**`, `src/components/payment-states/**`,
`src/components/QRPreview.tsx`, `src/components/SigningSummary.tsx` — see
`eslint.config.mjs`. It's a warning elsewhere while the rest of the app
catches up; please still fix what you touch. `__tests__/a11y-payment-flow.test.tsx`
runs a `jest-axe` audit over the same components, and
`e2e/tests/a11y-pay-flow.spec.ts` runs an `axe-core` audit against the live
generator and pay pages (gated on `PREVIEW_BASE_URL`, same as the
pay-to-receipt E2E). Run them locally with:

```bash
npx vitest run __tests__/a11y-payment-flow.test.tsx
```
