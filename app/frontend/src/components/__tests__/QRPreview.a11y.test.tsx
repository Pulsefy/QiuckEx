import React from 'react';
import { render } from '@testing-library/react';
import { axe } from 'vitest-axe';
import { describe, it, expect } from 'vitest';
import { QRPreview } from '../QRPreview';

describe('QRPreview Accessibility', () => {
  it('should not have any accessibility violations with value', async () => {
    const { container } = render(<QRPreview value="https://example.com" />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('should not have any accessibility violations without value', async () => {
    const { container } = render(<QRPreview />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
