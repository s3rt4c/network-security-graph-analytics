import React, { useState } from 'react';
import { describe, expect, it } from 'vitest';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { Modal } from '../components/common/Modal';

const ModalHarness: React.FC = () => {
  const [open, setOpen] = useState(false);

  return (
    <div>
      <button type="button" onClick={() => setOpen(true)}>
        Open Modal
      </button>
      <Modal isOpen={open} onClose={() => setOpen(false)} title="Inspect Record">
        <p>Modal content</p>
        <button type="button">Action Inside</button>
      </Modal>
    </div>
  );
};

describe('Shared Modal Accessibility', () => {
  it('labels dialog via aria-labelledby, traps focus, restores focus & body overflow across cycles', () => {
    document.body.style.overflow = 'scroll';
    const { unmount } = render(<ModalHarness />);

    // Mounting closed must not mutate existing body overflow
    expect(document.body.style.overflow).toBe('scroll');

    const trigger = screen.getByRole('button', { name: 'Open Modal' });
    trigger.focus();
    fireEvent.click(trigger);

    const dialog = screen.getByRole('dialog', { name: 'Inspect Record' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(document.body.style.overflow).toBe('hidden');
    expect(dialog.contains(document.activeElement)).toBe(true);

    const closeBtn = within(dialog).getByRole('button', { name: 'Close dialog' });
    const innerBtn = within(dialog).getByRole('button', { name: 'Action Inside' });

    // Tab forward wraps from last -> first; Shift+Tab wraps from first -> last
    innerBtn.focus();
    fireEvent.keyDown(document, { key: 'Tab' });
    expect(document.activeElement).toBe(closeBtn);

    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(innerBtn);

    // Escape closes dialog and restores previous overflow + trigger focus
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(document.body.style.overflow).toBe('scroll');
    expect(document.activeElement).toBe(trigger);

    // Second open/close cycle via close button
    fireEvent.click(trigger);
    const dialog2 = screen.getByRole('dialog', { name: 'Inspect Record' });
    fireEvent.click(within(dialog2).getByRole('button', { name: 'Close dialog' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(document.body.style.overflow).toBe('scroll');
    expect(document.activeElement).toBe(trigger);

    unmount();
    expect(document.body.style.overflow).toBe('scroll');
    document.body.style.overflow = '';
  });
});
