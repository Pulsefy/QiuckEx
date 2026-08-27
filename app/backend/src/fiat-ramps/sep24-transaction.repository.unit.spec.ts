/**
 * Sep24TransactionRepository – Unit Tests
 *
 * Verifies:
 *  - parseAnchorStatus correctly maps known / unknown strings
 *  - toInternalStatus correctly maps each terminal and in-flight anchor status
 */

import {
  Sep24AnchorStatus,
  Sep24InternalStatus,
} from './types/sep24.types';
import { Sep24TransactionRepository } from './sep24-transaction.repository';

describe('Sep24TransactionRepository (static helpers)', () => {
  // ── parseAnchorStatus ──────────────────────────────────────────────────────

  describe('parseAnchorStatus', () => {
    it.each([
      ['completed', Sep24AnchorStatus.Completed],
      ['pending_user_transfer_start', Sep24AnchorStatus.PendingUserTransferStart],
      ['pending_anchor', Sep24AnchorStatus.PendingAnchor],
      ['pending_external', Sep24AnchorStatus.PendingExternal],
      ['error', Sep24AnchorStatus.Error],
      ['anchor_error', Sep24AnchorStatus.AnchorError],
      ['refunded', Sep24AnchorStatus.Refunded],
      ['expired', Sep24AnchorStatus.Expired],
    ])('parses "%s" correctly', (raw, expected) => {
      expect(Sep24TransactionRepository.parseAnchorStatus(raw)).toBe(expected);
    });

    it('returns Unknown for unrecognised status strings', () => {
      expect(Sep24TransactionRepository.parseAnchorStatus('custom_anchor_status')).toBe(
        Sep24AnchorStatus.Unknown,
      );
    });

    it('returns Unknown for null input', () => {
      expect(Sep24TransactionRepository.parseAnchorStatus(null)).toBe(Sep24AnchorStatus.Unknown);
    });

    it('returns Unknown for undefined input', () => {
      expect(Sep24TransactionRepository.parseAnchorStatus(undefined)).toBe(
        Sep24AnchorStatus.Unknown,
      );
    });
  });

  // ── toInternalStatus ──────────────────────────────────────────────────────

  describe('toInternalStatus', () => {
    it('maps Completed → Completed', () => {
      expect(Sep24TransactionRepository.toInternalStatus(Sep24AnchorStatus.Completed)).toBe(
        Sep24InternalStatus.Completed,
      );
    });

    it('maps Refunded → Refunded', () => {
      expect(Sep24TransactionRepository.toInternalStatus(Sep24AnchorStatus.Refunded)).toBe(
        Sep24InternalStatus.Refunded,
      );
    });

    it('maps Expired → Expired', () => {
      expect(Sep24TransactionRepository.toInternalStatus(Sep24AnchorStatus.Expired)).toBe(
        Sep24InternalStatus.Expired,
      );
    });

    it('maps Error → Failed', () => {
      expect(Sep24TransactionRepository.toInternalStatus(Sep24AnchorStatus.Error)).toBe(
        Sep24InternalStatus.Failed,
      );
    });

    it('maps AnchorError → Failed', () => {
      expect(Sep24TransactionRepository.toInternalStatus(Sep24AnchorStatus.AnchorError)).toBe(
        Sep24InternalStatus.Failed,
      );
    });

    it.each([
      Sep24AnchorStatus.PendingAnchor,
      Sep24AnchorStatus.PendingExternal,
      Sep24AnchorStatus.PendingUserTransferStart,
      Sep24AnchorStatus.PendingTrust,
      Sep24AnchorStatus.PendingUser,
      Sep24AnchorStatus.PendingReceivingAnchor,
      Sep24AnchorStatus.IncompleteInfo,
      Sep24AnchorStatus.Unknown,
    ])('maps in-flight/unknown anchor status "%s" → Pending', (anchorStatus) => {
      expect(Sep24TransactionRepository.toInternalStatus(anchorStatus)).toBe(
        Sep24InternalStatus.Pending,
      );
    });
  });
});
