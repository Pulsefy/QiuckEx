import { SupportBundleReferenceTargetType } from './dto/support-bundle-reference.dto';

export interface SupportBundleReferenceRecord {
  id: string;
  bundleId: string;
  targetType: SupportBundleReferenceTargetType;
  targetId: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  redacted: boolean;
  redactedAt: string | null;
}
