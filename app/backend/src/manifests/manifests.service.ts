import { Injectable } from '@nestjs/common';
import { EnvironmentManifestDto, ManifestContractDto } from './dto/manifest-diff.dto';

export type DiffStatus = 'added' | 'removed' | 'modified' | 'unchanged';

export interface DiffNode<T> {
  status: DiffStatus;
  oldValue?: T;
  newValue?: T;
}

export interface ManifestDiff {
  contracts: Record<string, DiffNode<ManifestContractDto>>;
  urls: Record<string, DiffNode<string>>;
  featureFlags: Record<string, DiffNode<boolean>>;
}

@Injectable()
export class ManifestsService {
  public diffManifests(
    base: EnvironmentManifestDto,
    target: EnvironmentManifestDto,
  ): ManifestDiff {
    return {
      contracts: this.compareRecords(
        base.contracts,
        target.contracts,
        (a, b) => a.id === b.id && a.wasmHash === b.wasmHash,
      ),
      urls: this.compareRecords(base.urls, target.urls),
      featureFlags: this.compareRecords(base.featureFlags, target.featureFlags),
    };
  }

  private compareRecords<T>(
    oldRecord: Record<string, T> = {},
    newRecord: Record<string, T> = {},
    isEqual: (a: T, b: T) => boolean = (a, b) => a === b,
  ): Record<string, DiffNode<T>> {
    const result: Record<string, DiffNode<T>> = {};
    const allKeys = new Set([...Object.keys(oldRecord), ...Object.keys(newRecord)]);

    for (const key of allKeys) {
      const hasOld = key in oldRecord;
      const hasNew = key in newRecord;
      const oldValue = oldRecord[key];
      const newValue = newRecord[key];

      if (hasOld && !hasNew) {
        result[key] = { status: 'removed', oldValue };
      } else if (!hasOld && hasNew) {
        result[key] = { status: 'added', newValue };
      } else {
        if (isEqual(oldValue, newValue)) {
          result[key] = { status: 'unchanged', oldValue, newValue };
        } else {
          result[key] = { status: 'modified', oldValue, newValue };
        }
      }
    }

    return result;
  }
}
