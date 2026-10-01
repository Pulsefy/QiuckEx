/**
 * Shared formatting utilities and public profile visibility settings manager.
 */

export class SharedFormatter {
  /**
   * Formats numbers into locale-aware currency strings.
   */
  public static formatCurrency(amount: number, currency: string = 'USD', locale: string = 'en-US'): string {
    try {
      return new Intl.NumberFormat(locale, {
        style: 'currency',
        currency,
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      }).format(amount);
    } catch {
      return `$${amount.toFixed(2)}`;
    }
  }

  /**
   * Formats dates according to standard en-US display.
   */
  public static formatDate(date: Date | number | string, locale: string = 'en-US'): string {
    const d = new Date(date);
    return new Intl.DateTimeFormat(locale, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    }).format(d);
  }
}

export interface ProfileVisibilitySettings {
  userId: string;
  isPublic: boolean;
  updatedAt: string;
}

export class ProfileVisibilityManager {
  private settingsMap = new Map<string, ProfileVisibilitySettings>();

  /**
   * Toggles public profile visibility setting.
   */
  public toggleVisibility(userId: string, isPublic: boolean): ProfileVisibilitySettings {
    const updated: ProfileVisibilitySettings = {
      userId,
      isPublic,
      updatedAt: new Date().toISOString(),
    };
    this.settingsMap.set(userId, updated);
    return updated;
  }

  public getVisibility(userId: string): boolean {
    return this.settingsMap.get(userId)?.isPublic ?? true;
  }
}
