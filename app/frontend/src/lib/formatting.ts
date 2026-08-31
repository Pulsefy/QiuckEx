export type SupportedLocale = string | undefined | null;

const DEFAULT_LOCALE = "en-US";

function getDecimalSeparator(locale: string): string {
  return (
    new Intl.NumberFormat(locale)
      .formatToParts(1.1)
      .find((part) => part.type === "decimal")?.value ?? "."
  );
}

function normalizeDecimalString(value: number | string | bigint): string {
  if (typeof value === "bigint") {
    return value.toString();
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      return "0";
    }

    return value.toLocaleString("en-US", {
      useGrouping: false,
      maximumFractionDigits: 20,
    });
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return "0";
  }

  if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
    return trimmed;
  }

  const asNumber = Number(trimmed);
  if (Number.isFinite(asNumber)) {
    return asNumber.toLocaleString("en-US", {
      useGrouping: false,
      maximumFractionDigits: 20,
    });
  }

  return "0";
}

function getSafeLocale(locale?: SupportedLocale): string {
  const candidate =
    locale ??
    (typeof navigator !== "undefined" ? navigator.language : undefined);
  if (!candidate) {
    return DEFAULT_LOCALE;
  }

  try {
    return Intl.getCanonicalLocales(candidate)[0] ?? candidate;
  } catch {
    return DEFAULT_LOCALE;
  }
}

export function formatNumber(
  value: number | string,
  locale?: SupportedLocale,
): string {
  const resolvedLocale = getSafeLocale(locale);
  const normalized = normalizeDecimalString(value);

  if (!normalized.includes(".")) {
    return new Intl.NumberFormat(resolvedLocale, { useGrouping: true }).format(
      Number(normalized),
    );
  }

  const [rawInteger, rawFraction] = normalized.split(".");
  const sign = rawInteger.startsWith("-") ? "-" : "";
  const integer = rawInteger.replace(/^-/, "") || "0";
  const groupedInteger = new Intl.NumberFormat(resolvedLocale, {
    useGrouping: true,
  }).format(Number(integer));
  const decimalSeparator = getDecimalSeparator(resolvedLocale);
  const fraction = rawFraction.replace(/0+$/, "");

  return `${sign}${groupedInteger}${fraction ? `${decimalSeparator}${fraction}` : ""}`;
}

export function formatAssetAmount(
  value: number | string,
  asset: string,
  locale?: SupportedLocale,
): string {
  const resolvedLocale = getSafeLocale(locale);
  const normalized = normalizeDecimalString(value);
  const formattedNumber = formatNumber(normalized, resolvedLocale);

  return `${formattedNumber} ${asset}`.trim();
}

export function formatCurrency(
  value: number | string,
  currency: string,
  locale?: SupportedLocale,
): string {
  const resolvedLocale = getSafeLocale(locale);
  const numericValue = typeof value === "string" ? Number(value) : value;

  return new Intl.NumberFormat(resolvedLocale, {
    style: "currency",
    currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(Number.isFinite(numericValue) ? numericValue : 0);
}

export function formatDateTime(
  value: Date | string | number,
  locale?: SupportedLocale,
): string {
  const resolvedLocale = getSafeLocale(locale);
  const date = new Date(value);

  return new Intl.DateTimeFormat(resolvedLocale, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function formatDate(
  value: Date | string | number,
  locale?: SupportedLocale,
): string {
  const resolvedLocale = getSafeLocale(locale);
  const date = new Date(value);

  return new Intl.DateTimeFormat(resolvedLocale, {
    dateStyle: "medium",
  }).format(date);
}

export function getActiveLocale(locale?: SupportedLocale): string {
  return getSafeLocale(locale);
}
