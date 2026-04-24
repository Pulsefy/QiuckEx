export type NotificationCategory = "payments" | "escrows" | "system";
export type NotificationReadState = "all" | "unread" | "read";

export type StoredNotification = {
  id: string;
  category: NotificationCategory;
  title: string;
  description: string;
  href: string;
  actionLabel: string;
  createdAt: string;
  readAt: string | null;
};

export const NOTIFICATION_STORAGE_KEY = "quickex.notification-center.v2";

export const CATEGORY_LABELS: Record<NotificationCategory, string> = {
  payments: "Payments",
  escrows: "Escrows",
  system: "System",
};

export const CATEGORY_STYLES: Record<NotificationCategory, string> = {
  payments:
    "border-emerald-400/20 bg-emerald-400/10 text-emerald-100",
  escrows: "border-indigo-400/20 bg-indigo-400/10 text-indigo-100",
  system: "border-amber-400/20 bg-amber-400/10 text-amber-100",
};

export const INITIAL_NOTIFICATIONS: StoredNotification[] = [
  {
    id: "payment-milestone",
    category: "payments",
    title: "Payment received for Project milestone #1",
    description:
      "Alex Nova sent 50.00 USDC. Review the transaction and extend storage if you still need the record.",
    href: "/dashboard?panel=activity&tx=GD2P...5H2W",
    actionLabel: "Open transaction",
    createdAt: "2026-04-23T09:24:00.000Z",
    readAt: null,
  },
  {
    id: "payment-renewal",
    category: "payments",
    title: "Subscription renewal settled",
    description:
      "A 20.00 USDC renewal cleared successfully. The linked transaction is ready for cleanup.",
    href: "/dashboard?panel=activity&tx=GC8T...9Q0M",
    actionLabel: "Review settlement",
    createdAt: "2026-04-23T06:45:00.000Z",
    readAt: null,
  },
  {
    id: "escrow-outbid",
    category: "escrows",
    title: "You were outbid on @nova",
    description:
      "A higher offer just landed. Jump back into your active bids before the auction closes.",
    href: "/dashboard?panel=bids&bid=nova",
    actionLabel: "Open bid",
    createdAt: "2026-04-23T08:10:00.000Z",
    readAt: null,
  },
  {
    id: "escrow-winning",
    category: "escrows",
    title: "You are still winning @lux",
    description:
      "Your latest bid is holding the top spot. Keep an eye on the auction timer and watcher activity.",
    href: "/dashboard?panel=bids&bid=lux",
    actionLabel: "View auction",
    createdAt: "2026-04-22T18:15:00.000Z",
    readAt: "2026-04-22T19:00:00.000Z",
  },
  {
    id: "escrow-new-bid",
    category: "escrows",
    title: "New bid placed on @stellardev",
    description:
      "A new bidder pushed your listing higher. Review the updated listing activity before the close.",
    href: "/dashboard?panel=listings&listing=stellardev",
    actionLabel: "Open listing",
    createdAt: "2026-04-22T11:00:00.000Z",
    readAt: null,
  },
  {
    id: "system-webhooks",
    category: "system",
    title: "Webhook retries recovered",
    description:
      "Delivery errors cleared after the last retry. Double-check the developer dashboard if you want to rotate secrets.",
    href: "/settings/developer",
    actionLabel: "Open developer settings",
    createdAt: "2026-04-21T15:00:00.000Z",
    readAt: "2026-04-21T15:20:00.000Z",
  },
];

export function sortNotifications(
  notifications: StoredNotification[],
): StoredNotification[] {
  return [...notifications].sort((left, right) => {
    if (left.readAt && !right.readAt) {
      return 1;
    }

    if (!left.readAt && right.readAt) {
      return -1;
    }

    return Date.parse(right.createdAt) - Date.parse(left.createdAt);
  });
}

export function filterNotifications(
  notifications: StoredNotification[],
  category: NotificationCategory | "all",
  readState: NotificationReadState,
): StoredNotification[] {
  return notifications.filter((notification) => {
    const matchesCategory =
      category === "all" || notification.category === category;

    const matchesReadState =
      readState === "all" ||
      (readState === "unread" && !notification.readAt) ||
      (readState === "read" && Boolean(notification.readAt));

    return matchesCategory && matchesReadState;
  });
}

export function formatRelativeTime(isoTimestamp: string): string {
  const differenceMs = Date.parse(isoTimestamp) - Date.now();
  const differenceMinutes = Math.round(differenceMs / 60000);
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

  if (Math.abs(differenceMinutes) < 60) {
    return formatter.format(differenceMinutes, "minute");
  }

  const differenceHours = Math.round(differenceMinutes / 60);
  if (Math.abs(differenceHours) < 24) {
    return formatter.format(differenceHours, "hour");
  }

  const differenceDays = Math.round(differenceHours / 24);
  return formatter.format(differenceDays, "day");
}
