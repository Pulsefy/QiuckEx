// src/notifications/in-app-notification.repository.ts

@Injectable()
export class InAppNotificationRepository {
  constructor(private readonly db: SupabaseService) {}

  async create(data: {
    publicKey: string;
    eventType: string;
    eventId: string;
    title: string;
    body: string;
    metadata?: Record<string, unknown>;
  }) {
    return this.db.from("in_app_notifications").insert({
      ...data,
      read: false,
      createdAt: new Date().toISOString(),
    });
  }

  async findByUser(publicKey: string, page = 1, limit = 20) {
    return this.db
      .from("in_app_notifications")
      .select("*")
      .eq("publicKey", publicKey)
      .range((page - 1) * limit, page * limit - 1)
      .order("createdAt", { ascending: false });
  }

  async markAsRead(id: string) {
    return this.db.from("in_app_notifications").update({ read: true }).eq("id", id);
  }

  async markAllAsRead(publicKey: string) {
    return this.db
      .from("in_app_notifications")
      .update({ read: true })
      .eq("publicKey", publicKey);
  }
}