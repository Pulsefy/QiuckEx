// src/notifications/in-app-notification.repository.ts

import { Injectable } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";

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
    previewScope?: string;
  }) {
    const insertData: Record<string, unknown> = {
      publicKey: data.publicKey,
      eventType: data.eventType,
      eventId: data.eventId,
      title: data.title,
      body: data.body,
      metadata: data.metadata ?? null,
      read: false,
      createdAt: new Date().toISOString(),
    };

    if (data.previewScope) {
      insertData.preview_scope = data.previewScope;
    }

    return this.db.getClient().from("in_app_notifications").insert(insertData);
  }

  async findByUser(
    publicKey: string,
    page = 1,
    limit = 20,
    previewScope?: string,
  ) {
    let query = this.db
      .getClient()
      .from("in_app_notifications")
      .select("*")
      .eq("publicKey", publicKey);

    if (previewScope) {
      query = query.eq("preview_scope", previewScope);
    } else {
      query = query.is("preview_scope", null);
    }

    return query
      .range((page - 1) * limit, page * limit - 1)
      .order("createdAt", { ascending: false });
  }

  async markAsRead(publicKey: string, id: string) {
    return this.db
      .getClient()
      .from("in_app_notifications")
      .update({ read: true })
      .eq("publicKey", publicKey)
      .eq("id", id)
      .eq("read", false);
  }

  async markManyAsRead(publicKey: string, ids: string[]) {
    return this.db
      .getClient()
      .from("in_app_notifications")
      .update({ read: true })
      .eq("publicKey", publicKey)
      .eq("read", false)
      .in("id", ids);
  }

  async markAllAsRead(publicKey: string) {
    return this.db
      .getClient()
      .from("in_app_notifications")
      .update({ read: true })
      .eq("publicKey", publicKey)
      .eq("read", false);
  }
  async getUnreadCount(publicKey: string) {
    const { count } = await this.db
      .getClient()
      .from("in_app_notifications")
      .select("id", { count: "exact" })
      .eq("publicKey", publicKey)
      .eq("read", false);

    return count ?? 0;
  }
}
