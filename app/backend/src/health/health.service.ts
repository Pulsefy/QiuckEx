import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import { HorizonService } from "../stellar/horizon.service";

@Injectable()
export class HealthService {
  private readonly logger = new Logger(HealthService.name);

  constructor(
    private readonly supabase: SupabaseService,
    private readonly horizon: HorizonService,
  ) {}

  async checkSupabase(): Promise<"up" | "down"> {
    try {
      const client = this.supabase.getClient();

      const { error } = await client.from("usernames").select("id").limit(1);

      if (error) {
        this.logger.warn(`Supabase health check failed: ${error.message}`);
        return "down";
      }

      return "up";
    } catch (err) {
      this.logger.warn("Supabase health check threw an error");
      return "down";
    }
  }

  async checkHorizon(): Promise<"up" | "down"> {
    const baseUrl = this.horizon.getBaseUrl();

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3000);

      const res = await fetch(baseUrl, {
        method: "GET",
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!res.ok) {
        this.logger.warn(`Horizon health check returned ${res.status}`);
        return "down";
      }

      return "up";
    } catch (err) {
      this.logger.warn("Horizon health check failed");
      return "down";
    }
  }

  async getHealthStatus() {
    const [supabase, horizon] = await Promise.all([
      this.checkSupabase(),
      this.checkHorizon(),
    ]);

    const allHealthy = supabase === "up" && horizon === "up";

    return {
      status: allHealthy ? "ok" : "degraded",
      services: {
        supabase,
        horizon,
      },
    };
  }
}
