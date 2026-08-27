import { Logger } from "@nestjs/common";
import { createConnection, Socket } from "net";

/**
 * Minimal RESP (REdis Serialization Protocol) client built on top of Node's
 * `net` module. It implements only the commands needed by the sliding-window
 * rate limiter:
 *
 *   PING, ZADD, ZREMRANGEBYSCORE, ZCARD, ZRANGE, EXPIRE, DEL
 *
 * Keeping this dependency-free avoids adding an external redis client while
 * still allowing the limiter to be genuinely Redis-backed when `REDIS_URL` is
 * configured. If Redis is unreachable or disabled, callers are expected to
 * degrade gracefully to an in-memory store.
 */
export class RedisClient {
  private readonly logger = new Logger(RedisClient.name);
  private socket: Socket | null = null;
  private connected = false;
  private readonly pending: Array<{
    resolve: (value: unknown) => void;
    reject: (err: Error) => void;
  }> = [];
  private buffer = Buffer.alloc(0);

  constructor(
    private readonly url: string,
    private readonly connectTimeoutMs: number = 2000,
  ) {}

  async connect(): Promise<boolean> {
    if (this.connected && this.socket) return true;

    return new Promise<boolean>((resolve) => {
      const parsed = this.parseUrl(this.url);
      const socket = createConnection({
        host: parsed.host,
        port: parsed.port,
      });
      let settled = false;

      const finish = (ok: boolean) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(ok);
      };

      const timer = setTimeout(() => {
        if (!settled) {
          this.logger.warn(`Redis connection to ${this.url} timed out`);
          socket.destroy();
          finish(false);
        }
      }, this.connectTimeoutMs);

      socket.on("connect", () => {
        this.socket = socket;
        this.connected = true;
        this.logger.log("Connected to Redis");
        this.attachDataHandler(socket);
        finish(true);
      });

      socket.on("error", (err) => {
        this.logger.warn(`Redis connection error: ${err.message}`);
        this.connected = false;
        finish(false);
      });

      socket.on("close", () => {
        this.connected = false;
        while (this.pending.length) {
          this.pending.shift()!.reject(new Error("Redis connection closed"));
        }
      });
    });
  }

  async ping(): Promise<boolean> {
    try {
      const reply = await this.sendCommand(["PING"]);
      return reply === "PONG";
    } catch {
      return false;
    }
  }

  async zAdd(key: string, score: number, member: string): Promise<number> {
    const reply = await this.sendCommand(["ZADD", key, String(score), member]);
    return Number(reply);
  }

  async zRemRangeByScore(key: string, min: number, max: number): Promise<number> {
    const reply = await this.sendCommand([
      "ZREMRANGEBYSCORE",
      key,
      String(min),
      String(max),
    ]);
    return Number(reply);
  }

  async zCard(key: string): Promise<number> {
    const reply = await this.sendCommand(["ZCARD", key]);
    return Number(reply);
  }

  async zRange(key: string, start: number, stop: number): Promise<string[]> {
    const reply = await this.sendCommand([
      "ZRANGE",
      key,
      String(start),
      String(stop),
      "WITHSCORES",
    ]);
    return Array.isArray(reply) ? (reply as string[]) : [];
  }

  async expire(key: string, seconds: number): Promise<number> {
    const reply = await this.sendCommand(["EXPIRE", key, String(seconds)]);
    return Number(reply);
  }

  async del(key: string): Promise<number> {
    const reply = await this.sendCommand(["DEL", key]);
    return Number(reply);
  }

  /**
   * GET key — returns the string value, or null when the key is absent.
   */
  async get(key: string): Promise<string | null> {
    const reply = await this.sendCommand(["GET", key]);
    return reply === null ? null : String(reply);
  }

  /**
   * SET key value EX <seconds> — stores a value with a TTL.
   */
  async set(key: string, value: string, ttlSeconds: number): Promise<"OK"> {
    const reply = await this.sendCommand([
      "SET",
      key,
      value,
      "EX",
      String(ttlSeconds),
    ]);
    return String(reply) as "OK";
  }

  isConnected(): boolean {
    return this.connected;
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
    this.connected = false;
  }

  private attachDataHandler(socket: Socket): void {
    socket.on("data", (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.processBuffer();
    });
  }

  private processBuffer(): void {
    while (true) {
      const parsed = this.tryParseReply(this.buffer);
      if (parsed === null) break;
      this.buffer = this.buffer.subarray(parsed.consumed);
      const pending = this.pending.shift();
      if (pending) pending.resolve(parsed.value);
    }
  }

  private indexOfCrlf(buf: Buffer, from: number): number {
    const idx = buf.indexOf("\r\n", from);
    return idx < 0 ? -1 : idx;
  }

  private tryParseReply(
    buf: Buffer,
  ): { value: unknown; consumed: number } | null {
    if (buf.length === 0) return null;
    const type = buf[0];

    // Array reply: *<count>\r\n followed by bulk-string/error sub-replies.
    if (type === 42) {
      let pos = 1;
      const countCrlf = this.indexOfCrlf(buf, pos);
      if (countCrlf < 0) return null;
      const count = parseInt(buf.subarray(pos, countCrlf).toString(), 10);
      pos = countCrlf + 2;
      const values: unknown[] = [];
      for (let i = 0; i < count; i++) {
        if (pos >= buf.length) return null;
        if (buf[pos] === 36) {
          const lenCrlf = this.indexOfCrlf(buf, pos + 1);
          if (lenCrlf < 0) return null;
          const len = parseInt(buf.subarray(pos + 1, lenCrlf).toString(), 10);
          const dataStart = lenCrlf + 2;
          const dataEnd = dataStart + len;
          if (dataEnd + 2 > buf.length) return null;
          values.push(buf.subarray(dataStart, dataEnd).toString());
          pos = dataEnd + 2;
        } else if (buf[pos] === 45) {
          const errCrlf = this.indexOfCrlf(buf, pos + 1);
          if (errCrlf < 0) return null;
          values.push(buf.subarray(pos + 1, errCrlf).toString());
          pos = errCrlf + 2;
        } else {
          return null;
        }
      }
      return { value: values, consumed: pos };
    }

    if (type === 36) {
      // Bulk string "$<len>\r\n<data>\r\n" (len -1 = null bulk)
      const crlf = this.indexOfCrlf(buf, 1);
      if (crlf < 0) return null;
      const len = parseInt(buf.subarray(1, crlf).toString(), 10);
      if (len === -1) return { value: null, consumed: crlf + 2 };
      const dataStart = crlf + 2;
      const dataEnd = dataStart + len;
      if (dataEnd + 2 > buf.length) return null;
      return {
        value: buf.subarray(dataStart, dataEnd).toString(),
        consumed: dataEnd + 2,
      };
    }

    if (type === 43 || type === 45 || type === 58) {
      // Inline (+), error (-), or integer (:)
      const crlf = this.indexOfCrlf(buf, 1);
      if (crlf < 0) return null;
      const raw = buf.subarray(1, crlf).toString();
      if (type === 58) return { value: Number(raw), consumed: crlf + 2 };
      if (type === 45) return { value: raw, consumed: crlf + 2 };
      return { value: raw, consumed: crlf + 2 };
    }

    return null;
  }

  private sendCommand(args: string[]): Promise<unknown> {
    return new Promise<unknown>((resolve, reject) => {
      if (!this.connected || !this.socket) {
        reject(new Error("Redis not connected"));
        return;
      }

      this.pending.push({ resolve, reject });
      this.socket!.write(this.encode(args), (err) => {
        if (err) {
          const idx = this.pending.findIndex((p) => p.resolve === resolve);
          if (idx >= 0) this.pending.splice(idx, 1);
          reject(err);
        }
      });
    });
  }

  private encode(args: string[]): Buffer {
    const parts = [`*${args.length}\r\n`];
    for (const arg of args) {
      parts.push(`$${Buffer.byteLength(arg)}\r\n${arg}\r\n`);
    }
    return Buffer.from(parts.join(""));
  }

  private parseUrl(url: string): { host: string; port: number } {
    try {
      const u = new URL(url);
      return { host: u.hostname, port: Number(u.port || 6379) };
    } catch {
      const [host, port] = url.split(":");
      return { host: host || "127.0.0.1", port: Number(port || 6379) };
    }
  }
}
