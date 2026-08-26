import { Injectable } from "@nestjs/common";

import { OutboxRepository } from "./outbox.repository";
import { OutboxMessage, OutboxStageInput } from "./outbox.types";

/**
 * High-level entry point for producers. Call {@link stage} from inside the same
 * database transaction as the originating state change so the event is durable
 * before it is published by {@link OutboxDispatcher}.
 */
@Injectable()
export class OutboxService {
  constructor(private readonly repository: OutboxRepository) {}

  stage(input: OutboxStageInput): Promise<OutboxMessage> {
    return this.repository.stage(input);
  }
}
