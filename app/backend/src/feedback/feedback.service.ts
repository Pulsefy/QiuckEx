import { Injectable } from '@nestjs/common';
import { FeedbackDto } from './feedback.dto';
import { randomUUID } from 'crypto';

export interface StoredFeedback extends FeedbackDto {
  id: string;
  ipAddress?: string;
  createdAt: Date;
}

@Injectable()
export class FeedbackService {
  private readonly feedbackStorage: StoredFeedback[] = [];

  async createFeedback(feedback: FeedbackDto, ipAddress?: string): Promise<StoredFeedback> {
    const stored: StoredFeedback = {
      id: randomUUID(),
      ...feedback,
      ipAddress,
      createdAt: new Date(),
    };

    this.feedbackStorage.push(stored);
    return stored;
  }

  async listAll(): Promise<StoredFeedback[]> {
    return this.feedbackStorage;
  }
}
