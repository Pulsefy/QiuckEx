import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsNumber, IsObject, IsString } from 'class-validator';

export class EmitAnalyticsEventDto {
  @ApiProperty({ description: 'The name of the event to emit' })
  @IsNotEmpty()
  @IsString()
  eventName: string;

  @ApiProperty({ description: 'The version of the event schema' })
  @IsNotEmpty()
  @IsNumber()
  version: number;

  @ApiProperty({ description: 'The payload of the event' })
  @IsNotEmpty()
  @IsObject()
  payload: Record<string, any>;
}
