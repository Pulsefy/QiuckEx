import { IsNumber, IsString, Min } from 'class-validator';

export class TestnetResetDto {
  @IsString()
  contractId: string;

  @IsNumber()
  @Min(1)
  fromLedger: number;

  @IsNumber()
  @Min(1)
  toLedger: number;

  // When true, force reindex ignoring checkpoints
  force?: boolean;
}
