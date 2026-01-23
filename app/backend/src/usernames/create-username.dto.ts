import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';

export class CreateUsernameDto {
  @IsString()
  @IsNotEmpty()
  @Length(3, 32)
  @Matches(/^[a-z0-9_]+$/)
  username!: string;
}
