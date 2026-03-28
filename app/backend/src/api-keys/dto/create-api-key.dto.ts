import {
  IsArray,
  IsIn,
  IsNotEmpty,
  IsOptional,
  IsString,
  ArrayMinSize,
  MaxLength,
} from 'class-validator';
import { API_KEY_SCOPES, ApiKeyScope } from '../api-keys.types';

export class CreateApiKeyDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name: string;

  @IsArray()
  @ArrayMinSize(1)
  @IsIn(API_KEY_SCOPES, { each: true })
  scopes: ApiKeyScope[];

  @IsOptional()
  @IsString()
  owner_id?: string;
}
