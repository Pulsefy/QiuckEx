import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { IsOptional, IsString } from "class-validator";
import { ErasureSubject } from "../privacy-retention.service";


export class EncryptRecipientDto {
  @ApiProperty({ description: "Stellar recipient address to encrypt" })
  @IsString()
  recipientAddress!: string;

  @ApiProperty({ description: "Recipient view public key in PEM format" })
  @IsString()
  recipientViewPublicKeyPem!: string;
}

export class DeriveSecretDto {
  @ApiProperty({ description: "Ephemeral/client private key in PEM format" })
  @IsString()
  privateKeyPem!: string;

  @ApiProperty({ description: "Counterpart public key in PEM format" })
  @IsString()
  publicKeyPem!: string;
}

export class StealthEnvelopeDto {
  @ApiProperty({ description: "Ephemeral public key PEM" })
  ephPublicKeyPem!: string;

  @ApiProperty({ description: "Base64 initialization vector" })
  ivBase64!: string;

  @ApiProperty({ description: "Base64 authentication tag" })
  authTagBase64!: string;

  @ApiProperty({ description: "Base64 ciphertext" })
  ciphertextBase64!: string;

  @ApiProperty({ enum: ["aes-256-gcm"] })
  algorithm!: "aes-256-gcm";
}

export class DecryptEnvelopeDto {
  @ApiProperty({ type: StealthEnvelopeDto })
  envelope!: StealthEnvelopeDto;

  @ApiProperty({ description: "Recipient view private key in PEM format" })
  @IsString()
  recipientViewPrivateKeyPem!: string;
}

export class SharedSecretResponseDto {
  @ApiProperty({ description: "Derived hex-encoded shared secret" })
  sharedSecretHex!: string;
}

export class DecryptedRecipientResponseDto {
  @ApiProperty({ description: "Decrypted recipient address" })
  recipientAddress!: string;
}

export class ErasureRequestDto implements ErasureSubject {
  @ApiPropertyOptional({ description: "Stellar public key" })
  @IsOptional()
  @IsString()
  publicKey?: string;

  @ApiPropertyOptional({ description: "Registered username" })
  @IsOptional()
  @IsString()
  username?: string;

  @ApiPropertyOptional({ description: "Internal user ID" })
  @IsOptional()
  @IsString()
  userId?: string;
}

export class StoreRetentionResultDto {
  @ApiProperty()
  storeKey!: string;

  @ApiProperty()
  tableName!: string;

  @ApiProperty({ enum: ["delete", "anonymize"] })
  action!: "delete" | "anonymize";

  @ApiProperty()
  affectedRows!: number;

  @ApiPropertyOptional()
  error?: string;
}

export class PrivacyWorkflowResultDto {
  @ApiProperty()
  runAt!: string;

  @ApiProperty({ type: [StoreRetentionResultDto] })
  results!: StoreRetentionResultDto[];
}
