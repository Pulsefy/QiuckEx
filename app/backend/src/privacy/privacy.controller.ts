import { Body, Controller, Post } from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { PrivacyService } from "./privacy.service";
import { RateLimitTier } from "../auth/decorators/rate-limit-group.decorator";
import {
  EncryptRecipientDto,
  DeriveSecretDto,
  DecryptEnvelopeDto,
  StealthEnvelopeDto,
  SharedSecretResponseDto,
  DecryptedRecipientResponseDto,
} from "./dto/privacy.dto";

@ApiTags("privacy")
@Controller("privacy")
export class PrivacyController {
  constructor(private readonly privacyService: PrivacyService) {}

  @Post("encrypt-recipient")
  @RateLimitTier("mutation")
  @ApiOperation({
    summary: "Encrypt recipient metadata using recipient view public key",
  })
  @ApiResponse({ status: 201, type: StealthEnvelopeDto })
  encryptRecipient(@Body() body: EncryptRecipientDto) {
    return this.privacyService.encryptRecipientForViewKey(
      body.recipientAddress,
      body.recipientViewPublicKeyPem,
    );
  }

  @Post("derive-shared-secret")
  @RateLimitTier("mutation")
  @ApiOperation({
    summary: "Derive X25519 shared secret for non-custodial stealth flows",
  })
  @ApiResponse({ status: 201, type: SharedSecretResponseDto })
  deriveSharedSecret(@Body() body: DeriveSecretDto) {
    return {
      sharedSecretHex: this.privacyService.deriveSharedSecretHex(
        body.privateKeyPem,
        body.publicKeyPem,
      ),
    };
  }

  @Post("decrypt-recipient")
  @RateLimitTier("mutation")
  @ApiOperation({
    summary: "Decrypt recipient metadata envelope (for local integration testing)",
  })
  @ApiResponse({ status: 201, type: DecryptedRecipientResponseDto })
  decryptRecipient(@Body() body: DecryptEnvelopeDto) {
    return {
      recipientAddress: this.privacyService.decryptRecipientEnvelope(
        body.envelope,
        body.recipientViewPrivateKeyPem,
      ),
    };
  }
}
