import { Body, Controller, Post } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { PrivacyService, StealthEnvelope } from "./privacy.service";

class EncryptRecipientDto {
  recipientAddress!: string;
  recipientViewPublicKeyPem!: string;
}

class DeriveSecretDto {
  privateKeyPem!: string;
  publicKeyPem!: string;
}

class DecryptEnvelopeDto {
  envelope!: StealthEnvelope;
  recipientViewPrivateKeyPem!: string;
}

@ApiTags("privacy")
@Controller("privacy")
export class PrivacyController {
  constructor(private readonly privacyService: PrivacyService) {}

  @Post("encrypt-recipient")
  @ApiOperation({
    summary: "Encrypt recipient metadata using recipient view public key",
  })
  encryptRecipient(@Body() body: EncryptRecipientDto) {
    return this.privacyService.encryptRecipientForViewKey(
      body.recipientAddress,
      body.recipientViewPublicKeyPem,
    );
  }

  @Post("derive-shared-secret")
  @ApiOperation({
    summary: "Derive X25519 shared secret for non-custodial stealth flows",
  })
  deriveSharedSecret(@Body() body: DeriveSecretDto) {
    return {
      sharedSecretHex: this.privacyService.deriveSharedSecretHex(
        body.privateKeyPem,
        body.publicKeyPem,
      ),
    };
  }

  @Post("decrypt-recipient")
  @ApiOperation({
    summary: "Decrypt recipient metadata envelope (for local integration testing)",
  })
  decryptRecipient(@Body() body: DecryptEnvelopeDto) {
    return {
      recipientAddress: this.privacyService.decryptRecipientEnvelope(
        body.envelope,
        body.recipientViewPrivateKeyPem,
      ),
    };
  }
}
