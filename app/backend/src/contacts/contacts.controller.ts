import { Body, Controller, Delete, Get, Param, Patch, Post, Query } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { ContactsService } from './contacts.service';
import { ContactOwnerDto, CreateContactDto, UpdateContactDto } from './dto/contact.dto';

@ApiTags('contacts')
@Controller('contacts')
export class ContactsController {
  constructor(private readonly contacts: ContactsService) {}

  @Get()
  @ApiOperation({ summary: 'List contacts for a wallet' })
  @ApiResponse({ status: 200, description: 'Contacts returned' })
  async list(@Query() query: ContactOwnerDto) {
    return { contacts: await this.contacts.list(query.ownerPublicKey) };
  }

  @Post()
  @ApiOperation({ summary: 'Create or sync a contact' })
  @ApiResponse({ status: 201, description: 'Contact saved' })
  async create(@Body() body: CreateContactDto) {
    return { contact: await this.contacts.create(body.ownerPublicKey, body.contact) };
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a wallet contact' })
  async update(@Param('id') id: string, @Body() body: UpdateContactDto) {
    return { contact: await this.contacts.update(body.ownerPublicKey, id, body.contact) };
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a wallet contact' })
  async remove(@Param('id') id: string, @Query() query: ContactOwnerDto) {
    await this.contacts.remove(query.ownerPublicKey, id);
    return { ok: true };
  }
}
