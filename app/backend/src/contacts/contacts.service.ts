import { Injectable, NotFoundException } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import { ContactDto } from './dto/contact.dto';

export type ContactRecord = ContactDto & {
  id: string;
  createdAt: number;
  updatedAt: number;
};

@Injectable()
export class ContactsService {
  constructor(private readonly supabase: SupabaseService) {}

  async list(ownerPublicKey: string): Promise<ContactRecord[]> {
    const { data, error } = await this.supabase
      .getClient()
      .from('contacts')
      .select('id, address, nickname, tags, created_at, updated_at')
      .eq('owner_public_key', ownerPublicKey)
      .order('updated_at', { ascending: false });

    if (error) throw error;
    return (data ?? []).map((contact) => this.toClientContact(contact));
  }

  async create(ownerPublicKey: string, contact: ContactDto): Promise<ContactRecord> {
    const now = Date.now();
    const { data, error } = await this.supabase
      .getClient()
      .from('contacts')
      .upsert({
        id: contact.id,
        owner_public_key: ownerPublicKey,
        address: contact.address.trim(),
        nickname: contact.nickname.trim(),
        tags: contact.tags ?? [],
        created_at: new Date(now).toISOString(),
        updated_at: new Date(now).toISOString(),
      }, { onConflict: 'id,owner_public_key' })
      .select('id, address, nickname, tags, created_at, updated_at')
      .single();

    if (error) throw error;
    return this.toClientContact(data);
  }

  async update(ownerPublicKey: string, id: string, contact: ContactDto): Promise<ContactRecord> {
    const { data, error } = await this.supabase
      .getClient()
      .from('contacts')
      .update({
        address: contact.address.trim(),
        nickname: contact.nickname.trim(),
        tags: contact.tags ?? [],
        updated_at: new Date().toISOString(),
      })
      .eq('id', id)
      .eq('owner_public_key', ownerPublicKey)
      .select('id, address, nickname, tags, created_at, updated_at')
      .maybeSingle();

    if (error) throw error;
    if (!data) throw new NotFoundException('Contact not found');
    return this.toClientContact(data);
  }

  async remove(ownerPublicKey: string, id: string): Promise<void> {
    const { data, error } = await this.supabase
      .getClient()
      .from('contacts')
      .delete()
      .eq('id', id)
      .eq('owner_public_key', ownerPublicKey)
      .select('id')
      .maybeSingle();

    if (error) throw error;
    if (!data) throw new NotFoundException('Contact not found');
  }

  private toClientContact(contact: Record<string, unknown>): ContactRecord {
    return {
      id: String(contact.id),
      address: String(contact.address),
      nickname: String(contact.nickname ?? ''),
      tags: Array.isArray(contact.tags) ? contact.tags.map(String) : [],
      createdAt: new Date(String(contact.created_at)).getTime(),
      updatedAt: new Date(String(contact.updated_at)).getTime(),
    };
  }
}
