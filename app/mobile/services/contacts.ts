import AsyncStorage from '@react-native-async-storage/async-storage';
import { Contact } from '../types/contact';
import * as Crypto from 'expo-crypto';
import { StrKey } from '@stellar/stellar-base';

const CONTACTS_KEY = 'contacts';

export function isValidContactAddress(address: string): boolean {
  return StrKey.isValidEd25519PublicKey(address.trim());
}

export async function getContacts(): Promise<Contact[]> {
  const data = await AsyncStorage.getItem(CONTACTS_KEY);
  if (!data) return [];

  try {
    const parsed: unknown = JSON.parse(data);
    if (!Array.isArray(parsed)) throw new Error('Stored contacts are not an array');
    return parsed as Contact[];
  } catch {
    await AsyncStorage.removeItem(CONTACTS_KEY);
    return [];
  }
}

export async function saveContact(contact: Omit<Contact, 'id' | 'createdAt' | 'updatedAt'>): Promise<Contact> {
  const newContact: Contact = {
    ...contact,
    id: Crypto.randomUUID(),
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };

  const contacts = await getContacts();
  await AsyncStorage.setItem(CONTACTS_KEY, JSON.stringify([newContact, ...contacts]));
  return newContact;
}

export async function updateContact(updated: Contact): Promise<void> {
  const contacts = await getContacts();
  const next = contacts.map(c => c.id === updated.id ? { ...updated, updatedAt: Date.now() } : c);
  await cacheContacts(next);
}

export async function deleteContact(id: string): Promise<void> {
  const contacts = await getContacts();
  const next = contacts.filter(c => c.id !== id);
  await cacheContacts(next);
}
