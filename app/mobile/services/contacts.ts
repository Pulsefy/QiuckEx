import AsyncStorage from '@react-native-async-storage/async-storage';
import { Contact } from '../types/contact';
import * as Crypto from 'expo-crypto';
import NetInfo from '@react-native-community/netinfo';

let supabase: any = null;
try {
  supabase = require('./supabase').supabase;
} catch {}

const CONTACTS_KEY = 'contacts';
const SUPABASE_TABLE = 'contacts';

function isSupabaseConfigured() {
  return !!process.env.EXPO_PUBLIC_SUPABASE_URL && !!process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY;
}

export async function getContacts(): Promise<Contact[]> {
  const netInfo = await NetInfo.fetch();
  
  if (isSupabaseConfigured() && supabase && netInfo.isConnected !== false) {
    try {
      const { data, error } = await supabase.from(SUPABASE_TABLE).select('*').order('updatedAt', { ascending: false });
      if (!error && data) {
        // Sync local cache with remote data
        await AsyncStorage.setItem(CONTACTS_KEY, JSON.stringify(data));
        return data;
      }
    } catch (e) {
      console.warn("Failed to fetch contacts from Supabase, falling back to cache", e);
    }
  }
  
  // Fallback to local cache
  const data = await AsyncStorage.getItem(CONTACTS_KEY);
  return data ? JSON.parse(data) : [];
}

export async function saveContact(contact: Omit<Contact, 'id' | 'createdAt' | 'updatedAt'>): Promise<Contact> {
  const newContact: Contact = {
    ...contact,
    id: Crypto.randomUUID(),
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };

  const netInfo = await NetInfo.fetch();
  if (isSupabaseConfigured() && supabase && netInfo.isConnected !== false) {
    await supabase.from(SUPABASE_TABLE).insert([newContact]);
  }
  
  // Always update local cache
  const contacts = await getContacts();
  await AsyncStorage.setItem(CONTACTS_KEY, JSON.stringify([newContact, ...contacts]));
  return newContact;
}

export async function updateContact(updated: Contact): Promise<void> {
  const netInfo = await NetInfo.fetch();
  if (isSupabaseConfigured() && supabase && netInfo.isConnected !== false) {
    await supabase.from(SUPABASE_TABLE).update({ ...updated, updatedAt: Date.now() }).eq('id', updated.id);
  }
  
  // Always update local cache
  const contacts = await getContacts();
  const next = contacts.map(c => c.id === updated.id ? { ...updated, updatedAt: Date.now() } : c);
  await AsyncStorage.setItem(CONTACTS_KEY, JSON.stringify(next));
}

export async function deleteContact(id: string): Promise<void> {
  const netInfo = await NetInfo.fetch();
  if (isSupabaseConfigured() && supabase && netInfo.isConnected !== false) {
    await supabase.from(SUPABASE_TABLE).delete().eq('id', id);
  }
  
  // Always update local cache
  const contacts = await getContacts();
  const next = contacts.filter(c => c.id !== id);
  await AsyncStorage.setItem(CONTACTS_KEY, JSON.stringify(next));
}
