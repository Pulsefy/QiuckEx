/**
 * Jest setup file
 * Sets environment variables required for testing before any test files are loaded.
 */

// Set required environment variables for tests
process.env.NETWORK = 'testnet';
process.env.SUPABASE_URL = 'https://test-project.supabase.co';
process.env.SUPABASE_ANON_KEY = 'test-anon-key-for-testing';
process.env.NODE_ENV = 'test';
process.env.PORT = '4000';

// Set Jest timeout
jest.setTimeout(10000);

// Mock console methods to reduce noise during tests
jest.spyOn(console, 'log').mockImplementation(() => {});
jest.spyOn(console, 'debug').mockImplementation(() => {});
jest.spyOn(console, 'info').mockImplementation(() => {});
jest.spyOn(console, 'warn').mockImplementation(() => {});
jest.spyOn(console, 'error').mockImplementation(() => {});
