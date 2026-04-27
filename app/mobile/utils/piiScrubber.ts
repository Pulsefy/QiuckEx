export function scrubPii(text: string): string {
  if (!text) return text;
  
  // Basic email redaction
  let scrubbed = text.replace(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi, '[EMAIL]');
  
  // Basic phone redaction (e.g., +1-555-555-5555 or (555) 555-5555)
  scrubbed = scrubbed.replace(/(\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, '[PHONE]');
  
  // Basic SSN redaction
  scrubbed = scrubbed.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN]');

  // Credit Card redaction
  scrubbed = scrubbed.replace(/\b(?:\d{4}[ -]?){3}\d{4}\b/g, '[CARD]');

  return scrubbed;
}
