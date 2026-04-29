export const PII_FIXTURES = {
  // Expected transformations
  emails: [
    { input: "Contact me at john.doe@example.com for info.", expected: "Contact me at [EMAIL] for info." },
    { input: "Admin: admin123@sub.domain.co.uk", expected: "Admin: [EMAIL]" }
  ],
  phones: [
    { input: "Call me: +1-800-555-0199 today.", expected: "Call me: [PHONE] today." },
    { input: "Cell: (555) 123-4567.", expected: "Cell: [PHONE]." }
  ],
  ids: [
    { input: "My SSN is 123-45-6789.", expected: "My SSN is [SSN]." },
    { input: "Card number 4111 1111 1111 1111 is ready.", expected: "Card number [CARD] is ready." }
  ],
  
  // False positive guard (non-destructive behavior)
  safeText: [
    { input: "Product costs $45.00 and weighs 12.5 kg.", expected: "Product costs $45.00 and weighs 12.5 kg." },
    { input: "The company @open_source launched version 2.0.1", expected: "The company @open_source launched version 2.0.1" },
    { input: "Reference ID: 12345-67890", expected: "Reference ID: 12345-67890" }, // Resembles a phone/SSN but shouldn't be redacted
    { input: "My favorite numbers are 1, 555, and 1234567.", expected: "My favorite numbers are 1, 555, and 1234567." },
    { input: "There is an image file named user_profile.png attached.", expected: "There is an image file named user_profile.png attached." }
  ]
};
