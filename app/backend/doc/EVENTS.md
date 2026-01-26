# Internal Event System

Decoupled event handling using `@nestjs/event-emitter`.

## Registered Events

| Event Name | Description | Payload Schema |
| :--- | :--- | :--- |
| `username_claimed` | Fired when a username is registered | `{ username: string, publicKey: string, timestamp: string }` |
| `payment_received` | Fired when a payment is detected | `{ txHash: string, amount: string, sender: string }` |

## How to add new handlers
1. Inject `NotificationService` (or create a new service).
2. Use the `@OnEvent('event_name', { async: true })` decorator.