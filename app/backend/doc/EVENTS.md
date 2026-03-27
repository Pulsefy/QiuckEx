# Internal Event System

Decoupled event handling using `@nestjs/event-emitter`.

## Registered Events

### Core Payment Events

| Event Name | Description | Payload Schema |
| :--- | :--- | :--- |
| `username_claimed` | Fired when a username is registered | `{ username: string, publicKey: string, timestamp: string }` |
| `payment_received` | Fired when a payment is detected | `{ txHash: string, amount: string, sender: string }` |

### Recurring Payment Events

| Event Name | Description | Payload Schema |
| :--- | :--- | :--- |
| `recurring.link.created` | Fired when a recurring payment link is created | `{ linkId: string, username?: string, destination?: string }` |
| `recurring.link.updated` | Fired when a recurring link is updated | `{ linkId: string, changes: object }` |
| `recurring.link.cancelled` | Fired when a recurring link is cancelled | `{ linkId: string, username?: string, destination?: string }` |
| `recurring.link.paused` | Fired when a recurring link is paused | `{ linkId: string, username?: string, destination?: string }` |
| `recurring.link.resumed` | Fired when a recurring link is resumed | `{ linkId: string, username?: string, destination?: string }` |
| `recurring.link.completed` | Fired when a recurring link completes all periods | `{ linkId: string, totalExecuted: number }` |
| `recurring.payment.due` | Fired 24h before a payment is scheduled | `{ linkId: string, executionId: string, amount: number, asset: string, periodNumber: number }` |
| `recurring.payment.executed` | Fired when a recurring payment succeeds | `{ linkId: string, executionId: string, transactionHash: string, periodNumber: number }` |
| `recurring.payment.failed` | Fired when a recurring payment fails | `{ linkId: string, executionId: string, failureReason: string, retryCount: number, permanent: boolean }` |

## How to add new handlers
1. Inject `NotificationService` (or create a new service).
2. Use the `@OnEvent('event_name', { async: true })` decorator.