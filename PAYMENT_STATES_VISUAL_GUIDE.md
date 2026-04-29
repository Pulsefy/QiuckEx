# Payment Link States - Visual Guide

## 1. ACTIVE State

```
┌──────────────────────────────────────────┐
│          ✓ (Green Checkmark)             │
│                                          │
│        Payment Request                   │
│   This payment link is active and        │
│   ready to receive payment               │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  Payment Details                   │ │
│  │                                    │ │
│  │  Recipient:     @john_doe          │ │
│  │  Amount:        100 XLM            │ │
│  │  Memo:          Invoice #123       │ │
│  │  Expires:       05/27/2026         │ │
│  └────────────────────────────────────┘ │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  [Pay Now]  (Blue Button)          │ │
│  │  [Copy Payment Link]               │ │
│  └────────────────────────────────────┘ │
│                                          │
│  ℹ️ How it works: Clicking "Pay Now"    │
│  will open your Stellar wallet...       │
└──────────────────────────────────────────┘
```

## 2. EXPIRED State

```
┌──────────────────────────────────────────┐
│          ⏰ (Orange Clock)               │
│                                          │
│        Link Expired                      │
│   This payment link has expired.         │
│   Please request a new payment link.     │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  Original Payment Details (dimmed) │ │
│  │                                    │ │
│  │  Recipient:     @john_doe          │ │
│  │  Amount:        100 XLM            │ │
│  │  Memo:          Invoice #123       │ │
│  │  Expired On:    04/20/2026         │ │
│  └────────────────────────────────────┘ │
│                                          │
│  ⚠️ Why did this expire?                │
│  Payment links have an expiration       │
│  date for security reasons...           │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  [Go to Homepage]  (Blue Button)   │ │
│  │  [Go Back]                         │ │
│  └────────────────────────────────────┘ │
└──────────────────────────────────────────┘
```

## 3. PAID State

```
┌──────────────────────────────────────────┐
│      ✓✓ (Large Green Animated)          │
│                                          │
│     Payment Complete! 🎉                 │
│   Payment completed successfully!        │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  Payment Summary                   │ │
│  │  (Green/Blue Gradient BG)          │ │
│  │                                    │ │
│  │  Paid To:       @john_doe          │ │
│  │  Amount Paid:   100 XLM (Green)    │ │
│  │  Memo:          Invoice #123       │ │
│  │  Completed:     04/27/2026 10:30   │ │
│  └────────────────────────────────────┘ │
│                                          │
│  Transaction Hash                        │
│  ┌────────────────────────────────────┐ │
│  │ abc123def456...                    │ │
│  └────────────────────────────────────┘ │
│  ↗️ View on Explorer                    │
│                                          │
│  ✅ What's next?                        │
│  Your payment has been confirmed...     │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  [Back to Homepage] (Blue Button)  │ │
│  │  [Copy Transaction Hash]           │ │
│  └────────────────────────────────────┘ │
└──────────────────────────────────────────┘
```

## 4. REFUNDED State

```
┌──────────────────────────────────────────┐
│          ↩️ (Purple Return Arrow)        │
│                                          │
│       Payment Refunded                   │
│   This payment has been refunded.        │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  Refund Details                    │ │
│  │                                    │ │
│  │  Original Recipient:  @john_doe    │ │
│  │  Refunded Amount:     100 XLM      │ │
│  │  Original Memo:       Invoice #123 │ │
│  │  Payment Date:        04/27/2026   │ │
│  └────────────────────────────────────┘ │
│                                          │
│  ℹ️ About this refund                   │
│  This payment has been refunded by      │
│  the recipient. The funds have been...  │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  [Go to Homepage]  (Blue Button)   │ │
│  │  [Go Back]                         │ │
│  └────────────────────────────────────┘ │
└──────────────────────────────────────────┘
```

## 5. LOADING State

```
┌──────────────────────────────────────────┐
│                                          │
│          ⟳ (Spinning Loader)            │
│                                          │
│     Loading payment details...           │
│   Please wait while we fetch the         │
│   payment information                    │
│                                          │
└──────────────────────────────────────────┘
```

## 6. ERROR State

```
┌──────────────────────────────────────────┐
│          ⚠️ (Red Warning)               │
│                                          │
│      Unable to Load Payment              │
│                                          │
│   Username 'invalid_user' not found      │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  ⚠️ Multiple failures detected.    │ │
│  │  This could be due to:             │ │
│  │  • Network connectivity issues     │ │
│  │  • Server temporarily unavailable  │ │
│  │  • Invalid payment link params     │ │
│  └────────────────────────────────────┘ │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  [Retry (Attempt 2)]  (Blue)       │ │
│  │  [Go Home]                         │ │
│  └────────────────────────────────────┘ │
│                                          │
│   Still having issues? Contact support  │
│   with the error message above.         │
└──────────────────────────────────────────┘
```

## Color Scheme

- **ACTIVE**: Green (success, go ahead)
- **EXPIRED**: Orange (warning, time-related)
- **PAID**: Green + Blue gradient (success, celebration)
- **REFUNDED**: Purple (return, neutral)
- **LOADING**: Indigo (neutral, in-progress)
- **ERROR**: Red (error, stop) + Amber (warning box)

## Iconography

- All icons are SVG (inline)
- Consistent 2px stroke width
- Circular backgrounds with state color
- Size: 80x80px (w-20 h-20) for most states
- PAID state uses larger 96x96px (w-24 h-24) with animation

## Responsive Design

- All components use Tailwind CSS
- Mobile-first approach
- Max width: 2xl (672px) for main content
- Padding adjusts for mobile/desktop
- Text sizes scale appropriately
