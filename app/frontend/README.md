# QuickEx Frontend

The web dashboard and payment link generator for the QuickEx platform. Built with Next.js 15, Tailwind CSS, and the App Router.

## Getting Started

### Prerequisites

- Node.js 18+
- pnpm

### Installation

From the root of the monorepo:

```bash
pnpm install
```

### Development

Run the development server:

```bash
pnpm turbo run dev --filter=app/frontend
```

Open [http://localhost:3000](http://localhost:3000) to see the result.

### Environment Variables

Create a `.env.local` file in this directory:

```env
NEXT_PUBLIC_STELLAR_NETWORK=testnet  # 'testnet' or 'mainnet'
```

## Structure

- `src/app`: App Router pages (Landing, Dashboard, Generator)
- `src/components`: Shared React components (NetworkBadge, QRPreview)
- `src/styles`: Global CSS and Tailwind configuration

## Scripts

- `dev`: Start development server
- `build`: Build production bundle
- `lint`: Run ESLint
- `type-check`: Run TypeScript compilation check
