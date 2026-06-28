# Release Promotion Flow: Staging → Production

This document outlines the process for promoting a release from the staging environment to production.

## Overview

We maintain two primary environments:
- **Staging**: For safe end-to-end testing using testnet/staging backend
- **Production**: Live user-facing environment using mainnet

Both environments use identical code and build processes, differing only in configuration.

## Environment Setup

### Vercel Deployment

- **Branch**: `staging` deploys to staging environment
- **Branch**: `main` deploys to production environment
- Configure environment variables in Vercel project settings:

#### Staging Environment Variables
- `NEXT_PUBLIC_QUICKEX_API_URL`: Staging/testnet backend URL
- `NEXT_PUBLIC_SITE_URL`: Staging frontend URL
- `NEXT_PUBLIC_STELLAR_NETWORK`: `testnet` (or appropriate staging network)

#### Production Environment Variables
- `NEXT_PUBLIC_QUICKEX_API_URL`: Production backend URL
- `NEXT_PUBLIC_SITE_URL`: Production frontend URL  
- `NEXT_PUBLIC_STELLAR_NETWORK`: `mainnet`

## Promotion Process

### Step 1: Test on Staging
1. Deploy changes to `staging` branch
2. Verify functionality in staging environment
3. Perform QA testing and end-to-end tests
4. Confirm no regressions or issues

### Step 2: Merge to Main
1. Create a pull request from `staging` to `main`
2. Review changes and obtain approvals
3. Merge the pull request
4. The CD pipeline will automatically deploy to production

### Step 3: Verify Production Deployment
1. Check Vercel deployment status
2. Perform quick smoke tests on production
3. Monitor logs and error reporting

## Staging Banner

A prominent warning banner is automatically displayed in non-mainnet environments to prevent accidental use of real funds.

## CSP/CORS Configuration

Both staging and production use identical security headers (CSP, CORS, HSTS, etc.) to ensure environment parity.
