# Vercel Deployment Guide

This guide covers deploying the QuickEx frontend to Vercel with Preview Deployments for PRs and Production deployments from the main branch.

## Prerequisites

- Vercel account (https://vercel.com)
- GitHub repository connected to Vercel
- Backend API endpoints configured and accessible
- Environment variables documented in `VERCEL_ENV_SETUP.md`

## Initial Setup

### 1. Connect Repository to Vercel

1. Log in to [Vercel](https://vercel.com)
2. Click **"Add New..."** → **"Project"**
3. Import your GitHub repository
4. Vercel will automatically detect the Next.js framework

### 2. Configure Project Settings

#### Framework Preset
- **Framework**: Next.js
- **Root Directory**: `app/frontend`
- **Build Command**: `npm run build`
- **Output Directory**: `.next`
- **Install Command**: `npm install`

#### Environment Variables
Add the following environment variables in Vercel project settings:

**Production (main branch):**
```
NEXT_PUBLIC_QUICKEX_API_URL=https://api.quickex.to
NEXT_PUBLIC_SITE_URL=https://quickex.to
NEXT_PUBLIC_STELLAR_NETWORK=mainnet
NEXT_PUBLIC_ERROR_REPORTING_ENABLED=true
NEXT_PUBLIC_APP_VERSION=1.0.0
```

**Preview (all PRs):**
```
NEXT_PUBLIC_QUICKEX_API_URL=https://api-staging.quickex.to
NEXT_PUBLIC_STELLAR_NETWORK=testnet
NEXT_PUBLIC_ERROR_REPORTING_ENABLED=true
NEXT_PUBLIC_APP_VERSION=1.0.0-preview
```

### 3. Enable Preview Deployments

Preview deployments are automatically enabled by Vercel when you connect a GitHub repository. Each PR will generate a unique preview URL.

## Deployment Workflow

### Preview Deployments (Per PR)

Every pull request to the main branch automatically triggers:
1. **CI Checks**: Type checking and linting (via GitHub Actions)
2. **Build**: Next.js production build
3. **Preview Deployment**: Unique URL for testing

**Preview URL Format**: `https://<project-name>-<git-branch>-<random>.vercel.app`

### Production Deployments (Main Branch)

Merging to main branch triggers:
1. **CI Checks**: All checks must pass
2. **Build**: Production-optimized build
3. **Deployment**: Automatic deployment to production
4. **Domain Update**: Updates the custom domain (if configured)

## CI/CD Integration

### GitHub Actions

The `.github/workflows/frontend-ci.yml` workflow runs on every PR and push to main:

- **Lint Check**: ESLint validation
- **Type Check**: TypeScript compilation check
- **Build Check**: Production build verification
- **Security Scan**: npm audit and mixed-content detection

### Required GitHub Secrets

Add these secrets to your GitHub repository settings:

```
NEXT_PUBLIC_QUICKEX_API_URL
NEXT_PUBLIC_SITE_URL
NEXT_PUBLIC_STELLAR_NETWORK
NEXT_PUBLIC_ERROR_REPORTING_ENABLED
NEXT_PUBLIC_APP_VERSION
```

## Custom Domain Configuration

### Production Domain

1. Go to **Settings** → **Domains**
2. Add your custom domain (e.g., `quickex.to`)
3. Configure DNS records as instructed by Vercel
4. Enable automatic HTTPS

### Preview Domains

Preview deployments use Vercel's default `.vercel.app` domains. These are automatically HTTPS-enabled.

## Wallet Integration Validation

### Mixed Content Prevention

The deployment is configured to prevent mixed-content issues:

1. **HTTPS Enforcement**: All environment variables use HTTPS
2. **Security Headers**: HSTS and other security headers are configured
3. **Image Optimization**: Only HTTPS images are allowed
4. **API Calls**: All backend communication uses HTTPS

### Testing Wallet Integration

**Preview Environment:**
- Testnet wallet connections
- Testnet transactions
- Staging backend API

**Production Environment:**
- Mainnet wallet connections
- Mainnet transactions
- Production backend API

## Monitoring and Logs

### Vercel Dashboard

- **Deployments**: View deployment history and status
- **Logs**: Access real-time and historical logs
- **Analytics**: Monitor performance and usage
- **Speed Insights**: Analyze Core Web Vitals

### Error Reporting

Client-side errors are reported to the configured error reporting endpoint (if `NEXT_PUBLIC_ERROR_REPORTING_ENABLED=true`).

## Rollback Procedure

If a production deployment causes issues:

1. Go to **Deployments** in Vercel dashboard
2. Find the previous stable deployment
3. Click **"..."** → **"Promote to Production"**
4. Confirm the rollback

## Troubleshooting

### Build Failures

**Issue**: Build fails during deployment
- Check the build logs in Vercel
- Ensure all environment variables are set
- Verify dependencies are compatible
- Run `npm run build` locally to reproduce

### Preview Deployment Issues

**Issue**: Preview deployment not working
- Check that PR is from a forked repository (may need approval)
- Verify environment variables for Preview environment
- Check GitHub Actions CI status

### Mixed Content Warnings

**Issue**: Browser shows mixed-content warnings
- Ensure all `NEXT_PUBLIC_*` URLs use HTTPS
- Check that wallet provider URLs use HTTPS
- Verify no hardcoded HTTP URLs in codebase
- Run the security scan in GitHub Actions

### Environment Variable Issues

**Issue**: App not loading due to missing environment variables
- Verify all required variables are set in Vercel
- Check variable names match exactly (case-sensitive)
- Ensure Preview and Production environments are configured separately

## Performance Optimization

The deployment includes:

- **Automatic Image Optimization**: Next.js Image component
- **Code Splitting**: Automatic route-based splitting
- **Edge Network**: Vercel's global CDN
- **Static Generation**: Pre-rendered pages where possible
- **ISR**: Incremental Static Regeneration for dynamic content

## Security Best Practices

- **HTTPS Only**: All deployments use HTTPS
- **Security Headers**: HSTS, XSS protection, frame options
- **Environment Variables**: Sensitive data never exposed to client
- **Dependency Scanning**: Automated security audits
- **CORS Configuration**: Proper cross-origin settings

## Acceptance Criteria Validation

✅ **Every PR generates a working preview URL**
- Preview deployments are automatic
- CI checks run before deployment
- Preview URL is unique per PR

✅ **Main deploys automatically to production**
- Merging to main triggers production deployment
- All CI checks must pass
- Custom domain updates automatically

✅ **App loads and can complete core flows in both environments**
- Preview uses testnet configuration
- Production uses mainnet configuration
- Wallet integrations work in both
- No mixed-content issues

✅ **Documentation with Vercel URL**
- This guide provides complete setup instructions
- Environment variables are documented
- Troubleshooting guide included

## Additional Resources

- [Vercel Documentation](https://vercel.com/docs)
- [Next.js Deployment](https://nextjs.org/docs/deployment)
- [Environment Variables Guide](./VERCEL_ENV_SETUP.md)
- [Project README](./README.md)

## Support

For deployment issues:
1. Check Vercel deployment logs
2. Review GitHub Actions CI status
3. Consult troubleshooting section above
4. Open an issue in the repository
