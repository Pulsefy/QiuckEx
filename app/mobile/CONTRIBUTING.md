# Contributing to QuickEx Mobile (Expo)

Thank you for your interest in contributing to the QuickEx mobile app!

## Development Workflow

1. **Pick an issue**: Check the project's GitHub issues for mobile-specific tasks.
2. **Branching**: Use the naming convention `feature/mobile-[description]`.
3. **Drafting**: Create a draft PR early for feedback.

## Navigation Patterns

- We use **Expo Router** (file-based navigation).
- New screens should be added to the `app/` directory.
- Use the `<Link>` component or `useRouter` hook for navigation.

## Styling Guidelines

- Use `StyleSheet.create` for styling.
- Colors and typography should eventually follow a shared theme.

## Testing Guidelines

- Smoke tests ensure screens render without crashing.
- Run tests with `pnpm --filter=mobile test`.

## PR Checklist

- [ ] My code follows the code style.
- [ ] I have self-reviewed my changes.
- [ ] I have updated documentation if necessary.
- [ ] Tests pass locally.
