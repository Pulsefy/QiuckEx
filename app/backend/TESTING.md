# Backend Testing Strategy

## Layers

### Unit Tests

- Suffix: \*.unit.spec.ts
- Test pure services
- No Nest app bootstrap

### Integration Tests

- Suffix: \*.int.spec.ts
- Use TestingModule
- Mock external systems

### E2E Tests

- Located in /test
- Suffix: \*.e2e-spec.ts
- Boot full Nest app
- Use supertest
