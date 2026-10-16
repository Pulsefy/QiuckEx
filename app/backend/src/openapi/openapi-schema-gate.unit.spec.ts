import { validateOpenApiDocument } from "../../scripts/check-openapi-schemas";

describe("OpenAPI Schema CI Gate Unit Tests", () => {
  const allowlist = {
    routes: [
      {
        path: "/health",
        method: "get",
        reason: "Shallow ping",
      },
    ],
    schemas: [
      {
        schema: "DynamicDto",
        property: "untypedField",
        reason: "Untyped field exception",
      },
    ],
  };

  it("passes when all routes have response schemas and DTOs have types", () => {
    const spec = {
      paths: {
        "/api/users": {
          get: {
            responses: {
              "200": {
                description: "Success",
                content: {
                  "application/json": {
                    schema: {
                      $ref: "#/components/schemas/UserResponseDto",
                    },
                  },
                },
              },
            },
          },
        },
      },
      components: {
        schemas: {
          UserResponseDto: {
            type: "object",
            properties: {
              id: { type: "string" },
              name: { type: "string" },
            },
          },
        },
      },
    };

    const { routeViolations, schemaViolations } = validateOpenApiDocument(spec, allowlist);
    expect(routeViolations).toHaveLength(0);
    expect(schemaViolations).toHaveLength(0);
  });

  it("honors route allowlist for exempt routes", () => {
    const spec = {
      paths: {
        "/health": {
          get: {
            responses: {
              "200": {
                description: "Plain string health",
              },
            },
          },
        },
      },
      components: { schemas: {} },
    };

    const { routeViolations, schemaViolations } = validateOpenApiDocument(spec, allowlist);
    expect(routeViolations).toHaveLength(0);
    expect(schemaViolations).toHaveLength(0);
  });

  it("fails when a route has no response schema annotation", () => {
    const spec = {
      paths: {
        "/unannotated": {
          post: {
            responses: {
              "201": {
                description: "Created with no schema",
              },
            },
          },
        },
      },
      components: { schemas: {} },
    };

    const { routeViolations, schemaViolations } = validateOpenApiDocument(spec, allowlist);
    expect(routeViolations).toHaveLength(1);
    expect(routeViolations[0].path).toBe("/unannotated");
    expect(routeViolations[0].method).toBe("POST");
  });

  it("fails when a DTO property is missing a type definition", () => {
    const spec = {
      paths: {},
      components: {
        schemas: {
          IncompleteDto: {
            type: "object",
            properties: {
              validProp: { type: "string" },
              missingTypeProp: {},
            },
          },
        },
      },
    };

    const { routeViolations, schemaViolations } = validateOpenApiDocument(spec, allowlist);
    expect(schemaViolations).toHaveLength(1);
    expect(schemaViolations[0].schemaName).toBe("IncompleteDto");
    expect(schemaViolations[0].propertyName).toBe("missingTypeProp");
  });

  it("honors schema allowlist for intentional dynamic properties", () => {
    const spec = {
      paths: {},
      components: {
        schemas: {
          DynamicDto: {
            type: "object",
            properties: {
              untypedField: {},
            },
          },
        },
      },
    };

    const { routeViolations, schemaViolations } = validateOpenApiDocument(spec, allowlist);
    expect(schemaViolations).toHaveLength(0);
  });
});
