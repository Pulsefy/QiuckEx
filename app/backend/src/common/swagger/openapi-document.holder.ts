/**
 * Holds the generated OpenAPI document so runtime controllers (e.g.
 * `POST /docs/json`) can export the validated spec without re-bootstrapping
 * the application. Populated by main.ts during bootstrap.
 */
export class OpenApiDocumentHolder {
  private static instance: OpenApiDocumentHolder | null = null;

  private doc: Record<string, unknown> | null = null;

  static get(): OpenApiDocumentHolder {
    if (!OpenApiDocumentHolder.instance) {
      OpenApiDocumentHolder.instance = new OpenApiDocumentHolder();
    }
    return OpenApiDocumentHolder.instance;
  }

  set(document: Record<string, unknown>): void {
    this.doc = document;
  }

  get(): Record<string, unknown> | null {
    return this.doc;
  }

  reset(): void {
    this.doc = null;
  }
}
