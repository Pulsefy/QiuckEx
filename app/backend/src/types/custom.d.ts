// Lightweight module declarations to satisfy TypeScript in the build environment
declare module 'nest-winston';
declare module 'winston';

declare namespace Express {
  interface Request {
    apiKey?: {
      id: string;
      name: string;
      scopes: string[];
      rateLimit: number;
      organization_id?: string | null;
    };
    organizationContext?: {
      organizationId?: string;
      role: "admin" | "member" | "read_only";
    };
  }
}

export {};
