import { HttpStatus } from "@nestjs/common";

export type ErrorCode =
  | "INTERNAL_SERVER_ERROR"
  | "VALIDATION_ERROR"
  | "RATE_LIMIT_EXCEEDED"
  | "UNAUTHORIZED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "BAD_REQUEST"
  | "CONFLICT"
  | "SERVICE_UNAVAILABLE"
  | "GATEWAY_TIMEOUT"
  | string;

export interface ErrorCatalogEntry {
  code: ErrorCode;
  status: HttpStatus;
  meaning: string;
}

export const ErrorCatalog: Record<string, ErrorCatalogEntry> = {
  INTERNAL_SERVER_ERROR: {
    code: "INTERNAL_SERVER_ERROR",
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    meaning: "An unexpected error occurred on the server.",
  },
  VALIDATION_ERROR: {
    code: "VALIDATION_ERROR",
    status: HttpStatus.BAD_REQUEST,
    meaning: "The request failed validation.",
  },
  RATE_LIMIT_EXCEEDED: {
    code: "RATE_LIMIT_EXCEEDED",
    status: HttpStatus.TOO_MANY_REQUESTS,
    meaning: "The client has sent too many requests in a given amount of time.",
  },
  UNAUTHORIZED: {
    code: "UNAUTHORIZED",
    status: HttpStatus.UNAUTHORIZED,
    meaning: "Authentication is required and has failed or has not yet been provided.",
  },
  FORBIDDEN: {
    code: "FORBIDDEN",
    status: HttpStatus.FORBIDDEN,
    meaning: "The client does not have access rights to the content.",
  },
  NOT_FOUND: {
    code: "NOT_FOUND",
    status: HttpStatus.NOT_FOUND,
    meaning: "The requested resource could not be found.",
  },
  BAD_REQUEST: {
    code: "BAD_REQUEST",
    status: HttpStatus.BAD_REQUEST,
    meaning: "The server could not understand the request due to invalid syntax.",
  },
  CONFLICT: {
    code: "CONFLICT",
    status: HttpStatus.CONFLICT,
    meaning: "The request could not be completed due to a conflict with the current state of the target resource.",
  },
  SERVICE_UNAVAILABLE: {
    code: "SERVICE_UNAVAILABLE",
    status: HttpStatus.SERVICE_UNAVAILABLE,
    meaning: "The server is currently unable to handle the request due to a temporary overload or scheduled maintenance.",
  },
  GATEWAY_TIMEOUT: {
    code: "GATEWAY_TIMEOUT",
    status: HttpStatus.GATEWAY_TIMEOUT,
    meaning: "The server, while acting as a gateway or proxy, did not get a response in time from the upstream server that it needed in order to complete the request.",
  },
};
