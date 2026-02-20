import { ValidationError } from "class-validator";

export interface MappedValidationError {
  message: string;
  fields: Array<{
    field: string;
    errors: string[];
  }>;
}

export function mapValidationErrors(
  errors: ValidationError[],
): MappedValidationError {
  const fields = errors.map((error) => {
    const constraints = error.constraints
      ? Object.values(error.constraints)
      : [];

    return {
      field: error.property,
      errors: constraints,
    };
  });

  return {
    message: "Validation failed",
    fields,
  };
}
