// src/transactions/utils/param-builder.ts
import * as StellarSdk from "@stellar/stellar-sdk";
import { xdr } from "@stellar/stellar-sdk";
import { ContractParamDto } from "../dto/compose-transaction.dto";

export function buildScVal(param: ContractParamDto): xdr.ScVal {
  const v = param.value as string; // safe: all scalar values arrive as JSON strings

  switch (param.type) {
    case "address":
      return StellarSdk.nativeToScVal(StellarSdk.Address.fromString(v), {
        type: "address",
      });

    case "i128":
      return StellarSdk.nativeToScVal(BigInt(v), { type: "i128" });

    case "u128":
      return StellarSdk.nativeToScVal(BigInt(v), { type: "u128" });

    case "i64":
      return StellarSdk.nativeToScVal(BigInt(v), { type: "i64" });

    case "u64":
      return StellarSdk.nativeToScVal(BigInt(v), { type: "u64" });

    case "bool":
      return StellarSdk.nativeToScVal(Boolean(param.value), { type: "bool" });

    case "string":
      return StellarSdk.nativeToScVal(v, { type: "string" });

    case "symbol":
      return StellarSdk.nativeToScVal(v, { type: "symbol" });

    case "bytes":
      return StellarSdk.nativeToScVal(Buffer.from(v, "hex"), { type: "bytes" });

    case "u32":
      return StellarSdk.nativeToScVal(Number(v), { type: "u32" });

    case "i32":
      return StellarSdk.nativeToScVal(Number(v), { type: "i32" });

    case "vec":
      if (!Array.isArray(param.value)) {
        throw new Error(
          `Expected array for vec type, got ${typeof param.value}`,
        );
      }
      return StellarSdk.nativeToScVal(
        (param.value as ContractParamDto[]).map((item) => buildScVal(item)),
        { type: "vec" },
      );

    default:
      throw new Error(`Unsupported param type: "${param.type}"`);
  }
}
