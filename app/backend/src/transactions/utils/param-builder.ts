// src/transactions/utils/param-builder.ts
import * as StellarSdk from "@stellar/stellar-sdk";
import { xdr } from "@stellar/stellar-sdk";
import { ContractParamDto } from "../dto/compose-transaction.dto";

export function buildScVal(param: ContractParamDto): xdr.ScVal {
  switch (param.type) {
    case "address":
      return StellarSdk.nativeToScVal(
        StellarSdk.Address.fromString(param.value),
        { type: "address" },
      );

    case "i128":
      return StellarSdk.nativeToScVal(BigInt(param.value), { type: "i128" });

    case "u128":
      return StellarSdk.nativeToScVal(BigInt(param.value), { type: "u128" });

    case "i64":
      return StellarSdk.nativeToScVal(BigInt(param.value), { type: "i64" });

    case "u64":
      return StellarSdk.nativeToScVal(BigInt(param.value), { type: "u64" });

    case "bool":
      return StellarSdk.nativeToScVal(Boolean(param.value), { type: "bool" });

    case "string":
      return StellarSdk.nativeToScVal(String(param.value), { type: "string" });

    case "symbol":
      return StellarSdk.nativeToScVal(String(param.value), { type: "symbol" });

    case "bytes":
      return StellarSdk.nativeToScVal(Buffer.from(param.value, "hex"), {
        type: "bytes",
      });

    case "u32":
      return StellarSdk.nativeToScVal(Number(param.value), { type: "u32" });

    case "i32":
      return StellarSdk.nativeToScVal(Number(param.value), { type: "i32" });

    case "vec":
      if (!Array.isArray(param.value)) {
        throw new Error(
          `Expected array for vec type, got ${typeof param.value}`,
        );
      }
      return StellarSdk.nativeToScVal(
        param.value.map((v: ContractParamDto) => buildScVal(v)),
        { type: "vec" },
      );

    default:
      throw new Error(`Unsupported param type: "${param.type}"`);
  }
}
