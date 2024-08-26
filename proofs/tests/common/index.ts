import 'mocha';
import { Circomkit, WitnessTester } from "circomkit";

export const circomkit = new Circomkit({
  verbose: false,
});

export { WitnessTester };

function stringifyValue(value: any): string {
  if (Array.isArray(value)) {
    return `[${value.map(stringifyValue).join(', ')}]`;
  }
  if (typeof value === 'object' && value !== null) {
    return `{${Object.entries(value).map(([k, v]) => `${k}: ${stringifyValue(v)}`).join(', ')}}`;
  }
  return String(value);
}

export function generateDescription(input: any): string {
  return Object.entries(input)
    .map(([key, value]) => `${key} = ${stringifyValue(value)}`)
    .join(", ");
}