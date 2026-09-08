// Client-side encoding/decoding transforms for the Encoding Workbench.
//
// Everything here runs in the browser; input never leaves the page, which keeps
// tokens and payloads local. Each transform returns a discriminated result so the UI
// can show a friendly message instead of throwing on malformed input.

export type CodecResult = { ok: true; value: string } | { ok: false; error: string };
export type Direction = "encode" | "decode";
export type CodecId = "base64" | "base64url" | "url" | "hex" | "html" | "jwt";

export type CodecMeta = {
  id: CodecId;
  label: string;
  hint: string;
  /** JWT is inspection-only; there is no meaningful "encode" direction. */
  decodeOnly?: boolean;
};

export const CODECS: CodecMeta[] = [
  { id: "base64", label: "Base64", hint: "Standard base64 (RFC 4648)." },
  { id: "base64url", label: "Base64URL", hint: "URL-safe base64 with -_ and no padding." },
  { id: "url", label: "URL", hint: "Percent-encoding (encodeURIComponent)." },
  { id: "hex", label: "Hex", hint: "UTF-8 bytes as hexadecimal." },
  { id: "html", label: "HTML entities", hint: "Named and numeric HTML entities." },
  { id: "jwt", label: "JWT decode", hint: "Decode header and payload (no signature check).", decodeOnly: true },
];

/** Codec metadata keyed by id, so a known CodecId always resolves to a codec. */
export const CODEC_BY_ID = Object.fromEntries(
  CODECS.map((codec) => [codec.id, codec]),
) as Record<CodecId, CodecMeta>;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function ok(value: string): CodecResult {
  return { ok: true, value };
}

function fail(error: string): CodecResult {
  return { ok: false, error };
}

function bytesToBinary(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return binary;
}

function binaryToBytes(binary: string): Uint8Array {
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function decodeUtf8(bytes: Uint8Array): CodecResult {
  try {
    return ok(decoder.decode(bytes));
  } catch {
    return fail("Bytes are not valid UTF-8 text.");
  }
}

function base64Encode(input: string): CodecResult {
  return ok(btoa(bytesToBinary(encoder.encode(input))));
}

function base64Decode(input: string): CodecResult {
  const trimmed = input.trim();
  if (trimmed === "") return ok("");
  try {
    return decodeUtf8(binaryToBytes(atob(trimmed)));
  } catch {
    return fail("Input is not valid base64.");
  }
}

function base64UrlEncode(input: string): CodecResult {
  const standard = base64Encode(input);
  if (!standard.ok) return standard;
  return ok(standard.value.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
}

function base64UrlDecode(input: string): CodecResult {
  const trimmed = input.trim();
  if (trimmed === "") return ok("");
  if (/[^A-Za-z0-9\-_=]/.test(trimmed)) return fail("Input is not valid base64url.");
  const padded = trimmed.replace(/-/g, "+").replace(/_/g, "/").padEnd(
    Math.ceil(trimmed.length / 4) * 4,
    "=",
  );
  return base64Decode(padded);
}

function urlEncode(input: string): CodecResult {
  return ok(encodeURIComponent(input));
}

function urlDecode(input: string): CodecResult {
  try {
    return ok(decodeURIComponent(input));
  } catch {
    return fail("Input has an invalid percent-encoding sequence.");
  }
}

function hexEncode(input: string): CodecResult {
  return ok(
    Array.from(encoder.encode(input))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join(""),
  );
}

function hexDecode(input: string): CodecResult {
  const cleaned = input.replace(/0x/gi, "").replace(/[\s:]/g, "");
  if (cleaned === "") return ok("");
  if (cleaned.length % 2 !== 0) return fail("Hex input must have an even number of digits.");
  if (/[^0-9a-fA-F]/.test(cleaned)) return fail("Hex input contains a non-hex character.");
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = parseInt(cleaned.slice(index * 2, index * 2 + 2), 16);
  }
  return decodeUtf8(bytes);
}

const HTML_ENCODE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

const HTML_NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
};

function htmlEncode(input: string): CodecResult {
  return ok(input.replace(/[&<>"']/g, (char) => HTML_ENCODE_MAP[char] ?? char));
}

function htmlDecode(input: string): CodecResult {
  const value = input.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (match, body: string) => {
    if (body[0] === "#") {
      const codePoint =
        body[1] === "x" || body[1] === "X"
          ? parseInt(body.slice(2), 16)
          : parseInt(body.slice(1), 10);
      if (Number.isNaN(codePoint) || codePoint < 0 || codePoint > 0x10ffff) return match;
      try {
        return String.fromCodePoint(codePoint);
      } catch {
        return match;
      }
    }
    return HTML_NAMED_ENTITIES[body] ?? match;
  });
  return ok(value);
}

function jwtDecode(input: string): CodecResult {
  const parts = input.trim().split(".");
  const header = parts[0];
  const payload = parts[1];
  if (!header || !payload) {
    return fail("A JWT needs at least a header and a payload separated by dots.");
  }
  const sections: string[] = [];
  for (const [name, segment] of [
    ["Header", header],
    ["Payload", payload],
  ] as const) {
    const decoded = base64UrlDecode(segment);
    if (!decoded.ok) return fail(`${name} is not valid base64url.`);
    try {
      sections.push(`// ${name}\n${JSON.stringify(JSON.parse(decoded.value), null, 2)}`);
    } catch {
      return fail(`${name} is not valid JSON.`);
    }
  }
  const signature = parts.length >= 3 && parts[2] ? "present (not verified)" : "none";
  sections.push(`// Signature: ${signature}`);
  return ok(sections.join("\n\n"));
}

const TRANSFORMS: Record<CodecId, { encode: (input: string) => CodecResult; decode: (input: string) => CodecResult }> = {
  base64: { encode: base64Encode, decode: base64Decode },
  base64url: { encode: base64UrlEncode, decode: base64UrlDecode },
  url: { encode: urlEncode, decode: urlDecode },
  hex: { encode: hexEncode, decode: hexDecode },
  html: { encode: htmlEncode, decode: htmlDecode },
  jwt: { encode: () => fail("JWT is decode-only."), decode: jwtDecode },
};

/** Run one codec in one direction, returning a friendly error instead of throwing. */
export function transform(id: CodecId, direction: Direction, input: string): CodecResult {
  if (input === "") return ok("");
  return TRANSFORMS[id][direction](input);
}

/** UTF-8 byte length of a string, shown alongside character count in the UI. */
export function byteLength(value: string): number {
  return encoder.encode(value).length;
}
