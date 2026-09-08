import { describe, expect, it } from "vitest";

import { byteLength, transform } from "../src/utils/codec";

function value(result: ReturnType<typeof transform>): string {
  if (!result.ok) throw new Error(`expected ok, got error: ${result.error}`);
  return result.value;
}

describe("codec transforms", () => {
  it("round-trips base64 including multibyte UTF-8", () => {
    const encoded = value(transform("base64", "encode", "héllo · 안녕"));
    expect(encoded).toBe("aMOpbGxvIMK3IOyViOuFlQ==");
    expect(value(transform("base64", "decode", encoded))).toBe("héllo · 안녕");
  });

  it("reports invalid base64 without throwing", () => {
    const result = transform("base64", "decode", "not valid !!!");
    expect(result.ok).toBe(false);
  });

  it("round-trips base64url without padding", () => {
    const encoded = value(transform("base64url", "encode", "subjects?_=~"));
    expect(encoded).not.toContain("=");
    expect(encoded).not.toMatch(/[+/]/);
    expect(value(transform("base64url", "decode", encoded))).toBe("subjects?_=~");
  });

  it("round-trips URL percent-encoding and rejects bad sequences", () => {
    const encoded = value(transform("url", "encode", "a b&c=1"));
    expect(encoded).toBe("a%20b%26c%3D1");
    expect(value(transform("url", "decode", encoded))).toBe("a b&c=1");
    expect(transform("url", "decode", "%zz").ok).toBe(false);
  });

  it("round-trips hex and tolerates spacing and 0x", () => {
    expect(value(transform("hex", "encode", "AB"))).toBe("4142");
    expect(value(transform("hex", "decode", "0x41 0x42"))).toBe("AB");
    expect(transform("hex", "decode", "4").ok).toBe(false);
    expect(transform("hex", "decode", "zz").ok).toBe(false);
  });

  it("encodes and decodes HTML entities", () => {
    expect(value(transform("html", "encode", "<b>&\"'"))).toBe("&lt;b&gt;&amp;&quot;&#39;");
    expect(value(transform("html", "decode", "&lt;b&gt; &#65; &#x41;"))).toBe("<b> A A");
  });

  it("decodes a JWT header and payload without verifying the signature", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
      "eyJzdWIiOiIxMjMiLCJuYW1lIjoiQWRhIn0." +
      "c2ln";
    const decoded = value(transform("jwt", "decode", jwt));
    expect(decoded).toContain('"alg": "HS256"');
    expect(decoded).toContain('"name": "Ada"');
    expect(decoded).toContain("Signature: present (not verified)");
  });

  it("rejects a malformed JWT", () => {
    expect(transform("jwt", "decode", "only-one-part").ok).toBe(false);
  });

  it("treats empty input as empty output", () => {
    expect(value(transform("base64", "encode", ""))).toBe("");
  });

  it("counts UTF-8 bytes", () => {
    expect(byteLength("a")).toBe(1);
    expect(byteLength("é")).toBe(2);
    expect(byteLength("안")).toBe(3);
  });
});
