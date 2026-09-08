import { ArrowRightLeft, Braces, Check, Copy, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import {
  byteLength,
  CODEC_BY_ID,
  CODECS,
  type CodecId,
  type Direction,
  transform,
} from "../utils/codec";

const textAreaClass =
  "min-h-[220px] w-full resize-y rounded-md border border-line bg-black/20 p-3 font-mono text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-400/50";

function Counts({ value }: { value: string }) {
  return (
    <p className="mt-1 text-[11px] text-slate-600">
      {[...value].length} chars · {byteLength(value)} bytes
    </p>
  );
}

export function EncodingPage() {
  const [codecId, setCodecId] = useState<CodecId>("base64");
  const [direction, setDirection] = useState<Direction>("decode");
  const [input, setInput] = useState("");
  const [copied, setCopied] = useState(false);

  const codec = CODEC_BY_ID[codecId];
  const effectiveDirection: Direction = codec.decodeOnly ? "decode" : direction;

  const result = useMemo(
    () => transform(codec.id, effectiveDirection, input),
    [codec.id, effectiveDirection, input],
  );

  const selectCodec = (id: CodecId) => {
    setCodecId(id);
    setCopied(false);
  };

  const swap = () => {
    if (!result.ok || result.value === "") return;
    setInput(result.value);
    setDirection((current) => (current === "encode" ? "decode" : "encode"));
    setCopied(false);
  };

  const copyOutput = async () => {
    if (!result.ok || result.value === "") return;
    try {
      await navigator.clipboard.writeText(result.value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not copy the output");
    }
  };

  return (
    <div className="mx-auto max-w-[1200px] space-y-6 p-4 sm:p-6 lg:p-8">
      <header>
        <p className="flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-cyan-300">
          <Braces className="size-4" /> Encoding Workbench
        </p>
        <h1 className="mt-2 text-2xl font-semibold text-slate-100">Encode & decode</h1>
        <p className="mt-1 text-sm text-slate-500">
          Transform payloads and tokens between common encodings. Everything runs in your
          browser.
        </p>
      </header>

      <div className="flex items-start gap-3 rounded-md border border-emerald-500/20 bg-emerald-500/5 p-3 text-sm text-emerald-200/90">
        <ShieldCheck className="mt-0.5 size-4 shrink-0" />
        <p>
          This tool is client-side only. Input is never sent to the backend, so secrets and
          tokens stay on this device.
        </p>
      </div>

      <Card>
        <CardHeader className="gap-3">
          <CardTitle className="text-sm text-slate-200">Transform</CardTitle>
          <div className="flex flex-wrap items-center gap-2">
            {CODECS.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => selectCodec(item.id)}
                title={item.hint}
                className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                  item.id === codecId
                    ? "border-cyan-400/40 bg-cyan-400/10 text-cyan-200"
                    : "border-line bg-black/20 text-slate-300 hover:bg-white/[0.04]"
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            {codec.decodeOnly ? (
              <Badge tone="neutral">Decode only</Badge>
            ) : (
              <div className="inline-flex rounded-md border border-line p-0.5" role="group" aria-label="Direction">
                {(["encode", "decode"] as const).map((value) => (
                  <button
                    key={value}
                    type="button"
                    aria-pressed={direction === value}
                    onClick={() => {
                      setDirection(value);
                      setCopied(false);
                    }}
                    className={`rounded px-3 py-1 text-xs capitalize transition-colors ${
                      direction === value ? "bg-cyan-400/15 text-cyan-200" : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {value}
                  </button>
                ))}
              </div>
            )}
            <span className="text-xs text-slate-500">{codec.hint}</span>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 lg:grid-cols-[1fr_auto_1fr]">
            <div>
              <label className="text-[11px] uppercase tracking-widest text-slate-500" htmlFor="codec-input">
                Input
              </label>
              <textarea
                id="codec-input"
                aria-label="Input"
                spellCheck={false}
                className={`mt-1.5 ${textAreaClass}`}
                placeholder="Paste text, a token, or a payload…"
                value={input}
                onChange={(event) => {
                  setInput(event.target.value);
                  setCopied(false);
                }}
              />
              <Counts value={input} />
            </div>

            <div className="flex items-center justify-center lg:flex-col lg:gap-2">
              <Button
                variant="ghost"
                size="sm"
                aria-label="Swap output into input"
                disabled={!result.ok || result.value === ""}
                onClick={swap}
              >
                <ArrowRightLeft className="size-4" />
              </Button>
            </div>

            <div>
              <div className="flex items-center justify-between">
                <label className="text-[11px] uppercase tracking-widest text-slate-500" htmlFor="codec-output">
                  Output
                </label>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label="Copy output"
                  disabled={!result.ok || result.value === ""}
                  onClick={() => void copyOutput()}
                >
                  {copied ? <Check className="size-4 text-emerald-300" /> : <Copy className="size-4" />}
                </Button>
              </div>
              {result.ok ? (
                <textarea
                  id="codec-output"
                  aria-label="Output"
                  readOnly
                  spellCheck={false}
                  className={`mt-1.5 ${textAreaClass}`}
                  value={result.value}
                />
              ) : (
                <div
                  id="codec-output"
                  role="alert"
                  className="mt-1.5 flex min-h-[220px] items-start rounded-md border border-red-500/25 bg-red-500/5 p-3 text-sm text-red-300"
                >
                  {result.error}
                </div>
              )}
              {result.ok ? <Counts value={result.value} /> : null}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
