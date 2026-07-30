import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";

import { cn } from "../../utils/cn";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium",
  {
    variants: {
      tone: {
        neutral: "border-slate-700 bg-slate-800/70 text-slate-300",
        safe: "border-emerald-500/25 bg-emerald-500/10 text-emerald-300",
        warning: "border-amber-500/25 bg-amber-500/10 text-amber-300",
        critical: "border-red-500/25 bg-red-500/10 text-red-300",
        accent: "border-cyan-500/25 bg-cyan-500/10 text-cyan-300",
      },
    },
    defaultVariants: {
      tone: "neutral",
    },
  },
);

type BadgeProps = HTMLAttributes<HTMLSpanElement> &
  VariantProps<typeof badgeVariants>;

export function Badge({ className, tone, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ tone }), className)} {...props} />
  );
}
