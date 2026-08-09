import {
  Activity,
  FileSearch,
  FolderKanban,
  Search,
  Radar,
  Settings,
  ShieldCheck,
  TerminalSquare,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import { useUiStore } from "../stores/ui-store";
import { cn } from "../utils/cn";

const commands = [
  { label: "Open overview", hint: "Dashboard", icon: Activity, available: true, path: "/" },
  { label: "Create project", hint: "Phase 2", icon: FolderKanban, available: true, path: "/projects" },
  { label: "Import HTTP request", hint: "Phase 2", icon: TerminalSquare, available: true, path: "/repeater" },
  { label: "Start guarded URL scan", hint: "Phase 9", icon: Radar, available: true, path: "/scans" },
  { label: "Analyze uploaded code", hint: "Phase 10", icon: FileSearch, available: true, path: "/code-analysis" },
  { label: "Review safety policy", hint: "Docs", icon: ShieldCheck, available: true },
  { label: "Open settings", hint: "Phase 7", icon: Settings, available: false },
];

export function CommandMenu() {
  const commandOpen = useUiStore((state) => state.commandOpen);
  const setCommandOpen = useUiStore((state) => state.setCommandOpen);
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        if (commandOpen) setQuery("");
        setCommandOpen(!commandOpen);
      }
      if (event.key === "Escape") {
        setQuery("");
        setCommandOpen(false);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [commandOpen, setCommandOpen]);

  useEffect(() => {
    if (commandOpen) {
      window.requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [commandOpen]);

  const filteredCommands = useMemo(
    () =>
      commands.filter((command) =>
        command.label.toLowerCase().includes(query.toLowerCase()),
      ),
    [query],
  );

  if (!commandOpen) return null;

  const runCommand = (label: string, available: boolean, path?: string) => {
    if (!available) {
      toast.info("This workflow unlocks in the next implementation phase.");
      return;
    }
    setQuery("");
    setCommandOpen(false);
    if (label === "Review safety policy") {
      window.open("/api/docs", "_blank", "noopener,noreferrer");
      return;
    }
    void navigate(path ?? "/");
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/65 px-4 pt-[14vh] backdrop-blur-sm"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          setQuery("");
          setCommandOpen(false);
        }
      }}
    >
      <section
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="w-full max-w-xl overflow-hidden rounded-xl border border-slate-700/80 bg-[#0c121a] shadow-2xl"
      >
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Search className="size-4 text-slate-500" aria-hidden="true" />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search commands…"
            className="h-13 min-w-0 flex-1 bg-transparent text-sm text-slate-100 outline-none placeholder:text-slate-600"
          />
          <button
            type="button"
            onClick={() => {
              setQuery("");
              setCommandOpen(false);
            }}
            aria-label="Close command palette"
            className="rounded p-1 text-slate-500 hover:bg-white/5 hover:text-slate-200"
          >
            <X className="size-4" />
          </button>
        </div>
        <div className="max-h-80 overflow-y-auto p-2">
          {filteredCommands.length === 0 ? (
            <p className="px-3 py-8 text-center text-sm text-slate-500">
              No matching command
            </p>
          ) : (
            filteredCommands.map((command) => (
              <button
                key={command.label}
                type="button"
                onClick={() => runCommand(command.label, command.available, command.path)}
                className={cn(
                  "flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-colors",
                  "hover:bg-white/[0.05] focus-visible:bg-white/[0.05] focus-visible:outline-none",
                )}
              >
                <command.icon className="size-4 text-slate-500" aria-hidden="true" />
                <span className="flex-1 text-sm text-slate-200">{command.label}</span>
                <span className="text-[11px] text-slate-600">{command.hint}</span>
              </button>
            ))
          )}
        </div>
        <footer className="flex items-center gap-4 border-t border-line bg-black/10 px-4 py-2 text-[10px] uppercase tracking-widest text-slate-600">
          <span>↵ Select</span>
          <span>Esc Close</span>
          <span className="ml-auto">Safety-first commands</span>
        </footer>
      </section>
    </div>
  );
}
