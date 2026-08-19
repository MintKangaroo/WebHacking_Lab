import {
  Activity,
  BookOpenText,
  Braces,
  ChevronLeft,
  CircleDot,
  FileCode2,
  FileText,
  FlaskConical,
  FolderKanban,
  GitBranch,
  Menu,
  PanelLeftClose,
  Radar,
  Search,
  Settings,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";

import { CommandMenu } from "../components/command-menu";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "../components/ui/tooltip";
import { useUiStore } from "../stores/ui-store";
import { cn } from "../utils/cn";

type NavigationItem = {
  label: string;
  icon: LucideIcon;
  available: boolean;
  path?: string;
};

const primaryNavigation: NavigationItem[] = [
  { label: "Overview", icon: Activity, available: true, path: "/" },
  { label: "Projects", icon: FolderKanban, available: true, path: "/projects" },
  { label: "HTTP Repeater", icon: TerminalSquare, available: true, path: "/repeater" },
  { label: "URL Scanner", icon: Radar, available: true, path: "/scans" },
  { label: "Code Analysis", icon: FileCode2, available: true, path: "/code-analysis" },
  { label: "Analyzer", icon: Braces, available: true, path: "/analyzer" },
  { label: "Attack Flow", icon: GitBranch, available: false },
];

const secondaryNavigation: NavigationItem[] = [
  { label: "CTF Workspace", icon: BookOpenText, available: false },
  { label: "Local Labs", icon: FlaskConical, available: true, path: "/labs" },
  { label: "Reports", icon: FileText, available: true, path: "/reports" },
];

function NavigationButton({
  item,
  collapsed,
}: {
  item: NavigationItem;
  collapsed: boolean;
}) {
  const sharedClass = cn(
    "group flex h-9 w-full items-center gap-3 rounded-md px-3 text-sm transition-colors",
    !item.available && "cursor-not-allowed text-slate-600",
    collapsed && "justify-center px-0",
  );
  const children = (
    <>
      <item.icon className="size-4 shrink-0" aria-hidden="true" />
      {!collapsed && <span className="truncate">{item.label}</span>}
      {!collapsed && !item.available && (
        <span className="ml-auto text-[9px] uppercase tracking-wider text-slate-700">
          Soon
        </span>
      )}
    </>
  );
  const content = item.available && item.path ? (
    <NavLink
      to={item.path}
      end={item.path === "/"}
      className={({ isActive }) =>
        cn(
          sharedClass,
          isActive
            ? "bg-cyan-400/[0.09] text-cyan-300"
            : "text-slate-500 hover:bg-white/[0.04] hover:text-slate-200",
        )
      }
    >
      {children}
    </NavLink>
  ) : (
    <button
      type="button"
      disabled={!item.available}
      className={sharedClass}
    >
      {children}
    </button>
  );

  if (!collapsed) return content;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{content}</TooltipTrigger>
      <TooltipContent side="right">{item.label}</TooltipContent>
    </Tooltip>
  );
}

function Sidebar() {
  const collapsed = useUiStore((state) => state.sidebarCollapsed);
  const toggleSidebar = useUiStore((state) => state.toggleSidebar);

  return (
    <aside
      className={cn(
        "fixed inset-y-0 left-0 z-30 hidden border-r border-line bg-[#090d13]/95 transition-[width] duration-200 lg:flex lg:flex-col",
        collapsed ? "w-[72px]" : "w-60",
      )}
    >
      <div
        className={cn(
          "flex h-16 items-center border-b border-line px-4",
          collapsed ? "justify-center" : "gap-3",
        )}
      >
        <div className="relative grid size-8 shrink-0 place-items-center rounded-lg border border-cyan-400/20 bg-cyan-400/[0.08]">
          <ShieldCheck className="size-[18px] text-cyan-300" />
          <span className="absolute -right-0.5 -top-0.5 size-2 rounded-full border-2 border-[#090d13] bg-emerald-400" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold tracking-tight text-slate-50">
              WebHacking Lab
            </p>
            <p className="text-[10px] uppercase tracking-[0.18em] text-slate-600">
              Security workspace
            </p>
          </div>
        )}
      </div>

      <nav aria-label="Primary" className="flex-1 space-y-6 overflow-y-auto p-3">
        <div>
          {!collapsed && (
            <p className="mb-2 px-3 text-[10px] font-medium uppercase tracking-[0.16em] text-slate-600">
              Analyze
            </p>
          )}
          <div className="space-y-1">
            {primaryNavigation.map((item) => (
              <NavigationButton key={item.label} item={item} collapsed={collapsed} />
            ))}
          </div>
        </div>
        <div>
          {!collapsed && (
            <p className="mb-2 px-3 text-[10px] font-medium uppercase tracking-[0.16em] text-slate-600">
              Learn & report
            </p>
          )}
          <div className="space-y-1">
            {secondaryNavigation.map((item) => (
              <NavigationButton key={item.label} item={item} collapsed={collapsed} />
            ))}
          </div>
        </div>
      </nav>

      <div className="border-t border-line p-3">
        <NavigationButton
          item={{ label: "Settings", icon: Settings, available: false }}
          collapsed={collapsed}
        />
        <button
          type="button"
          onClick={toggleSidebar}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className={cn(
            "mt-2 flex h-9 w-full items-center gap-3 rounded-md px-3 text-sm text-slate-500 hover:bg-white/[0.04] hover:text-slate-300",
            collapsed && "justify-center px-0",
          )}
        >
          <PanelLeftClose
            className={cn("size-4", collapsed && "rotate-180")}
            aria-hidden="true"
          />
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  );
}

function Topbar() {
  const collapsed = useUiStore((state) => state.sidebarCollapsed);
  const setCommandOpen = useUiStore((state) => state.setCommandOpen);

  return (
    <header
      className={cn(
        "fixed inset-x-0 top-0 z-20 flex h-16 items-center border-b border-line bg-canvas/85 px-4 backdrop-blur-xl transition-[padding] sm:px-6",
        collapsed ? "lg:pl-[96px]" : "lg:pl-[264px]",
      )}
    >
      <button
        type="button"
        className="mr-3 rounded-md p-2 text-slate-400 hover:bg-white/5 lg:hidden"
        aria-label="Open navigation"
      >
        <Menu className="size-5" />
      </button>
      <div className="hidden min-w-0 items-center gap-2 text-sm sm:flex">
        <span className="text-slate-600">Workspace</span>
        <ChevronLeft className="size-3 rotate-180 text-slate-700" />
        <span className="truncate text-slate-300">Local Security Workspace</span>
      </div>
      <Button
        type="button"
        variant="secondary"
        onClick={() => setCommandOpen(true)}
        className="mx-auto h-9 w-full max-w-sm justify-start text-slate-500 sm:absolute sm:left-1/2 sm:-translate-x-1/2"
      >
        <Search className="size-3.5" aria-hidden="true" />
        <span className="flex-1 text-left">Search or run a command</span>
        <kbd className="rounded border border-slate-700 bg-black/20 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">
          ⌘K
        </kbd>
      </Button>
      <div className="ml-auto hidden items-center gap-3 sm:flex">
        <Badge tone="safe">
          <CircleDot className="size-2.5 fill-current" />
          Safety gated
        </Badge>
        <div
          className="grid size-8 place-items-center rounded-full border border-violet-400/20 bg-violet-400/10 text-[11px] font-semibold text-violet-200"
          aria-label="Local user profile"
        >
          MK
        </div>
      </div>
    </header>
  );
}

export function AppShell() {
  const collapsed = useUiStore((state) => state.sidebarCollapsed);

  return (
    <div className="min-h-screen bg-canvas text-slate-200">
      <Sidebar />
      <Topbar />
      <main
        className={cn(
          "min-h-screen pt-16 transition-[padding] duration-200",
          collapsed ? "lg:pl-[72px]" : "lg:pl-60",
        )}
      >
        <Outlet />
      </main>
      <CommandMenu />
    </div>
  );
}
