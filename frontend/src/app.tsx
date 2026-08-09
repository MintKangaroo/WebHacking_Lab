import {
  QueryClient,
  QueryClientProvider,
  QueryErrorResetBoundary,
} from "@tanstack/react-query";
import { Component, type ErrorInfo, type ReactNode } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Toaster } from "sonner";

import { Button } from "./components/ui/button";
import { TooltipProvider } from "./components/ui/tooltip";
import { AppShell } from "./layouts/app-shell";
import { DashboardPage } from "./pages/dashboard-page";
import { CodeAnalysisPage } from "./pages/code-analysis-page";
import { ProjectPage } from "./pages/project-page";
import { ProjectsPage } from "./pages/projects-page";
import { RepeaterPage } from "./pages/repeater-page";
import { ScansPage } from "./pages/scans-page";

type ErrorBoundaryProps = {
  children: ReactNode;
  onReset: () => void;
};

type ErrorBoundaryState = {
  hasError: boolean;
};

class ApplicationErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  public state: ErrorBoundaryState = { hasError: false };

  public static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true };
  }

  public componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Dashboard render failed", error, info.componentStack);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <main className="grid min-h-screen place-items-center bg-canvas p-6 text-center">
          <div>
            <p className="font-mono text-xs uppercase tracking-widest text-red-400">
              Dashboard unavailable
            </p>
            <h1 className="mt-3 text-xl font-semibold text-slate-100">
              The API response could not be loaded.
            </h1>
            <p className="mt-2 text-sm text-slate-500">
              Confirm that the backend is healthy, then try again.
            </p>
            <Button
              className="mt-5"
              onClick={() => {
                this.setState({ hasError: false });
                this.props.onReset();
              }}
            >
              Retry
            </Button>
          </div>
        </main>
      );
    }
    return this.props.children;
  }
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={250}>
        <QueryErrorResetBoundary>
          {({ reset }) => (
            <ApplicationErrorBoundary onReset={reset}>
              <BrowserRouter>
                <Routes>
                  <Route element={<AppShell />}>
                    <Route index element={<DashboardPage />} />
                    <Route path="projects" element={<ProjectsPage />} />
                    <Route path="projects/:projectId" element={<ProjectPage />} />
                    <Route path="repeater" element={<RepeaterPage />} />
                    <Route path="analyzer" element={<RepeaterPage />} />
                    <Route path="scans" element={<ScansPage />} />
                    <Route path="code-analysis" element={<CodeAnalysisPage />} />
                    <Route path="*" element={<Navigate to="/" replace />} />
                  </Route>
                </Routes>
              </BrowserRouter>
            </ApplicationErrorBoundary>
          )}
        </QueryErrorResetBoundary>
        <Toaster theme="dark" position="bottom-right" />
      </TooltipProvider>
    </QueryClientProvider>
  );
}
