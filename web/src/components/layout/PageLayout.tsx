import type { ReactNode } from "react";
import { Navbar } from "./Navbar";

export interface PageLayoutProps {
  children: ReactNode;
}

/** App shell: sticky navigation plus a centered, width-constrained content area. */
export function PageLayout({ children }: PageLayoutProps) {
  return (
    <div className="flex min-h-full flex-col overflow-x-hidden">
      <Navbar />
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-6 sm:py-10">{children}</main>
      <footer className="border-t border-white/10 py-6 text-center text-xs text-slate-500">
        AgentLatch Console · Invicti design system
      </footer>
    </div>
  );
}
