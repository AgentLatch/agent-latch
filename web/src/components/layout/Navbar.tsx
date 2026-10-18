import { useEffect, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { cn } from "../../lib/cn";
import { NAV_ITEMS } from "./navItems";

function linkClass({ isActive }: { isActive: boolean }): string {
  return cn(
    "relative rounded-lg px-3 py-2 text-sm font-medium transition-colors",
    isActive ? "text-white" : "text-slate-400 hover:text-slate-100",
    // Active route highlight: a soft violet pill with a neon underline.
    isActive && "bg-white/5",
  );
}

function Brand() {
  return (
    <NavLink to="/" className="flex items-center gap-2.5" aria-label="AgentLatch home">
      <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent shadow-neon">
        <svg viewBox="0 0 24 24" className="h-5 w-5 text-white" fill="none" aria-hidden="true">
          <path
            d="M12 2 4 6v6c0 5 3.4 7.7 8 10 4.6-2.3 8-5 8-10V6l-8-4Z"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinejoin="round"
          />
        </svg>
      </span>
      <span className="text-sm font-semibold tracking-wide text-white">
        Agent<span className="text-accent-cyan-bright">Latch</span>
      </span>
    </NavLink>
  );
}

function MenuIcon({ open }: { open: boolean }) {
  return (
    <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor" aria-hidden="true">
      {open ? (
        <path d="M6 6l12 12M18 6 6 18" strokeWidth="1.8" strokeLinecap="round" />
      ) : (
        <path d="M4 7h16M4 12h16M4 17h16" strokeWidth="1.8" strokeLinecap="round" />
      )}
    </svg>
  );
}

export function Navbar() {
  const [open, setOpen] = useState(false);
  const location = useLocation();

  // Close the mobile drawer whenever the route changes.
  useEffect(() => {
    setOpen(false);
  }, [location.pathname]);

  return (
    <header className="sticky top-0 z-40 border-b border-white/10 bg-base/80 backdrop-blur-md">
      <nav className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6">
        <Brand />

        {/* Desktop nav */}
        <div className="hidden items-center gap-1 md:flex">
          {NAV_ITEMS.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.to === "/"} className={linkClass}>
              {item.label}
            </NavLink>
          ))}
        </div>

        {/* Mobile toggle */}
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="rounded-lg p-2 text-slate-300 hover:bg-white/5 hover:text-white md:hidden"
          aria-label="Toggle navigation menu"
          aria-expanded={open}
          aria-controls="mobile-menu"
        >
          <MenuIcon open={open} />
        </button>
      </nav>

      {/* Mobile drawer */}
      <div
        id="mobile-menu"
        className={cn(
          "overflow-hidden border-t border-white/10 bg-base/95 backdrop-blur-md md:hidden",
          "transition-[max-height] duration-300 ease-in-out",
          open ? "max-h-72" : "max-h-0 border-t-0",
        )}
      >
        <div className="space-y-1 px-4 py-3">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                cn(
                  "block rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                  isActive ? "bg-accent/15 text-white" : "text-slate-300 hover:bg-white/5",
                )
              }
            >
              {item.label}
            </NavLink>
          ))}
        </div>
      </div>
    </header>
  );
}
