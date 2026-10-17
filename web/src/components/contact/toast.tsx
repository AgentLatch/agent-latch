import { useCallback, useEffect, useRef, useState } from "react";
import { cn } from "../../lib/cn";

/** A single toast notification. */
export type ToastKind = "success" | "error";

export interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  message?: string;
}

/** How long a toast stays on screen before auto-dismissing (ms). */
const AUTO_DISMISS_MS = 5000;

/**
 * Tiny self-contained toast manager. Kept local to the contact feature so it
 * needs no app-wide provider: a page calls `useToasts()` and renders
 * `<ToastViewport />` with the returned state.
 */
export function useToasts() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((t) => t.id !== id));
  }, []);

  const push = useCallback((kind: ToastKind, title: string, message?: string) => {
    const id = nextId.current++;
    setToasts((current) => [...current, { id, kind, title, message }]);
    return id;
  }, []);

  return { toasts, push, dismiss };
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" aria-hidden="true">
      <path d="m5 13 4 4L19 7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function AlertIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" aria-hidden="true">
      <path d="M12 8v5M12 16.5v.5" strokeWidth="2" strokeLinecap="round" />
      <circle cx="12" cy="12" r="9" strokeWidth="1.8" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" aria-hidden="true">
      <path d="M6 6l12 12M18 6 6 18" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

function ToastCard({ toast, onDismiss }: { toast: Toast; onDismiss: (id: number) => void }) {
  // Auto-dismiss after a delay; cleared if the toast unmounts first.
  useEffect(() => {
    const timer = window.setTimeout(() => onDismiss(toast.id), AUTO_DISMISS_MS);
    return () => window.clearTimeout(timer);
  }, [toast.id, onDismiss]);

  const success = toast.kind === "success";

  return (
    <div
      role="status"
      aria-live={success ? "polite" : "assertive"}
      className={cn(
        "toast-in pointer-events-auto flex w-full items-start gap-3 rounded-2xl border bg-surface p-4 backdrop-blur-md",
        success
          ? "border-risk-low/40 shadow-neon-cyan"
          : "border-risk-high/40 shadow-[0_0_20px_rgba(244,63,94,0.45)]",
      )}
    >
      <span
        className={cn(
          "grid h-9 w-9 shrink-0 place-items-center rounded-full",
          success ? "bg-risk-low/15 text-risk-low" : "bg-risk-high/15 text-risk-high",
        )}
      >
        {success ? <CheckIcon /> : <AlertIcon />}
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-white">{toast.title}</p>
        {toast.message && <p className="mt-0.5 text-xs text-slate-400">{toast.message}</p>}
      </div>
      <button
        type="button"
        onClick={() => onDismiss(toast.id)}
        className="shrink-0 rounded-lg p-1 text-slate-500 transition-colors hover:bg-white/5 hover:text-white"
        aria-label="Dismiss notification"
      >
        <CloseIcon />
      </button>
    </div>
  );
}

/** Fixed, stacked container for active toasts (bottom-right on desktop, full-width on mobile). */
export function ToastViewport({
  toasts,
  onDismiss,
}: {
  toasts: Toast[];
  onDismiss: (id: number) => void;
}) {
  return (
    <div className="pointer-events-none fixed inset-x-4 bottom-4 z-50 flex flex-col gap-3 sm:inset-x-auto sm:right-6 sm:bottom-6 sm:w-96">
      {toasts.map((toast) => (
        <ToastCard key={toast.id} toast={toast} onDismiss={onDismiss} />
      ))}
    </div>
  );
}
