import { useState } from "react";
import { Button } from "../ui";
import { cn } from "../../lib/cn";
import type { ToastKind } from "./toast";

/** Select options come from the ticket so the labels stay stable. */
const AGENT_STACKS = ["LangChain", "AutoGen", "CrewAI", "Custom Python"] as const;
const SUBJECT_TYPES = [
  "Custom Scanner Rules",
  "Enterprise CI/CD Integration",
  "Open Source Contribution",
  "General Query",
] as const;

type Field = "fullName" | "workEmail" | "company" | "agentStack" | "subjectType" | "message";

interface FormState {
  fullName: string;
  workEmail: string;
  company: string;
  agentStack: string;
  subjectType: string;
  message: string;
}

const EMPTY: FormState = {
  fullName: "",
  workEmail: "",
  company: "",
  agentStack: "",
  subjectType: "",
  message: "",
};

type Errors = Partial<Record<Field, string>>;

// Pragmatic email shape check — not RFC-exhaustive, just enough to catch typos.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Validate the whole form and return a map of field -> error message. */
function validate(values: FormState): Errors {
  const errors: Errors = {};
  if (values.fullName.trim().length < 2) errors.fullName = "Please enter your full name.";
  if (!values.workEmail.trim()) errors.workEmail = "Work email is required.";
  else if (!EMAIL_RE.test(values.workEmail.trim()))
    errors.workEmail = "Enter a valid email address.";
  if (!values.company.trim()) errors.company = "Company or organization is required.";
  if (!values.agentStack) errors.agentStack = "Select the agent stack you use.";
  if (!values.subjectType) errors.subjectType = "Select a subject type.";
  if (values.message.trim().length < 10)
    errors.message = "Please add a few more details (10+ characters).";
  return errors;
}

const labelClass = "mb-1.5 block text-sm font-medium text-slate-200";
const controlBase =
  "w-full rounded-xl border bg-white/5 px-3.5 py-2.5 text-sm text-slate-100 transition-colors " +
  "placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-accent/60";

function controlClass(invalid: boolean): string {
  return cn(
    controlBase,
    invalid
      ? "border-risk-high/60 focus:ring-risk-high/50"
      : "border-white/10 focus:border-accent/50",
  );
}

interface ContactFormProps {
  /** Raise a toaster notification from the parent page. */
  onNotify: (kind: ToastKind, title: string, message?: string) => void;
}

export function ContactForm({ onNotify }: ContactFormProps) {
  const [values, setValues] = useState<FormState>(EMPTY);
  const [errors, setErrors] = useState<Errors>({});
  const [touched, setTouched] = useState<Partial<Record<Field, boolean>>>({});
  const [submitting, setSubmitting] = useState(false);

  function setField(field: Field, value: string) {
    setValues((prev) => ({ ...prev, [field]: value }));
    // Re-validate a field the user has already interacted with, so errors clear live.
    if (touched[field]) {
      setErrors((prev) => ({ ...prev, [field]: validate({ ...values, [field]: value })[field] }));
    }
  }

  function handleBlur(field: Field) {
    setTouched((prev) => ({ ...prev, [field]: true }));
    setErrors((prev) => ({ ...prev, [field]: validate(values)[field] }));
  }

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const nextErrors = validate(values);
    setErrors(nextErrors);
    setTouched({
      fullName: true,
      workEmail: true,
      company: true,
      agentStack: true,
      subjectType: true,
      message: true,
    });

    if (Object.keys(nextErrors).length > 0) {
      onNotify("error", "Please fix the highlighted fields", "A few details still need attention.");
      return;
    }

    // No backend yet: this is a static-site form, so we acknowledge locally
    // rather than claim a message was delivered to a server.
    setSubmitting(true);
    window.setTimeout(() => {
      setSubmitting(false);
      onNotify(
        "success",
        "Inquiry captured",
        `Thanks, ${values.fullName.trim().split(" ")[0]} — we'll follow up at ${values.workEmail.trim()}.`,
      );
      setValues(EMPTY);
      setTouched({});
      setErrors({});
    }, 800);
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="space-y-5">
      <div className="grid gap-5 sm:grid-cols-2">
        <div>
          <label htmlFor="fullName" className={labelClass}>
            Full name
          </label>
          <input
            id="fullName"
            type="text"
            autoComplete="name"
            value={values.fullName}
            onChange={(e) => setField("fullName", e.target.value)}
            onBlur={() => handleBlur("fullName")}
            className={controlClass(Boolean(errors.fullName))}
            placeholder="Ada Lovelace"
            aria-invalid={Boolean(errors.fullName)}
            aria-describedby={errors.fullName ? "fullName-error" : undefined}
          />
          <FieldError id="fullName-error" message={errors.fullName} />
        </div>

        <div>
          <label htmlFor="workEmail" className={labelClass}>
            Work email
          </label>
          <input
            id="workEmail"
            type="email"
            autoComplete="email"
            value={values.workEmail}
            onChange={(e) => setField("workEmail", e.target.value)}
            onBlur={() => handleBlur("workEmail")}
            className={controlClass(Boolean(errors.workEmail))}
            placeholder="you@company.com"
            aria-invalid={Boolean(errors.workEmail)}
            aria-describedby={errors.workEmail ? "workEmail-error" : undefined}
          />
          <FieldError id="workEmail-error" message={errors.workEmail} />
        </div>
      </div>

      <div>
        <label htmlFor="company" className={labelClass}>
          Company / organization
        </label>
        <input
          id="company"
          type="text"
          autoComplete="organization"
          value={values.company}
          onChange={(e) => setField("company", e.target.value)}
          onBlur={() => handleBlur("company")}
          className={controlClass(Boolean(errors.company))}
          placeholder="Acme AI"
          aria-invalid={Boolean(errors.company)}
          aria-describedby={errors.company ? "company-error" : undefined}
        />
        <FieldError id="company-error" message={errors.company} />
      </div>

      <div className="grid gap-5 sm:grid-cols-2">
        <div>
          <label htmlFor="agentStack" className={labelClass}>
            Agent stack
          </label>
          <select
            id="agentStack"
            value={values.agentStack}
            onChange={(e) => setField("agentStack", e.target.value)}
            onBlur={() => handleBlur("agentStack")}
            className={controlClass(Boolean(errors.agentStack))}
            aria-invalid={Boolean(errors.agentStack)}
            aria-describedby={errors.agentStack ? "agentStack-error" : undefined}
          >
            <option value="">Select a stack…</option>
            {AGENT_STACKS.map((stack) => (
              <option key={stack} value={stack}>
                {stack}
              </option>
            ))}
          </select>
          <FieldError id="agentStack-error" message={errors.agentStack} />
        </div>

        <div>
          <label htmlFor="subjectType" className={labelClass}>
            Subject type
          </label>
          <select
            id="subjectType"
            value={values.subjectType}
            onChange={(e) => setField("subjectType", e.target.value)}
            onBlur={() => handleBlur("subjectType")}
            className={controlClass(Boolean(errors.subjectType))}
            aria-invalid={Boolean(errors.subjectType)}
            aria-describedby={errors.subjectType ? "subjectType-error" : undefined}
          >
            <option value="">Select a subject…</option>
            {SUBJECT_TYPES.map((subject) => (
              <option key={subject} value={subject}>
                {subject}
              </option>
            ))}
          </select>
          <FieldError id="subjectType-error" message={errors.subjectType} />
        </div>
      </div>

      <div>
        <label htmlFor="message" className={labelClass}>
          Message
        </label>
        <textarea
          id="message"
          rows={5}
          value={values.message}
          onChange={(e) => setField("message", e.target.value)}
          onBlur={() => handleBlur("message")}
          className={cn(controlClass(Boolean(errors.message)), "resize-y")}
          placeholder="Tell us about your agents, pipeline, or how you'd like to contribute…"
          aria-invalid={Boolean(errors.message)}
          aria-describedby={errors.message ? "message-error" : undefined}
        />
        <FieldError id="message-error" message={errors.message} />
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" variant="glow" size="lg" disabled={submitting}>
          {submitting ? "Sending…" : "Submit inquiry"}
        </Button>
        <p className="text-xs text-slate-500">
          Static demo form — submissions aren't sent to a server yet.
        </p>
      </div>
    </form>
  );
}

function FieldError({ id, message }: { id: string; message?: string }) {
  if (!message) return null;
  return (
    <p id={id} className="mt-1.5 text-xs text-risk-high">
      {message}
    </p>
  );
}
