import { GlassCard, SectionHeader } from "../components/ui";
import { ContactForm } from "../components/contact/ContactForm";
import { QuickLinks } from "../components/contact/QuickLinks";
import { ToastViewport, useToasts } from "../components/contact/toast";

export function Contact() {
  const { toasts, push, dismiss } = useToasts();

  return (
    <div className="space-y-8">
      <SectionHeader
        eyebrow="Contact"
        title="Partner with AgentLatch"
        subtitle="Request a custom static scanner rule-set evaluation, discuss enterprise CI/CD integration, or contribute to the open-source project."
      />

      <div className="grid gap-6 lg:grid-cols-[1.6fr_1fr]">
        <GlassCard className="order-2 lg:order-1">
          <ContactForm onNotify={push} />
        </GlassCard>

        <div className="order-1 space-y-4 lg:order-2">
          <QuickLinks onNotify={push} />
        </div>
      </div>

      <ToastViewport toasts={toasts} onDismiss={dismiss} />
    </div>
  );
}
