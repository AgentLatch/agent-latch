# AgentLatch Console — Invicti UI (AL-101)

The React + TypeScript foundation for the AgentLatch enterprise console: design tokens, reusable UI components, and the app shell with navigation. This is the base the four product pages are built on.

## Stack

- **React 18** + **TypeScript**, built with **Vite**
- **Tailwind CSS** for the design tokens
- **react-router-dom** for routing

## Getting started

Requires Node.js 18+.

```sh
cd web
npm install
npm run dev        # http://localhost:5173
npm run build      # type-check + production build to dist/
```

## Design tokens (Invicti)

Defined in [`tailwind.config.ts`](tailwind.config.ts):

| Token | Value | Use |
| --- | --- | --- |
| `bg-base` | `#080C14` | App background (dark slate base) |
| `bg-surface` | `rgba(19, 28, 49, 0.6)` | Glass card surface (with `backdrop-blur`) |
| `accent` | `#8B5CF6` → `accent-deep` `#7C3AED` | Primary accent (violet) |
| `accent-cyan` | `#06B6D4` → `accent-cyan-bright` `#22D3EE` | Secondary accent (cyan) |
| `risk-high` | `#F43F5E` | High / critical |
| `risk-medium` | `#F59E0B` | Medium |
| `risk-low` | `#10B981` | Low |
| `shadow-neon` | violet glow | Neon glow on buttons and interactive cards |

## Components

Reusable UI in [`src/components/ui`](src/components/ui) (re-exported from its `index.ts`):

- **Button** — variants `primary`, `secondary`, `ghost`, and `glow` (neon); sizes `sm`/`md`/`lg`.
- **Badge** — tones `neutral`, `violet`, `cyan`, and the risk levels `high`/`medium`/`low`.
- **GlassCard** — frosted surface with backdrop blur; `interactive` adds a hover glow.
- **SectionHeader** — eyebrow, title, subtitle, and an optional right-aligned action.
- **PageLayout** ([`src/components/layout`](src/components/layout)) — the app shell: sticky navbar + content + footer.

## Navigation

[`Navbar`](src/components/layout/Navbar.tsx) is sticky, highlights the active route, and collapses to a toggleable drawer on mobile. Routes live in [`navItems.ts`](src/components/layout/navItems.ts); the four pages are under [`src/pages`](src/pages).
