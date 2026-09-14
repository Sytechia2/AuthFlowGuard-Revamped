---
name: AuthFlowGuard
description: A calm, evidence-led interface for testing website authentication.
colors:
  primary: "#1f5fc4"
  primary-dark: "#164996"
  primary-soft: "#eaf2ff"
  neutral-bg: "#f3f5f8"
  surface: "#ffffff"
  surface-subtle: "#f7f9fb"
  ink: "#172033"
  muted: "#607084"
  border: "#d9e0e8"
  success: "#22734b"
  warning: "#946218"
  danger: "#b33b45"
typography:
  display:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(2rem, 4vw, 3rem)"
    fontWeight: 700
    lineHeight: 1.08
    letterSpacing: "-0.045em"
  body:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.82rem"
    fontWeight: 700
    lineHeight: 1.4
rounded:
  sm: "0.45rem"
  md: "0.55rem"
  lg: "0.75rem"
  pill: "999px"
spacing:
  sm: "0.5rem"
  md: "1rem"
  lg: "1.5rem"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "#ffffff"
    rounded: "{rounded.sm}"
    padding: "0.78rem 1rem"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.primary-dark}"
    rounded: "{rounded.sm}"
    padding: "0.68rem 0.88rem"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.lg}"
    padding: "clamp(1.25rem, 3vw, 2rem)"
---

# Design System: AuthFlowGuard

## Overview

**Creative North Star: "The trusted local workbench"**

AuthFlowGuard should feel like a professional instrument for examining a real
system: calm, precise, and easy to audit. The interface gives evidence and
workflow state more visual weight than decoration. It is a security tool first,
not an AI showcase and not a theatrical hacker console.

The visual language uses a light workspace, dark navy ink, and one controlled
blue accent. Warm amber is reserved for permission and caution states; green
and red are reserved for outcome meaning. Surfaces are quiet and structured so
that users can focus on target scope, authentication steps, evidence, and
limitations.

**Key Characteristics:**

- Light, professional workspace with high-contrast navy text.
- One primary blue accent used for actions, focus, and active navigation.
- Clear status colors with text labels; color is never the only signal.
- Information-dense layouts that remain readable on small screens.

## Colors

The palette is restrained and semantic: blue for action and orientation, warm
amber for permission or caution, and green/red only for meaningful outcomes.

### Primary

- **Instrument Blue** (#1f5fc4): primary actions, active navigation, focus, and links.
- **Deep Instrument Blue** (#164996): hover states and high-emphasis labels.

### Neutral

- **Workspace Gray** (#f3f5f8): application background.
- **Paper White** (#ffffff): panels, fields, and interactive surfaces.
- **Quiet Surface** (#f7f9fb): secondary rows and low-emphasis containers.
- **Navy Ink** (#172033): headings and primary content.
- **Slate Annotation** (#607084): supporting copy and metadata.
- **Rule Gray** (#d9e0e8): borders and separators.

### Named Rules

**The Evidence-First Rule.** Visual emphasis belongs to the target, workflow
state, evidence, and result meaning—not to decorative chrome.

**The One-Accent Rule.** Blue is the only general-purpose accent. Green, amber,
and red appear only when their status meaning is real.

## Typography

**Display Font:** Inter, with ui-sans-serif and system-ui fallbacks

**Body Font:** Inter, with ui-sans-serif and system-ui fallbacks

**Label/Mono Font:** Cascadia Code or SFMono-Regular for IDs, references, and
machine-readable values.

**Character:** Compact, neutral, and highly legible. The display scale creates
clear page orientation without turning the interface into a marketing surface.

### Hierarchy

- **Display** (700, `clamp(2rem, 4vw, 3rem)`, 1.08): current workflow view.
- **Title** (600, 1.05rem, 1.3): panel headings and result titles.
- **Body** (400, 1rem, 1.5): instructions, explanations, and evidence context.
- **Label** (700, 0.82rem, 1.4): field labels and control descriptions.
- **Machine label** (400, 0.72–0.76rem): scan IDs, OWASP references, and status metadata.

## Layout

Desktop uses a stable navigation rail and a generous content workspace capped at
96rem. The main content uses two-column grids for setup and discovery, then
collapses to a single column below 920px. At 640px, navigation becomes a compact
four-item row and forms stack vertically. Spacing follows a simple 0.5rem base
rhythm with larger separation between workflow sections.

## Elevation & Depth

Depth is mostly tonal: white panels sit on a quiet gray workspace, with thin
rules defining boundaries. A single soft ambient shadow supports panel grouping;
there are no glows, gradients, or hard offset shadows.

## Shapes

Controls and panels use restrained rounded corners: 0.45rem for fields and
buttons, 0.55rem for compact rows, and 0.75rem for larger panels. Pills are
reserved for compact status labels. Borders are 1px and neutral except for
semantic focus and active states.

## Components

### Buttons

- **Primary:** Instrument Blue fill, white text, compact confident padding.
- **Secondary:** White fill, neutral border, blue text; blue border on hover.
- **Focus:** A visible blue outline with a small offset, never a glow-only state.

### Cards / Containers

- **Background:** Paper White, with Quiet Surface for secondary rows.
- **Border:** 1px Rule Gray.
- **Shadow:** Soft ambient shadow on major panels only.
- **Internal padding:** Responsive `clamp(1.25rem, 3vw, 2rem)` for major panels.

### Inputs / Fields

- **Style:** White background, 1px neutral border, 0.45rem radius.
- **Focus:** Instrument Blue border and a restrained outline ring.
- **Error:** Red text with a clear message; do not rely on border color alone.

### Navigation

The left rail is white with a compact brand mark and four workflow steps. The
active step uses a pale blue surface and dark blue text. On smaller screens the
rail becomes a compact horizontal workflow selector.

## Do's and Don'ts

### Do:

- **Do** make authorization, evidence, coverage, and limitations easy to find.
- **Do** keep controls keyboard-visible and status states text-labelled.
- **Do** use the blue accent sparingly so primary actions remain obvious.
- **Do** preserve the real scan data and security meaning while changing presentation.

### Don't:

- **Don't** use neon hacker imagery, decorative cyberpunk effects, or AI-dashboard tropes.
- **Don't** use gradients, glass, glow effects, or ornamental metric cards as decoration.
- **Don't** imply a security verdict without the evidence that supports it.
- **Don't** make color the only way to understand a result or workflow state.
