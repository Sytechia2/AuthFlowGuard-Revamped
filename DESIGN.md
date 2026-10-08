---
name: AuthFlowGuard
description: A security scanner that reads like one; the scan is the unit, its severity is the headline, and every verdict sits one row from its evidence.
colors:
  navy: "#1b3a73"
  navy-hover: "#132c5a"
  navy-soft: "#e7edf7"
  focus: "#2f63c4"
  critical: "#7d1a30"
  critical-mark: "#7a0f2b"
  high: "#c0282b"
  high-mark: "#d0302f"
  medium: "#e8771d"
  medium-ink: "#2a1400"
  low: "#f2c230"
  low-ink: "#3a2c00"
  low-mark: "#f5c518"
  passed: "#20733a"
  passed-mark: "#2e8b3e"
  unrated: "#66717f"
  success-soft: "#e6f4ea"
  warning: "#8a5a00"
  warning-soft: "#fff5dc"
  danger: "#b3261e"
  danger-soft: "#fdecea"
  bg: "#eff3f7"
  surface: "#ffffff"
  surface-2: "#f6f8fa"
  band: "#e8eef5"
  row-tint: "#f9fafc"
  ink: "#18202e"
  muted: "#4f5b6c"
  subtle: "#66717f"
  rule: "#dce2e9"
  rule-strong: "#c3ccd7"
typography:
  headline:
    fontFamily: "Spline Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1.75rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  title:
    fontFamily: "Spline Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1.05rem"
    fontWeight: 600
    lineHeight: 1.45
  body:
    fontFamily: "Spline Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.45
    fontFeature: "tnum"
  table:
    fontFamily: "Spline Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.95rem"
    fontWeight: 400
    lineHeight: 1.3
    letterSpacing: "-0.012em"
    fontFeature: "tnum"
  label:
    fontFamily: "Spline Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.93rem"
    fontWeight: 500
    lineHeight: 1
  meta:
    fontFamily: "Spline Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.86rem"
    fontWeight: 500
    lineHeight: 1.45
  count:
    fontFamily: "Spline Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1.9rem"
    fontWeight: 500
    lineHeight: 1.1
    fontFeature: "tnum"
  mono:
    fontFamily: "ui-monospace, Cascadia Mono, Cascadia Code, Consolas, SFMono-Regular, Menlo, monospace"
    fontSize: "0.9em"
    fontWeight: 400
rounded:
  sm: "0.2667rem"
  badge: "0.3333rem"
  md: "0.4rem"
  pill: "999px"
  round: "50%"
spacing:
  hair: "2px"
  xs: "0.2667rem"
  sm: "0.5333rem"
  md: "0.8rem"
  card: "0.9333rem"
  lg: "1.2rem"
  xl: "1.6rem"
  gutter: "1.7333rem"
components:
  button-primary:
    backgroundColor: "{colors.navy}"
    textColor: "{colors.surface}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    padding: "0 0.8rem"
    height: "2.1333rem"
  button-primary-hover:
    backgroundColor: "{colors.navy-hover}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    padding: "0 0.8rem"
    height: "2.1333rem"
  button-secondary-hover:
    textColor: "{colors.navy}"
  button-danger:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.danger}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    padding: "0 0.8rem"
    height: "2.1333rem"
  button-danger-hover:
    backgroundColor: "{colors.danger-soft}"
  nav-item:
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "0 0.8rem"
    height: "2.4rem"
  nav-item-hover:
    backgroundColor: "{colors.surface-2}"
  nav-item-active:
    backgroundColor: "{colors.navy}"
    textColor: "{colors.surface}"
  tab:
    textColor: "{colors.ink}"
    padding: "0.4rem 0.8rem 0.6rem"
  tab-active:
    textColor: "{colors.navy}"
  status-pill-running:
    backgroundColor: "{colors.navy-soft}"
    textColor: "{colors.navy}"
    typography: "{typography.meta}"
    rounded: "{rounded.pill}"
    padding: "0.2rem 0.6667rem"
  status-pill-completed:
    backgroundColor: "#c6ead0"
    textColor: "#165c2c"
    typography: "{typography.meta}"
    rounded: "{rounded.pill}"
    padding: "0.2rem 0.6667rem"
  status-pill-awaiting-guidance:
    backgroundColor: "{colors.warning-soft}"
    textColor: "{colors.warning}"
    typography: "{typography.meta}"
    rounded: "{rounded.pill}"
    padding: "0.2rem 0.6667rem"
  status-pill-failed:
    backgroundColor: "{colors.danger-soft}"
    textColor: "{colors.danger}"
    typography: "{typography.meta}"
    rounded: "{rounded.pill}"
    padding: "0.2rem 0.6667rem"
  rating-badge-critical:
    backgroundColor: "{colors.critical}"
    textColor: "{colors.surface}"
    rounded: "{rounded.badge}"
    padding: "0.2667rem 0.4667rem"
  rating-badge-high:
    backgroundColor: "{colors.high}"
    textColor: "{colors.surface}"
    rounded: "{rounded.badge}"
    padding: "0.2667rem 0.4667rem"
  rating-badge-medium:
    backgroundColor: "{colors.medium}"
    textColor: "{colors.medium-ink}"
    rounded: "{rounded.badge}"
    padding: "0.2667rem 0.4667rem"
  rating-badge-low:
    backgroundColor: "{colors.low}"
    textColor: "{colors.low-ink}"
    rounded: "{rounded.badge}"
    padding: "0.2667rem 0.4667rem"
  rating-badge-passed:
    backgroundColor: "{colors.passed}"
    textColor: "{colors.surface}"
    rounded: "{rounded.badge}"
    padding: "0.2667rem 0.4667rem"
  rating-badge-unrated:
    backgroundColor: "{colors.unrated}"
    textColor: "{colors.surface}"
    rounded: "{rounded.badge}"
    padding: "0.2667rem 0.4667rem"
  card:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.md}"
  severity-tile:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "0.8667rem 0.9333rem 0.8rem"
  table-header:
    backgroundColor: "{colors.band}"
    textColor: "{colors.ink}"
    padding: "0.6rem 0.9333rem"
  table-row-open:
    backgroundColor: "{colors.row-tint}"
  details-panel-header:
    backgroundColor: "{colors.band}"
    textColor: "{colors.ink}"
    typography: "{typography.title}"
    padding: "0.9333rem 0.9333rem 0.8rem"
  input-field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "0.4667rem 0.6667rem"
    height: "2.4rem"
  option-selected:
    backgroundColor: "{colors.navy-soft}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "0.8rem 0.9333rem"
  step-number:
    backgroundColor: "{colors.navy}"
    textColor: "{colors.surface}"
    rounded: "{rounded.round}"
    size: "1.6rem"
---

# Design System: AuthFlowGuard

## Overview

**Creative North Star: "The Scanner That Reads Like One"**

AuthFlowGuard looks like the category it belongs to: a vulnerability scanner. The scan is the unit of everything; each scan has a page whose headline is its severity, and every verdict sits one table row away from its evidence. The world borrows the category conventions people already read fluently from tools like Nessus and Qualys (a left rail, breadcrumb, severity bar, count tiles, a findings table sorted Critical first, a details panel at the right) and none of their branding.

The material is plain and office-lit: white surfaces on a cool light-gray workspace, dark slate ink, 1px gray hairlines, modest corners and a single soft shadow. One deep navy carries every action and the current place in the app. The only other saturated colours on screen are the severity scale, and each of those is always spoken aloud by a text label. Density is that of a working tool, compact table rows with tabular numerals and a fluid root size that keeps proportions from laptop to large desktop.

It rejects the generic form wizard of four equal steps, and it rejects the theatrical hacker console: no neon, no dark terminal chrome, no glow.

**Key Characteristics:**

- Light theme only: white cards on a cool gray workspace, dark slate ink.
- One navy accent for actions, the active nav item, the selected tab and progress.
- Scanner severity scale (Critical, High, Medium, Low, Passed), always paired with its word.
- Flat surfaces separated by 1px rules, with one soft shadow token.
- Spline Sans throughout, tabular numerals everywhere, monospace only for machine strings.
- One authored motion, the severity bar's grow-in, switched off for reduced motion.

## Colors

A cool, near-neutral slate world with exactly one action hue and a conventional scanner severity scale that is never left to speak without words.

### Primary

- **Ledger Navy** (navy): primary buttons, the active sidebar item, the selected tab's text and 2px underline, completed and current stepper steps, guidance step numbers, link text, selected option borders, checkbox accent. It is the only colour that means "act here" or "you are here".
- **Pressed Navy** (navy-hover): hover state of primary buttons only.
- **Navy Wash** (navy-soft): quiet navy surfaces: running/queued status pill, engine pill, selected option card, text selection.
- **Focus Blue** (focus): the 2px focus outline (2px offset) on every focusable element; on fields the border also turns focus blue.

### Secondary

The severity scale. Each severity has a **fill** and a **mark**. Fills carry text (rating badges, severity chips); marks are the brighter siblings used where no text sits on the colour (severity bar segments, tile top rules, the connection dot).

- **Crimson Critical** (critical fill, critical-mark): the worst finding; white text on the fill.
- **Signal Red High** (high fill, high-mark): white text on the fill.
- **Scanner Orange Medium** (medium, used for both fill and mark) with **Burnt Umber Ink** (medium-ink) as its text colour.
- **Caution Yellow Low** (low fill, low-mark) with **Olive Ink** (low-ink) as its text colour.
- **Ledger Green Passed** (passed fill, passed-mark): white text on the fill; the mark also marks a finished check and an online API.
- **Slate Not-Rated** (unrated): inconclusive and unrated results, with white text.

### Tertiary

State colours for workflow, not for findings: **Amber Caution** (warning, on warning-soft) for "Needs your help" and the discovery prompt; **Alarm Red** (danger, on danger-soft) for failed scans, errors and destructive actions; **Mint Wash** (success-soft) behind success notices.

### Neutral

- **Cool Workspace** (bg): the application background behind every card.
- **Paper White** (surface): cards, sidebar, tiles, fields, secondary buttons.
- **Soft Surface** (surface-2): hover fill for nav items and icon buttons, neutral notices, step markers.
- **Header Band** (band): the tinted band behind table headers and the Scan details title.
- **Row Tint** (row-tint): hovered rows and the open findings row with its detail row.
- **Slate Ink** (ink): headings, body, table text.
- **Muted Slate** (muted): subtitles, help text, detail headings, icon buttons at rest.
- **Subtle Slate** (subtle): metadata, counts, breadcrumb separators, pending steps.
- **Hairline** (rule): all structural 1px rules: table rows, card internals, sidebar edge, action bar edge.
- **Strong Hairline** (rule-strong): control borders (secondary buttons, inputs, options) and the tab strip baseline.

### Named Rules

**The One Navy Rule.** Navy is the only action and orientation hue. A second accent colour is never introduced; severity and state colours never stand in for a button or a nav state.

**The Spoken Severity Rule.** Severity colour is always paired with its text label (Critical, High, Medium, Low, Passed, Inconclusive, Not rated). The severity bar, which has no room for words, carries an accessible label listing every non-zero count, and the five labelled tiles sit directly beneath it.

**The Dark Ink Rule.** Medium and Low badges and chips use dark ink (medium-ink, low-ink), never white; white text on orange or yellow fails contrast. Critical, High, Passed and Not rated take white.

**The Fill and Mark Rule.** Text sits only on fills. The brighter marks are for bars, tile rules and dots where no text appears.

## Typography

**Display Font:** Spline Sans (self-hosted, weights 400/500/600), with ui-sans-serif, system-ui, -apple-system and Segoe UI fallbacks
**Body Font:** Spline Sans, same stack
**Label/Mono Font:** ui-monospace, Cascadia Mono, Cascadia Code, Consolas, SFMono-Regular, Menlo, at 0.9em

**Character:** One workhorse grotesque with slightly technical, squared-off letterforms, set with tabular numerals globally so counts, codes and durations line up. Hierarchy comes from size and weight steps of 400, 500 and 600; nothing is bolder than 600.

### Hierarchy

- **Headline** (600, 1.75rem; 1.85rem for a scan's own title, 1.2, -0.02em): the page title, next to its status pill.
- **Count** (500, 1.9rem, 1.1; 1.4rem on phones): the number in each severity tile.
- **Title** (600, 1.05rem): card titles, guidance step titles, the Scan details band.
- **Body** (400, 1rem, 1.45): running copy; help text capped at 70ch, notices and write-up paragraphs at 75ch.
- **Table** (400, 0.95rem, 1.3, -0.012em): findings check names and result text, clamped to two lines in the row.
- **Label** (500, 0.93rem, line-height 1): buttons, field labels, tabs (0.97rem), nav items (0.97rem); table header cells use 600 at the same size.
- **Meta** (500, 0.86rem): status and engine pills, definition-list terms, detail sub-headings (600, muted, +0.01em).
- **Mono** (400, 0.9em; 0.8-0.88rem in lists): target URLs, scan IDs, CSS selectors.

### Named Rules

**The Real Words Rule.** Analyser result text is shown exactly as the analyser wrote it. The table clamps it to two lines and the detail row shows it in full; the interface never paraphrases, summarises or softens a verdict.

**The Machine Strings Rule.** Monospace is only for strings a machine reads: URLs, IDs and selectors. Check codes (CHK-006) and OWASP references (WSTG-SESS-06) stay in Spline Sans with tabular numerals.

## Layout

The shell is a two-column grid: a sticky white sidebar rail (14.4rem) with the brand mark, Scans and New scan, and the local API status pinned to its foot above a hairline; then a workspace padded 1.4667rem top and 1.7333rem sides. Pages centre in the workspace at one of two widths: wide (120rem) for the scan list, a scan's results and the check catalogue; narrow (72rem) for New scan and a check's write-up. Component widths follow the page; only running paragraphs keep a 75ch measure. Every page opens with a breadcrumb and a page header that wraps: title, status pill and monospace target on the left, actions on the right.

A scan's results page puts tabs (Findings, Evidence, AI discovery, Report) above a two-column body: the main column (severity card, five count tiles, findings table) and a 16.6667rem Scan details panel at the right. New scan uses a 11.3333rem sticky section nav beside settings cards, with a sticky translucent white action bar pinned to the bottom edge of the workspace.

The whole interface scales from one fluid root size, clamp(14px, 1.09vw, 19px) (15px at a 1376px window, 19px from about 1745px), and all spacing is in rem against that 15px base, so the 4/8/12/14/18/24px rhythm reads as 0.2667/0.5333/0.8/0.9333/1.2/1.6rem.

Responsive steps: at 1180px the details panel drops below the findings; at 900px the settings nav hides and two-column form and guidance grids stack; at 760px the rail becomes a top bar (brand, nav row, API status at right), the five severity tiles squeeze into one row of five, and the findings table hides its OWASP and Result columns, folding both into compact metadata under the check name.

## Elevation & Depth

Flat by default. Depth comes from tone (white cards on the cool workspace, a tinted band for headers) and 1px rules, plus one very soft shadow shared by every card and tile. There are no hover lifts, no glows and no layered elevation scale.

### Shadow Vocabulary

- **Resting card** (`box-shadow: 0 1px 2px rgba(24, 32, 46, 0.06), 0 2px 0.4rem rgba(24, 32, 46, 0.04)`): every card, severity tile and the Scan details panel. Nothing else casts a shadow.

### Named Rules

**The One Shadow Rule.** There is exactly one shadow token. If something needs more separation, use a band, a rule or space, not a deeper shadow.

## Shapes

Corners are modest and consistent: 0.4rem on cards, tiles, buttons, fields, options and nav items; 0.2667rem on icon buttons, severity chips and the rename field; 0.3333rem on rating badges. Full pills (999px) are reserved for status pills, the engine pill and the severity bar itself; circles for status dots, step markers and step numbers.

Structure is drawn with 1px hairlines. The few heavier coloured rules each carry meaning: a 0.2667rem top rule in the severity mark colour on each count tile, a 0.2rem top rule on stepper steps (navy when done or current), and the 2px navy underline of the selected tab. Severity bar segments are separated by 1px gaps over a hairline track, with a minimum segment width of 0.4rem so a single finding is always visible.

### Named Rules

**The Hairline Rule.** Borders and dividers are 1px. Coloured rules thicker than 1px exist only as a severity tile's top rule, a stepper step's top rule and the selected tab underline; never as a side stripe on a card, row, notice or panel.

## Components

### Buttons

Compact and square-shouldered, with a fixed 2.1333rem height and label typography.

- **Shape:** gently rounded (0.4rem), 1px border, 0.4rem icon gap.
- **Primary:** navy fill, white label; darkens to pressed navy on hover (120ms ease-out).
- **Secondary:** white fill, strong-hairline border, ink label; border and label turn navy on hover.
- **Danger:** white fill, pale red border, danger label; washes to danger-soft with a danger border on hover. Used for Delete in the report panel's danger row.
- **Icon button:** 2rem transparent square in muted slate, soft-surface fill on hover.
- **Focus / Disabled:** 2px focus-blue outline with 2px offset; disabled at 55% opacity with a not-allowed cursor.

### Status and rating labels

- **Status pill:** full pill, meta type. Queued/Running in navy wash (Running adds a spinning loader), Completed in green (#c6ead0 / #165c2c), Needs your help in amber, Failed in red. Always worded.
- **Rating badge:** 0.3333rem corners, 0.93rem regular weight, severity fill with white or dark ink per the Dark Ink Rule. Labels come from the fixed scale: Critical, High, Medium, Low, Passed, Inconclusive, Not rated.
- **Severity chips:** small 1.4667rem squares of count numerals on severity fills in the scans list.

### Cards / Containers

- **Corner Style:** 0.4rem.
- **Background:** paper white on the cool workspace.
- **Shadow Strategy:** the single resting-card shadow (see Elevation & Depth).
- **Border:** none on the card itself; internals separate with hairlines.
- **Internal Padding:** 0.9333rem to 1.3333rem depending on density; tables run edge to edge.
- **Scan details panel:** a card whose title sits in a band-tinted header with a hairline beneath, then a definition list (600 terms, regular values; target and scan ID in mono).

### Severity summary (signature)

- **Severity bar:** a 1.4rem full-pill track in hairline gray holding one segment per non-zero severity, flex-grown by count, in severity marks, Critical first. Zero-count segments are never drawn. Segments grow in from 40% width and 60% opacity over 700ms on cubic-bezier(0.16, 1, 0.3, 1), the system's one authored motion; under prefers-reduced-motion it does not run.
- **Count tiles:** always the five standard tiles (Critical, High, Medium, Low, Passed), each a white card with its severity-mark top rule, a label and a count numeral; a zero still shows "0". A sixth Inconclusive tile appears only when there are inconclusive or unrated results.

### Findings table

- **Header:** band-tinted row, 600 label type, hairline beneath.
- **Rows:** 3.2667rem tall, hairline separated; columns Severity (badge), Code, Check, OWASP reference, Result (two-line clamp of the real analyser text), and a chevron. Sorted Critical first, then by code.
- **States:** row-tint on hover; the whole row toggles. The open row and its detail row share row-tint, and the chevron rotates 180 degrees.
- **Detail row:** indented under the check, a responsive grid of muted 600 sub-headings over the full result, evidence and recommendation.

### Inputs / Fields

- **Style:** white, 1px strong-hairline border, 0.4rem corners, 2.4rem min height; labels 500 at 0.93rem above, help text subtle at 0.84rem below.
- **Hover:** border darkens to a mid slate.
- **Focus:** 2px focus-blue outline flush to the field and a focus-blue border.
- **Options:** radio and checkbox cards with a strong-hairline border; selected cards take a navy border on navy wash. Checkboxes and radios use the navy accent colour.
- **Error:** danger-coloured message text; never colour alone.

### Navigation

- **Sidebar rail:** white, 1px right hairline. Nav items are 2.4rem rows with a lucide icon and 0.97rem label; soft-surface on hover; the active item is a solid navy fill with white text. The API status sits at the foot with a coloured dot and words (online, offline, checking).
- **Breadcrumb:** navy links without underline (underline on hover), subtle slash separators, current page in ink.
- **Tabs:** text tabs on a strong-hairline baseline; hover turns navy; selected is navy, 500 weight, with a 2px navy underline.
- **Settings section nav:** a sticky list on a 1px left hairline, muted text turning navy on hover.
- **Mobile:** the rail becomes a sticky top bar with a bottom hairline.

### Live progress stepper

Four equal steps on a row (two per row on phones), each with a 0.2rem top rule and a circular marker. Pending steps are subtle with a hairline marker; the current step is navy text with a navy-outlined marker; done steps are ink text with a filled navy marker and check. Below it, a hairline-separated check list marks each check done (green), running (navy spinner) or pending (hollow ring).

### Guided discovery and report panel

- **Guidance:** an amber notice (warning-soft) explains what is needed; numbered step cards (navy circle numbers) sit in a two-column grid with a bordered, scrollable list of observed controls; a sticky action bar finishes the flow.
- **Report panel:** hairline-separated rows of navy icon, title and description, and an action button; the destructive row sits apart behind a pale red rule with danger-coloured title and icon.

## Do's and Don'ts

### Do:

- **Do** pair every severity colour with its word; the bar's colour is backed by an accessible label and the labelled tiles beneath it.
- **Do** use dark ink (medium-ink, low-ink) on Medium and Low fills, and white on Critical, High, Passed and Not rated.
- **Do** leave zero-count severities out of the severity bar, while the five standard tiles still show 0.
- **Do** show analyser result text verbatim: two-line clamp in the row, in full in the detail row.
- **Do** keep navy as the single accent for primary actions, the active nav item, the selected tab and progress.
- **Do** separate with 1px hairlines and tone; use the one resting-card shadow on cards and tiles only.
- **Do** keep monospace for URLs, IDs and selectors only, and tabular numerals on everything.
- **Do** keep the severity bar grow-in as the only authored motion, and switch it off under prefers-reduced-motion.

### Don't:

- **Don't** let a severity or state colour appear without its text label, or use colour as the only signal.
- **Don't** put white text on the Medium orange or Low yellow fills.
- **Don't** draw a sliver for a severity with zero findings.
- **Don't** paraphrase, summarise or soften analyser results in the interface.
- **Don't** introduce a second accent hue, or use a severity colour for a button or nav state.
- **Don't** add coloured side stripes, borders thicker than 1px beyond the tile, stepper and tab rules, gradients, glows or a second shadow depth.
- **Don't** set check codes, OWASP references or prose in monospace.
- **Don't** borrow Nessus, Qualys or any other vendor's logo, name, colours as branding, or layout chrome beyond the shared category conventions.
- **Don't** go dark-mode, neon or hacker-console; the world is light only.
