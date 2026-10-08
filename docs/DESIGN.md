# Squawk — design pillars

The experience charter. [`CHARTER.md`](CHARTER.md) says what must stay *true*;
this says what must stay *consistent* on screen. When a design choice is in
question, hold it against these pillars. When they and the charter disagree, the
charter wins: honesty outranks polish.

These are not style preferences. Each one is derived from what Squawk is (an
evidence-first, read-only, single-operator security instrument) and who it is for
(one person with no team and no enterprise stack).
The visual language borrows from instrument panels the audience already trusts:
Wiz and Tenable for security density, Splunk for evidence tables, Lightroom for a
calm dark workspace, Claude and Brave for restraint.

---

## The seven pillars

### 1. Show the work, never assert

Every result carries the evidence behind it: what ran, what it examined, what was
checked. A verdict with nothing behind it is the charter's first invariant broken
on screen, because a pass that shows nothing is indistinguishable from a scan that
never happened. So a clean run shows its coverage, a self-audit shows every check
including the passes, and a target that could not be fully scanned is never drawn
as clean.

*Check:* can the reader see what backs this number, or are they asked to trust it?

### 2. Three honest states, shape before colour

A finding or a check is `ok`, a `gap`, or `unknown`, never a fabricated pass. Each
state carries a **shape** as well as a colour (a dot, a triangle, a dashed ring),
so it reads for someone who cannot rely on hue. Colour is never the only cue.
Severity marks (C/H/M/L/I) ride in the same shape-plus-colour chip everywhere.
Contrast meets WCAG AA in both themes.

*Check:* if this screen were greyscale, does every status still read?

### 3. Red means critical, not brand

The accent is teal. Red is reserved for genuine criticals and the loudest alarms.
An interface that is red everywhere has no way left to say "this one matters."

*Check:* is red doing work here, or is it decoration?

### 4. Name what you are looking at

Every run and every view leads with its **target, service, and time**. No
timestamp stands alone; no context is unlabelled. The tool's own posture
(read-only, loopback-only, single-user) is stated on screen as the loopback
badge, not left for the reader to assume.

*Check:* dropped onto this page cold, could the reader say what run, what target,
and what scope this is?

### 5. Severity-first, one decision per row

Group by the advisory, worst severity first. The operator gets a shortlist to act
on, not a thousand near-identical rows. The **same grouping key is used across
every view**, so Findings and Triage never disagree on a count. Noise the tool
hides is counted out loud, never silently dropped.

*Check:* is the first thing on screen the thing to act on first?

### 6. Calm instrument, loud only when earned

Quiet by default. The squawk codes (7500 attack, 7600 lost signal, 7700
emergency, 1200 nothing-to-report) are the only alarms, and they earn their
volume. Motion is minimal and respects `prefers-reduced-motion`. The aviation
transponder vocabulary is the app's voice: consistent, not decorative.

*Check:* does this shout only when it should, and stay calm otherwise?

### 7. One design system, two themes, one operator

CSS tokens (`:root` variables) are the single source of styling. No literal
colours in components, no per-view drift. Light and dark are both first-class,
defined token-level, and the exported report shares the same system. Keyboard
focus is always visible. Every screen answers one question for a person with no
time: **what do I do next?** Nothing needs an account, a server, or a teammate.

*Check:* does this use the tokens, work in both themes, and leave the operator
with an obvious next step?

---

## The user journey

One operator, one machine, one loop. Each step names the pillars it leans on.
Step 0 is not a page; it is on every page.

0. **Every page.** A clock wall in the top bar: UTC (what the evidence is
   stamped in), the server's zone (where the scan ran), and the reader's
   (where it is being read). Three machines, three zones, none of them
   assumed. *(1, 4)*
1. **Overview.** The estate as it stands: newest run per target, ranked by risk,
   gaps flagged so "clean" is never a false all-clear. *(1, 4, 5)*
2. **Scan.** Pick the kind of insight; its tile lists what it can point at
   (targets already run, checkouts under the scan roots); run. A path is typed
   only when it is new. Missing scanners show as gaps on the launcher, not
   hidden. *(1, 4)*
3. **Job.** Live per-stage progress while it runs: what has finished and how
   long it took, what is running and how long it has been, against the budget
   that stage is actually bounded by — never a percentage, because no scanner
   here publishes one and a bar advancing on a guess is a denominator nobody
   measured. A failed stage reads as a failure, never as a zero. *(1, 2)*
4. **Scan complete.** The verdict first (a squawk code or `No squawk`), then
   **What ran** and what it examined, then what this service does not cover.
   Never a bare bill of health. *(1, 4, 6)*
5. **Findings.** Drill to the advisory: what it is, what proved it, what to do,
   whether it has been seen before. Empty columns and redaction placeholders are
   not shown. *(1, 2, 5)*
5b. **Estate.** The same advisories across every target at once, grouped by the
   same key, so a number on the Overview can be clicked through to exactly the
   findings behind it. Every count says what it is out of. *(1, 5)*
6. **Triage.** Decide once per advisory, not once per row. Every mark is
   recorded in the evidence store with who, when and why, and follows the
   finding on to the next run; the markdown is an export of that record.
   *(5, 7)*
7. **History and Compare.** The same target over time: what was remediated, what
   is new, whether coverage held, and a −5 to +5 rating with the median at 0 (a
   run that could not look is drawn hollow, never a clean high). *(1, 2)*
8. **Baselines.** File what is accepted, so the next run diffs against it. *(4, 5)*
9. **Evidence integrity.** The Overview closes with whether the evidence store
   still verifies, when it was last checked, and the command to check it. Never
   verified reads as *never verified*, not as ok — an unrun check that renders
   as a pass is the tool's own cardinal sin. *(1, 2, 6)*

---

## Screen-review checklist

Run any screen through this before calling it done:

- [ ] **Evidence.** Every result shows what backs it (pillar 1).
- [ ] **Greyscale.** Every status reads without colour (pillar 2).
- [ ] **Red.** Used only for critical or alarm (pillar 3).
- [ ] **Identity.** Target, service, scope and time are named (pillar 4).
- [ ] **Priority.** The thing to act on first is first (pillar 5).
- [ ] **Every number links to its proof.** A count that references data is a
      link to the rows behind it, not text. Added 2026-09-06 after the Overview
      shipped three tiles and five legend counts that a reader had to take on
      trust; `/estate` is what made them answerable (pillar 1).
- [ ] **Every number states its denominator.** Out of how many, over what
      window, and what was excluded and why. A page that shows *12* without
      *of 40* is asking to be misread (pillars 1, 5; charter I12, I15).
- [ ] **Themes.** Legible in light and dark; colours come from tokens (pillars 2, 7).
- [ ] **Focus.** Keyboard focus is visible; motion respects reduced-motion (pillars 6, 7).
- [ ] **Next step.** The operator knows what to do next (pillar 7).
- [ ] **Sizing.** Icons and controls are constrained (the class of bug where an
      unsized `.btn svg` rendered as a giant blob).
- [ ] **Voice.** Copy is plain, active, and in the tool's aviation register, with
      no unlabelled jargon.
