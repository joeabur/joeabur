# Joseph Mark Ochieng’ — Cybersecurity Portfolio

A static portfolio site: plain HTML5, CSS3 and vanilla JavaScript. No build step, no npm, no backend, no external requests — it works offline.

```
cybersecurity-portfolio/
├── index.html      # all content
├── styles.css      # design tokens in :root (colours, fonts)
├── script.js       # mobile nav, scroll highlight, mailto form
├── assets/icons/   # favicon.svg
├── assets/images/  # put project screenshots here
└── documents/      # CV PDF
```

## Open it
Double-click `index.html`. That's it.

## Customize
- **Text / sections:** edit `index.html` (each section is commented).
- **Colours / spacing:** edit the variables at the top of `styles.css`.
- **Skill domains:** each tab in `#skills` is a `role="tabpanel"` block. Add a new tab button and matching panel with the same `id` pattern; `script.js` wires up any `[data-tabs]` group automatically.
- **Diagrams:** the incident lifecycle, pipeline and vulnerability steppers use the same tab markup. The architecture boxes read their text from the `ARCH` object in `script.js`.
- **Detection example:** edit the `<tr data-seq="FFS" data-truth="benign">` rows in `#lab`. `F` = failed login, `S` = success. The example is synthetic.
- **Contact form:** client-side only; it builds a `mailto:` link that opens the visitor's email app.

### Labels used on the site (keep them honest)
- **My experience** — only things from your CV.
- **General practice** — how the discipline typically works.
- **Conceptual / Synthetic data** — illustrative; never a real deployment or real data.

### Project case studies
Each project card has a `Read the case study` panel. The five public repositories' case studies were written from each repo's own README and file layout (reviewed October 2026) and say what the repo states, including its limitations. Re-check them if the repositories change. Fields marked **To add** (`<span class="ph">`) are placeholders (mostly screenshots). The private Security Testing Platform card still needs your own content; nothing about its internals was read or published. Do not describe features you have not built.

## Replace the CV
`documents/Joseph_Ochieng_Cybersecurity_Analyst_Resume.pdf` is your real CV. To update it, replace the file using the **same filename** and the *Download My CV* button keeps working. Note: the CV includes a phone number and is publicly downloadable once the site is published.

## Add project screenshots and links
1. Save images in `assets/images/` (e.g. `security-testing-platform.png`).
2. In `index.html`, replace the `<div class="media-slot">…</div>` in a project card with:
   `<img src="assets/images/security-testing-platform.png" alt="Describe the screenshot" loading="lazy">`
3. **Security Testing Platform** is a *private* repository, so it is deliberately not linked. If you make it public, add a `<p class="links">` line like the other cards.
4. The other project cards link to public repositories on your GitHub and describe them using only each repo's public one-line description or language. **Please review each card against the actual repo** and edit wording/technologies so only tools you really used are listed. Never publish employer data, logs, credentials or sensitive configs.

## Publish free with GitHub Pages
This repo includes `.github/workflows/pages.yml`, which deploys the `cybersecurity-portfolio/` folder.
1. Merge the branch into `main`.
2. In the repo go to **Settings → Pages → Build and deployment → Source: GitHub Actions**.
3. The site appears at `https://joeabur.github.io/joeabur/` after the workflow finishes.

(Alternative: copy the folder's contents to a repo named `joeabur.github.io` for `https://joeabur.github.io/`.)

## Verification checklist
| Check | Result |
|---|---|
| Opens from `file://` with no console errors or failed requests (headless Chromium, 1280 / 820 / 390 px) | ✅ |
| No horizontal page scroll at 1280, 820 and 390 px | ✅ |
| All in-page `#anchors` resolve | ✅ |
| Skill and stepper tabs: mouse and arrow-key navigation | ✅ |
| Architecture boxes, project filters, case-study panels, glossary tooltip, back-to-top | ✅ |
| Detection simulation recalculates for threshold and "success required" | ✅ |
| Mobile menu opens, navigates and closes | ✅ |
| CV button points to an existing PDF | ✅ |
| Skip link, focus styles, ARIA tab pattern, reduced-motion support | ✅ implemented; not tested with a screen reader |
| Colour contrast | ✅ designed for it; not audited with a tool |
| Live external links, mailto in a real mail client, Safari/Firefox, real phones | ⚠️ not tested |
