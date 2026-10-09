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
- **Contact form:** it is client-side only; it builds a `mailto:` link that opens the visitor's email app.

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
| Opens from `file://` with no console errors or failed requests (headless Chromium) | ✅ |
| No horizontal scroll at 1280px and 390px widths | ✅ |
| Mobile menu opens, link click scrolls and closes it | ✅ |
| All local assets (CSS, JS, favicon, CV PDF) load via relative paths | ✅ |
| CV button points to an existing PDF with `download` attribute | ✅ |
| External links use `rel="noopener noreferrer"` | ✅ |
| Skip link, focus styles, ARIA labels, reduced-motion support | ✅ implemented; not tested with a screen reader |
| Live external links (GitHub/LinkedIn), mailto in a real mail client, real phones/Safari/Firefox | ⚠️ not tested |
