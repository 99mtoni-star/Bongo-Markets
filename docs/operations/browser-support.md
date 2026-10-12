# Browser Support (NFR-M07)

Supported browsers: the current and previous major versions of Chrome, Edge, Firefox and Safari (desktop and mobile), plus responsive mobile web.

- **No JavaScript dependency.** Every page works with plain HTML forms, and the mobile menu uses `<details>`.
- **CSS features used:** grid, flexbox, custom properties, `prefers-color-scheme`, `<progress>`. All are supported by the browser versions above.
- **Automated check:** M06-T010 renders the key pages in Chromium at phone width (390 px) and desktop width (1280 px) and asserts there is no horizontal overflow.
- **Manual check before each release:** Firefox, Safari (iOS) and Edge, recorded in the release evidence (M20).
