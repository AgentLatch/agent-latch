# Challenge: [OpenMAIC / Server-Side Headless Chromium Rendered With Sandbox Disabled] (Challenge 01)

## 1. Upstream source repository
- GitHub Link: https://github.com/THU-MAIC/OpenMAIC
- Version analyzed: v1.2.0-rc.1
- Target vulnerable file(s): render-service/src/preview-renderer.ts
  - ChromiumPreviewRenderer.render (lines 523-591), browser launch (lines 532-537)
  - installPreviewRequestGuard (lines 411-432) — a real mitigation, network-layer only

## 2. What is the vulnerability?
- `ChromiumPreviewRenderer.render` (preview-renderer.ts:523-591) launches Puppeteer/Chromium with
  `args: ['--no-sandbox', '--disable-dev-shm-usage']` (line 537) and then calls `page.setContent`
  with the Interactive scene's LLM-generated `html` field (lines 551-556, 581), executing it inside
  that unsandboxed renderer process on the render-service's own infrastructure rather than only in
  an isolated client browser tab. `--no-sandbox` disables Chromium's OS-level, multi-process
  privilege-separation boundary — the exact class of protection ASI05 names — so a V8/Chromium
  renderer-process exploit class normally contained by that sandbox would instead execute with the
  render-service host process's own privileges; the existing `installPreviewRequestGuard` network
  request filter restricts outbound navigation but does nothing to restore the disabled OS sandbox.