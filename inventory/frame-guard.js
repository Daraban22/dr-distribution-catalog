// GitHub Pages cannot send X-Frame-Options, so refuse to run inside a frame.
if (window.top !== window.self) {
  document.documentElement.style.display = "none";
  try { window.top.location = window.self.location; } catch { /* blocked */ }
}
