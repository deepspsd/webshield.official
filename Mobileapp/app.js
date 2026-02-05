(function () {
  const screens = Array.from(document.querySelectorAll('[data-screen]'));
  const tabs = Array.from(document.querySelectorAll('.tab[data-nav]'));
  const navButtons = Array.from(document.querySelectorAll('[data-nav]'));
  const iframes = Array.from(document.querySelectorAll('iframe[data-src]'));

  function getIframeForScreen(name) {
    const screen = screens.find((s) => s.dataset.screen === name);
    if (!screen) return null;
    return screen.querySelector('iframe[data-src]');
  }

  function ensureIframeLoaded(iframe) {
    if (!iframe) return;
    if (iframe.getAttribute('src')) return;
    const src = iframe.getAttribute('data-src');
    if (src) iframe.setAttribute('src', src);
  }

  function setActiveScreen(name) {
    screens.forEach((s) => s.classList.toggle('is-active', s.dataset.screen === name));
    tabs.forEach((t) => t.classList.toggle('is-active', t.dataset.nav === name));

    const iframe = getIframeForScreen(name);
    ensureIframeLoaded(iframe);
    applyThemeToIframe(iframe);
  }

  navButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-nav');
      if (target) setActiveScreen(target);
    });
  });

  // Theme toggle (simple)
  const themeToggle = document.getElementById('themeToggle');
  const root = document.documentElement;

  function getTheme() {
    return root.getAttribute('data-theme') || 'dark';
  }

  function setTheme(next) {
    if (next === 'light') root.setAttribute('data-theme', 'light');
    else root.removeAttribute('data-theme');

    try {
      localStorage.setItem('webshield_mobile_theme', next);
    } catch (_) {
      // ignore
    }

    const icon = themeToggle?.querySelector('.icon');
    if (icon) icon.textContent = next === 'light' ? '🌙' : '☀️';

    // Apply to already loaded iframes
    iframes.forEach((f) => applyThemeToIframe(f));
  }

  function applyThemeToIframe(iframe) {
    if (!iframe) return;
    try {
      if (!iframe.contentDocument) return;
      const theme = getTheme();
      if (theme === 'light') iframe.contentDocument.documentElement.setAttribute('data-theme', 'light');
      else iframe.contentDocument.documentElement.removeAttribute('data-theme');
    } catch (_) {
      // ignore: cross-origin / not loaded yet
    }
  }

  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const current = getTheme();
      setTheme(current === 'light' ? 'dark' : 'light');
    });
  }

  try {
    const saved = localStorage.getItem('webshield_mobile_theme');
    if (saved === 'light' || saved === 'dark') setTheme(saved);
    else setTheme('dark');
  } catch (_) {
    setTheme('dark');
  }

  // Iframe load hook for theme sync
  iframes.forEach((f) => {
    f.addEventListener('load', () => applyThemeToIframe(f));
  });

  // Profile button opens profile screen
  const profileBtn = document.getElementById('profileBtn');
  if (profileBtn) {
    profileBtn.addEventListener('click', () => setActiveScreen('profile'));
  }

  // Default
  setActiveScreen('home');
})();
