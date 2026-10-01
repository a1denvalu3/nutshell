// Applies the saved colour theme before first paint (no flash). "system"
// follows the OS; "light"/"dark" set data-theme on <html>, which the CSS
// tokens read. Exposed as window.cashuTheme for the theme menu.
(function () {
  var root = document.documentElement, KEY = 'cashu-theme', query = window.matchMedia('(prefers-color-scheme: dark)');
  function saved() {
    try { var v = localStorage.getItem(KEY); return v === 'light' || v === 'dark' ? v : 'system'; } catch (e) { return 'system'; }
  }
  function apply(mode) {
    if (mode === 'system') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', mode);
    var dark = mode === 'dark' || (mode === 'system' && query.matches);
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', dark ? '#121212' : '#f4f0e6');
    return dark;
  }
  window.cashuTheme = {
    get: saved,
    isDark: function () { return apply(saved()); },
    set: function (mode) {
      try { if (mode === 'system') localStorage.removeItem(KEY); else localStorage.setItem(KEY, mode); } catch (e) { /* private mode */ }
      var dark = apply(mode);
      window.dispatchEvent(new CustomEvent('cashu-theme', { detail: { mode: mode, dark: dark } }));
      return dark;
    },
  };
  apply(saved());
  query.addEventListener('change', function () {
    if (saved() !== 'system') return;
    var dark = apply('system');
    window.dispatchEvent(new CustomEvent('cashu-theme', { detail: { mode: 'system', dark: dark } }));
  });
})();
