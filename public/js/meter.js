// Calculadora de resistencia a fuerza bruta. Todo ocurre en el navegador:
// la contraseña escrita nunca sale de esta página: no hay peticiones de red ni formulario.
(() => {
  const input = document.getElementById('meter-input');
  const toggle = document.getElementById('meter-toggle');
  const rows = document.getElementById('meter-rows');
  const note = document.getElementById('meter-note');
  if (!input || !rows) return;

  // Intentos por segundo (estimaciones de orden de magnitud).
  const RATES = {
    md5: 1.6e11, // MD5 sin sal en una tarjeta gráfica de gama alta
    argon: 1e3, // Argon2id m=19 MiB, t=2 en la misma tarjeta
    online: 1 / 3600, // contra Sigilo: bloqueo progresivo de la cuenta ≈ 1 intento por hora
  };

  const COMMON = new Set([
    '123456', '123456789', '12345678', '12345', '1234567', '111111', '000000', '123123', 'qwerty', 'qwerty123',
    'password', 'password1', 'contraseña', 'contrasena', 'admin', 'admin123', 'abc123', 'iloveyou', 'teamo',
    'hola123', 'letmein', 'welcome', 'monkey', 'dragon', 'football', 'futbol', 'sigilo', 'secreto', 'colombia',
    'mexico', 'argentina', 'princesa', 'superman', 'batman', 'passw0rd', 'p@ssw0rd', '1q2w3e4r', 'asdfgh',
  ]);

  const charsetSize = (pw) => {
    let size = 0;
    if (/[a-z]/.test(pw)) size += 26;
    if (/[A-Z]/.test(pw)) size += 26;
    if (/[0-9]/.test(pw)) size += 10;
    if (/[^A-Za-z0-9]/.test(pw)) size += 33;
    if (/[^\x00-\x7F]/.test(pw)) size += 60; // ñ, tildes, emoji...
    return size;
  };

  // Palabra + números/símbolo al final (perro123, Maria2024!): lo primero que prueba un diccionario.
  const WORD_PATTERN = /^([a-záéíóúüñ]{1,14})(\d{0,4})([!.?*#@$]?)$/i;

  const classify = (pw) => {
    if (COMMON.has(pw.toLowerCase())) return 'common';
    if (WORD_PATTERN.test(pw)) return 'word';
    return 'random';
  };

  // Intentos esperados (la mitad del espacio de búsqueda).
  const expectedGuesses = (pw) => {
    if (!pw) return 0;
    const kind = classify(pw);
    if (kind === 'common') return 10;
    if (kind === 'word') {
      const [, , digits, symbol] = WORD_PATTERN.exec(pw);
      // ~300 000 palabras y nombres, con variantes de mayúsculas, años o números y un símbolo final.
      return (3e5 * 4 * Math.pow(10, digits.length) * (symbol ? 10 : 1)) / 2;
    }
    const unique = new Set(pw).size;
    const effectiveLength = unique === 1 ? 1 : pw.length;
    return Math.pow(charsetSize(pw), effectiveLength) / 2;
  };

  const YEAR = 365.25 * 24 * 3600;
  const UNIVERSE = 1.38e10 * YEAR;
  const plural = (n, one, many) => `${n.toLocaleString('es')} ${n === 1 ? one : many}`;

  const humanize = (seconds) => {
    if (seconds < 1) return 'al instante';
    if (seconds < 60) return plural(Math.round(seconds), 'segundo', 'segundos');
    if (seconds < 3600) return plural(Math.round(seconds / 60), 'minuto', 'minutos');
    if (seconds < 86400) return plural(Math.round(seconds / 3600), 'hora', 'horas');
    if (seconds < YEAR) return plural(Math.round(seconds / 86400), 'día', 'días');
    if (seconds > UNIVERSE) return 'más que la edad del universo';
    const years = seconds / YEAR;
    if (years < 1e3) return plural(Math.round(years), 'año', 'años');
    if (years < 1e6) return `${Math.round(years / 1e3).toLocaleString('es')} mil años`;
    if (years < 1e9) return `${Math.round(years / 1e6).toLocaleString('es')} millones de años`;
    return `${Math.round(years / 1e9).toLocaleString('es')} mil millones de años`;
  };

  // Barra en escala logarítmica: 1 segundo = vacía, edad del universo = llena.
  const barWidth = (seconds) => {
    if (seconds <= 1) return 2;
    return Math.min(100, Math.max(2, (Math.log10(seconds) / Math.log10(UNIVERSE)) * 100));
  };

  const render = () => {
    const pw = input.value;
    const guesses = expectedGuesses(pw);
    for (const row of rows.children) {
      const seconds = guesses / RATES[row.dataset.scenario];
      const time = row.querySelector('.meter-time');
      const fill = row.querySelector('.meter-bar > span');
      time.textContent = pw ? humanize(seconds) : '—';
      fill.style.width = pw ? `${barWidth(seconds)}%` : '0';
      row.dataset.level = !pw ? '' : seconds < 86400 ? 'weak' : seconds < 100 * YEAR ? 'fair' : 'strong';
    }
    const kind = pw ? classify(pw) : 'random';
    note.textContent =
      kind === 'common'
        ? 'Es una de las contraseñas más usadas: cualquier diccionario la prueba entre las primeras.'
        : kind === 'word'
          ? 'Parece una palabra con números o un símbolo al final. Los diccionarios prueban esas combinaciones antes que nada.'
          : 'Estimación para una contraseña elegida al azar. Si es una frase conocida o un patrón de teclado, cae mucho antes.';
  };

  input.addEventListener('input', render);
  toggle?.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    toggle.textContent = show ? 'Ocultar' : 'Mostrar';
    toggle.setAttribute('aria-pressed', String(show));
  });
})();
