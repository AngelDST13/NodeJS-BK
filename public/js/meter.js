// Calculadora de fuerza bruta. Todo ocurre en el navegador:
// la contraseña escrita nunca sale de esta página: no hay peticiones de red ni formulario.
(() => {
  const $ = (id) => document.getElementById(id);
  const input = $('meter-input');
  const toggle = $('meter-toggle');
  const out = $('meter-output');
  if (!input || !out) return;

  // Conjuntos de caracteres que un atacante debe probar según lo que aparece en la contraseña.
  const CLASSES = [
    { test: /[a-z]/, size: 26, label: 'minúsculas' },
    { test: /[A-Z]/, size: 26, label: 'mayúsculas' },
    { test: /[0-9]/, size: 10, label: 'números' },
    { test: /[ -/:-@[-`{-~]/, size: 33, label: 'símbolos' },
    { test: /[^\x00-\x7F]/, size: 60, label: 'ñ, tildes y otros' },
  ];

  // Intentos por segundo de cada escenario (órdenes de magnitud; una tarjeta gráfica de gama alta para los robos).
  const SCENARIOS = [
    { label: 'En línea contra Sigilo', detail: 'límite por IP y bloqueo progresivo de la cuenta', rate: 1 / 3600 },
    { label: 'En línea sin protección', detail: 'un sitio que no limita intentos', rate: 100 },
    { label: 'Base robada con Argon2id', detail: 'como guarda Sigilo: 19 MiB por intento', rate: 1e3 },
    { label: 'Base robada con bcrypt', detail: 'coste 12, buena práctica clásica', rate: 1.4e3 },
    { label: 'Base robada con SHA-256', detail: 'prohibido para contraseñas', rate: 2.2e10 },
    { label: 'Base robada con MD5', detail: 'prohibido para contraseñas', rate: 1.6e11 },
  ];

  const COMMON = new Set([
    '123456', '123456789', '12345678', '12345', '1234567', '1234567890', '111111', '000000', '123123', 'qwerty',
    'qwerty123', 'password', 'password1', 'contraseña', 'contrasena', 'admin', 'admin123', 'abc123', 'iloveyou',
    'teamo', 'hola123', 'letmein', 'welcome', 'monkey', 'dragon', 'football', 'futbol', 'sigilo', 'secreto',
    'colombia', 'mexico', 'argentina', 'princesa', 'superman', 'batman', 'passw0rd', 'p@ssw0rd', '1q2w3e4r', 'asdfgh',
  ]);
  const WORD_PATTERN = /^([a-záéíóúüñ]{1,14})(\d{0,4})([!.?*#@$]?)$/i;

  const YEAR = 365.25 * 24 * 3600;
  const UNIVERSE = 1.38e10 * YEAR;

  // ---------- Formato ----------

  const sup = (n) => String(n).replace(/\d/g, (d) => '⁰¹²³⁴⁵⁶⁷⁸⁹'[d]);

  // Exacto si cabe; si no, notación científica: 6,28 × 10⁵⁷
  const bigToText = (big) => {
    const digits = big.toString();
    if (digits.length <= 15) return Number(big).toLocaleString('es');
    return `${digits[0]},${digits.slice(1, 3)} × 10${sup(digits.length - 1)}`;
  };

  const numToText = (n) => {
    if (n < 1e15) return Math.round(n).toLocaleString('es');
    const exp = Math.floor(Math.log10(n));
    return `${(n / 10 ** exp).toFixed(2).replace('.', ',')} × 10${sup(exp)}`;
  };

  const plural = (n, one, many) => `${n.toLocaleString('es')} ${n === 1 ? one : many}`;
  const duration = (seconds) => {
    if (!Number.isFinite(seconds)) return 'incalculable: supera cualquier escala';
    if (seconds < 1) return 'menos de 1 segundo';
    if (seconds < 60) return plural(Math.round(seconds), 'segundo', 'segundos');
    if (seconds < 3600) return plural(Math.round(seconds / 60), 'minuto', 'minutos');
    if (seconds < 86400) return plural(Math.round(seconds / 3600), 'hora', 'horas');
    if (seconds < YEAR) return plural(Math.round(seconds / 86400), 'día', 'días');
    if (seconds > UNIVERSE) return `${numToText(seconds / UNIVERSE)} veces la edad del universo`;
    const years = seconds / YEAR;
    if (years < 1e3) return plural(Math.round(years), 'año', 'años');
    if (years < 1e6) return `${Math.round(years / 1e3).toLocaleString('es')} mil años`;
    if (years < 1e9) {
      const millions = Math.round(years / 1e6);
      return `${millions.toLocaleString('es')} ${millions === 1 ? 'millón' : 'millones'} de años`;
    }
    return `${(years / 1e9).toFixed(1).replace('.', ',')} mil millones de años`;
  };

  const rateText = (rate) => (rate < 1 ? `1 cada ${Math.round(1 / rate / 60)} min` : `${numToText(rate)} / s`);

  // ---------- Análisis ----------

  const analyze = (pw) => {
    const chars = [...pw];
    const classes = CLASSES.filter((c) => c.test.test(pw));
    const alphabet = classes.reduce((sum, c) => sum + c.size, 0);
    const combos = BigInt(alphabet) ** BigInt(chars.length);
    const bits = chars.length * Math.log2(alphabet || 1);

    // Intentos que necesita un atacante: promedio (mitad del espacio) y peor caso (todo el espacio).
    let kind = 'random';
    let average = Number(combos) / 2;
    if (COMMON.has(pw.toLowerCase())) {
      kind = 'common';
      average = 10;
    } else if (WORD_PATTERN.test(pw)) {
      kind = 'word';
      const [, , digits, symbol] = WORD_PATTERN.exec(pw);
      // ~300 000 palabras y nombres × variantes de mayúsculas × números finales × símbolo final.
      average = (3e5 * 4 * 10 ** digits.length * (symbol ? 10 : 1)) / 2;
    } else if (new Set(chars).size <= 2 && chars.length > 2) {
      kind = 'repeat';
      average = alphabet * alphabet * chars.length;
    }

    const policy = [
      { ok: chars.length >= 12, label: '12 caracteres o más' },
      { ok: /[a-z]/.test(pw), label: 'una minúscula' },
      { ok: /[A-Z]/.test(pw), label: 'una mayúscula' },
      { ok: /[0-9]/.test(pw), label: 'un número' },
      { ok: /[^A-Za-z0-9]/.test(pw), label: 'un símbolo' },
    ];

    return { length: chars.length, classes, alphabet, combos, bits, kind, average, worst: average * 2, policy };
  };

  // ---------- Pintado ----------

  const set = (id, text) => {
    const el = $(id);
    if (el) el.textContent = text;
  };

  const barWidth = (seconds) =>
    seconds <= 1 ? 2 : Math.min(100, Math.max(2, (Math.log10(seconds) / Math.log10(UNIVERSE)) * 100));
  const level = (seconds) => (seconds < 86400 ? 'weak' : seconds < 100 * YEAR ? 'fair' : 'strong');

  const NOTES = {
    common:
      'Es una de las contraseñas más usadas: los diccionarios la prueban entre los primeros 10 intentos. Los tiempos usan ese número, no todas las combinaciones.',
    word: 'Parece una palabra con números o un símbolo al final. Un diccionario la encuentra sin recorrer todas las combinaciones, así que los tiempos usan esa estimación.',
    repeat: 'Repite casi siempre el mismo carácter: se adivina con muy pocos intentos.',
    random:
      'Si la elegiste al azar, quien ataca tiene que recorrer las combinaciones una por una. En promedio acierta a mitad de camino; en el peor caso, en la última.',
  };

  const cell = (main, sub, label) => {
    const td = document.createElement('td');
    if (label) td.dataset.label = label;
    td.textContent = main;
    if (sub) {
      const small = document.createElement('small');
      small.textContent = sub;
      td.append(small);
    }
    return td;
  };

  const render = () => {
    const pw = input.value;
    out.hidden = !pw;
    if (!pw) return;
    const a = analyze(pw);

    set('m-length', `${a.length} ${a.length === 1 ? 'carácter' : 'caracteres'}`);
    set('m-alphabet', `${a.alphabet} por posición`);
    set('m-alphabet-detail', a.classes.map((c) => `${c.label} (${c.size})`).join(' + '));
    set('m-formula', `${a.alphabet}${sup(a.length)} =`);
    set('m-combos', bigToText(a.combos));
    set('m-bits', `${Math.round(a.bits)} bits de entropía`);
    set('m-average', a.kind === 'random' ? bigToText(a.combos / 2n || 1n) : numToText(a.average));
    set('m-note', NOTES[a.kind]);
    out.dataset.kind = a.kind;

    $('m-policy').replaceChildren(
      ...a.policy.map((p) => {
        const li = document.createElement('li');
        li.className = p.ok ? 'ok' : 'missing';
        li.textContent = `${p.ok ? '✓' : '✗'} ${p.label}`;
        return li;
      }),
    );
    set('m-policy-verdict', a.policy.every((p) => p.ok) ? 'Sigilo la aceptaría.' : 'Sigilo la rechazaría al crear la cuenta.');

    $('m-scenarios').replaceChildren(
      ...SCENARIOS.map((s) => {
        const avg = a.average / s.rate;
        const tr = document.createElement('tr');
        tr.dataset.level = level(avg);
        tr.append(
          cell(s.label, s.detail),
          cell(rateText(s.rate), null, 'Velocidad'),
          cell(duration(avg), null, 'Tiempo promedio'),
          cell(duration(a.worst / s.rate), null, 'Peor caso'),
        );
        const barCell = document.createElement('td');
        barCell.className = 'bar-cell';
        const bar = document.createElement('span');
        bar.className = 'meter-bar';
        const fill = document.createElement('span');
        fill.style.width = `${barWidth(avg)}%`;
        bar.append(fill);
        barCell.append(bar);
        tr.append(barCell);
        return tr;
      }),
    );
  };

  input.addEventListener('input', render);
  toggle?.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    toggle.textContent = show ? 'Ocultar' : 'Mostrar';
    toggle.setAttribute('aria-pressed', String(show));
  });
  render();
})();
