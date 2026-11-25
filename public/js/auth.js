// Interacciones de las pantallas de acceso. Sin JavaScript los formularios funcionan igual;
// esto solo agrega ayudas y movimiento. Las contraseñas nunca salen del formulario.
(() => {
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const form = document.querySelector('[data-auth-form]');
  const seal = document.querySelector('.auth-brand .seal-lg');
  const brand = document.querySelector('.auth-brand');

  // ---------- Mostrar / ocultar contraseña ----------
  document.querySelectorAll('.auth-form input[type="password"]').forEach((input) => {
    const wrap = document.createElement('div');
    wrap.className = 'pw-wrap';
    input.parentNode.insertBefore(wrap, input);
    wrap.append(input);
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'pw-toggle';
    toggle.textContent = 'Mostrar';
    toggle.setAttribute('aria-pressed', 'false');
    toggle.setAttribute('aria-label', 'Mostrar contraseña');
    toggle.addEventListener('click', () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      toggle.textContent = show ? 'Ocultar' : 'Mostrar';
      toggle.setAttribute('aria-pressed', String(show));
      toggle.setAttribute('aria-label', show ? 'Ocultar contraseña' : 'Mostrar contraseña');
      input.focus();
    });
    wrap.append(toggle);

    // ---------- Aviso de Bloq Mayús ----------
    const caps = document.createElement('p');
    caps.className = 'caps-warning';
    caps.hidden = true;
    caps.setAttribute('role', 'status');
    caps.textContent = 'Bloq Mayús está activado.';
    wrap.after(caps);
    const checkCaps = (e) => {
      if (typeof e.getModifierState === 'function') caps.hidden = !e.getModifierState('CapsLock');
    };
    input.addEventListener('keydown', checkCaps);
    input.addEventListener('keyup', checkCaps);
    input.addEventListener('blur', () => (caps.hidden = true));
  });

  // ---------- Fuerza de la contraseña (misma política que el servidor) ----------
  const COMMON = /^(123456|password|contraseña|qwerty|admin|abc123|iloveyou|teamo|sigilo)/i;
  document.querySelectorAll('[data-strength]').forEach((input) => {
    const field = input.closest('.field');
    const staticHint = field.querySelector('.hint');
    const box = document.createElement('div');
    box.className = 'strength';
    box.id = `${input.id}-strength`;
    box.setAttribute('aria-live', 'polite');
    box.innerHTML =
      '<div class="strength-bar"><span></span></div><ul class="checks"></ul><span class="strength-label"></span>';
    const rules = [
      { label: '12+ caracteres', test: (v) => [...v].length >= 12 },
      { label: 'minúscula', test: (v) => /[a-z]/.test(v) },
      { label: 'mayúscula', test: (v) => /[A-Z]/.test(v) },
      { label: 'número', test: (v) => /[0-9]/.test(v) },
      { label: 'símbolo', test: (v) => /[^A-Za-z0-9]/.test(v) },
    ];
    const list = box.querySelector('.checks');
    const items = rules.map((r) => {
      const li = document.createElement('li');
      li.textContent = r.label;
      list.append(li);
      return li;
    });
    const label = box.querySelector('.strength-label');
    if (staticHint) staticHint.replaceWith(box);
    else field.append(box);
    input.setAttribute('aria-describedby', box.id);

    const LABELS = ['', 'Muy débil', 'Débil', 'Aceptable', 'Fuerte'];
    const update = () => {
      const v = input.value;
      const passed = rules.map((r, i) => {
        const ok = r.test(v);
        items[i].classList.toggle('ok', ok);
        return ok;
      });
      const count = passed.filter(Boolean).length;
      let level = !v ? 0 : count <= 2 ? 1 : count <= 4 ? 2 : [...v].length >= 16 ? 4 : 3;
      if (v && COMMON.test(v)) level = 1;
      box.dataset.level = String(level);
      label.textContent = v
        ? `${LABELS[level]}${count === 5 ? '' : ` (faltan ${5 - count} requisito${5 - count === 1 ? '' : 's'})`}`
        : '';
    };
    input.addEventListener('input', update);
    update();
  });

  // ---------- ¿Coinciden las contraseñas? ----------
  document.querySelectorAll('[data-match]').forEach((input) => {
    const other = document.getElementById(input.dataset.match);
    if (!other) return;
    const msg = document.createElement('p');
    msg.className = 'match';
    msg.setAttribute('aria-live', 'polite');
    input.closest('.field').append(msg);
    const update = () => {
      if (!input.value) {
        msg.textContent = '';
        msg.className = 'match';
        return;
      }
      const same = input.value === other.value;
      msg.textContent = same ? 'Las contraseñas coinciden.' : 'Todavía no coinciden.';
      msg.className = `match ${same ? 'ok' : 'bad'}`;
    };
    input.addEventListener('input', update);
    other.addEventListener('input', update);
  });

  // ---------- Cuentas de prueba (solo aparecen en desarrollo local) ----------
  document.querySelectorAll('[data-fill-email]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const email = document.getElementById('email');
      const password = document.getElementById('password');
      if (!email || !password) return;
      email.value = btn.dataset.fillEmail;
      password.value = btn.dataset.fillPassword;
      email.dispatchEvent(new Event('input', { bubbles: true }));
      password.dispatchEvent(new Event('input', { bubbles: true }));
      form?.querySelector('button[type="submit"]')?.focus();
    });
  });

  // ---------- Envío: botón "Verificando…" y sin doble envío ----------
  if (form) {
    let sent = false;
    form.addEventListener('submit', (e) => {
      if (sent) {
        e.preventDefault();
        return;
      }
      sent = true;
      const submit = form.querySelector('button[type="submit"]');
      if (submit) {
        submit.setAttribute('aria-busy', 'true');
        submit.textContent = 'Verificando…';
      }
      if (seal && !reduceMotion) {
        seal.classList.remove('is-sealing');
        void seal.getBoundingClientRect();
        seal.classList.add('is-sealing');
      }
    });
  }

  // Si el servidor devolvió un error, el formulario da una sacudida breve.
  if (!reduceMotion && document.querySelector('.auth-form .msg-error')) {
    document.querySelector('.auth-form').classList.add('is-error');
  }

  if (reduceMotion || !seal || !brand) return;

  // ---------- El sello gira como un dial con cada tecla ----------
  let dial = 0;
  document.querySelectorAll('.auth-form input').forEach((input) => {
    input.addEventListener('input', (e) => {
      const deleting = e.inputType && e.inputType.startsWith('delete');
      dial += deleting ? -15 : 15;
      seal.style.setProperty('--dial', `${dial}deg`);
    });
  });

  // ---------- El panel sigue suavemente al cursor ----------
  const mark = brand.querySelector('.auth-mark');
  const rosette = brand.querySelector('.guilloche');
  if (window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
    document.addEventListener('pointermove', (e) => {
      const x = e.clientX / window.innerWidth - 0.5;
      const y = e.clientY / window.innerHeight - 0.5;
      if (mark) mark.style.translate = `${(x * 18).toFixed(1)}px ${(y * 14).toFixed(1)}px`;
      if (rosette) rosette.style.translate = `${(-x * 40).toFixed(1)}px ${(-y * 30).toFixed(1)}px`;
    });
  }
})();
