// Movimiento de la portada. Sin JavaScript (o con "reducir movimiento") todo se ve completo y estático.
(() => {
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const root = document.documentElement;

  // 0. Fondo del hero: la nota cifrada real extendida como trama. Los caracteres que
  //    parpadean son intentos de un ataque; el cifrado los rechaza y vuelve a su valor.
  //    Cerca del cursor los intentos se intensifican.
  const field = document.querySelector('.hero-field');
  const source = [...document.querySelectorAll('.evidence code')].map((c) => c.textContent.trim()).join('');
  if (field && source && field.getContext) startField(field, source, reduceMotion);

  if (reduceMotion) return;

  // 1. Al cargar: el hash y la nota cifrada se "descifran" de izquierda a derecha,
  //    como un ataque que prueba caracteres hasta dar con el valor guardado.
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=$';
  const scramble = (el, duration) => {
    const target = el.textContent;
    const start = performance.now();
    el.setAttribute('aria-label', target);
    const frame = (now) => {
      const progress = Math.min(1, (now - start) / duration);
      const locked = Math.floor(target.length * progress);
      let text = target.slice(0, locked);
      for (let i = locked; i < target.length; i++) {
        text += target[i] === '.' || target[i] === '$' ? target[i] : ALPHABET[(Math.random() * ALPHABET.length) | 0];
      }
      el.textContent = text;
      if (progress < 1) requestAnimationFrame(frame);
      else el.removeAttribute('aria-label');
    };
    requestAnimationFrame(frame);
  };
  document.querySelectorAll('[data-scramble]').forEach((el, i) => scramble(el, 1100 + i * 500));

  // 2. Al hacer scroll: el sello del menú gira como el dial de una caja fuerte.
  const dial = document.querySelector('.home .brand .seal');
  if (dial) {
    let ticking = false;
    const turn = () => {
      dial.style.transform = `rotate(${(window.scrollY * 0.25) % 360}deg)`;
      ticking = false;
    };
    window.addEventListener(
      'scroll',
      () => {
        if (!ticking) {
          ticking = true;
          requestAnimationFrame(turn);
        }
      },
      { passive: true },
    );
  }

  // 4. Los contadores suben desde cero cuando aparecen.
  const countUp = (el) => {
    const target = Number(el.dataset.count);
    if (!target) return;
    const start = performance.now();
    const duration = Math.min(1600, 500 + target * 40);
    const frame = (now) => {
      const p = Math.min(1, (now - start) / duration);
      el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3))).toLocaleString('es');
      if (p < 1) requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  };

  // 3. Apariciones al entrar en pantalla. Lo que ya se ve al cargar no se oculta.
  const reveals = [...document.querySelectorAll('[data-reveal]')];
  const inView = (el) => el.getBoundingClientRect().top < window.innerHeight * 0.9;
  reveals.filter(inView).forEach((el) => {
    el.classList.add('is-in');
    el.querySelectorAll('[data-count]').forEach((n) => requestAnimationFrame(() => countUp(n)));
  });
  root.classList.add('motion');

  if (!('IntersectionObserver' in window)) {
    reveals.forEach((el) => el.classList.add('is-in'));
    return;
  }
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) reveal(entry.target);
      }
    },
    { rootMargin: '0px 0px -12% 0px' },
  );
  const reveal = (el) => {
    if (el.classList.contains('is-in')) return;
    el.classList.add('is-in');
    el.querySelectorAll('[data-count]').forEach(countUp);
    observer.unobserve(el);
  };
  reveals.filter((el) => !el.classList.contains('is-in')).forEach((el) => observer.observe(el));

  // Saltos bruscos (enlaces #reto, tecla Fin): lo que quedó por encima también se muestra.
  let pending = false;
  const catchUp = () => {
    pending = false;
    for (const el of reveals) if (el.getBoundingClientRect().top < window.innerHeight) reveal(el);
  };
  window.addEventListener('scroll', () => {
    if (!pending) {
      pending = true;
      requestAnimationFrame(catchUp);
    }
  }, { passive: true });
  window.addEventListener('hashchange', catchUp);
})();

function startField(canvas, source, still) {
  const GLYPHS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=$.';
  const BG = '#2e3fd1';
  const FONT_PX = 13;
  const CELL_W = 11;
  const CELL_H = 21;
  const ctx = canvas.getContext('2d');
  const base = document.createElement('canvas');
  const baseCtx = base.getContext('2d');
  let cols = 0;
  let rows = 0;
  let dpr = 1;
  let active = new Map(); // índice de celda -> { char, until, born }
  let pointer = null;
  let running = false;
  let visible = true;
  let last = 0;

  const charAt = (i) => source[i % source.length];
  const font = () => `${FONT_PX}px ui-monospace, "Cascadia Mono", Consolas, monospace`;

  const layout = () => {
    const rect = canvas.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    for (const c of [canvas, base]) {
      c.width = Math.round(rect.width * dpr);
      c.height = Math.round(rect.height * dpr);
    }
    cols = Math.ceil(rect.width / CELL_W) + 1;
    rows = Math.ceil(rect.height / CELL_H) + 1;
    baseCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
    baseCtx.fillStyle = BG;
    baseCtx.fillRect(0, 0, rect.width, rect.height);
    baseCtx.font = font();
    baseCtx.textBaseline = 'top';
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        // Cada fila arranca en otro punto del texto cifrado para que no se vean columnas repetidas.
        const i = r * 37 + c;
        baseCtx.fillStyle = `rgba(243, 245, 255, ${0.06 + ((i * 7919) % 5) * 0.012})`;
        baseCtx.fillText(charAt(i), c * CELL_W, r * CELL_H + 3);
      }
    }
    active = new Map();
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.drawImage(base, 0, 0);
  };

  const spawn = (now, count, near) => {
    for (let k = 0; k < count; k++) {
      let c;
      let r;
      if (near && pointer) {
        const angle = Math.random() * Math.PI * 2;
        const dist = Math.random() * 150;
        c = Math.floor((pointer.x + Math.cos(angle) * dist) / CELL_W);
        r = Math.floor((pointer.y + Math.sin(angle) * dist) / CELL_H);
      } else {
        c = (Math.random() * cols) | 0;
        r = (Math.random() * rows) | 0;
      }
      if (c < 0 || r < 0 || c >= cols || r >= rows) continue;
      const life = 140 + Math.random() * 520;
      active.set(r * cols + c, { char: GLYPHS[(Math.random() * GLYPHS.length) | 0], born: now, until: now + life });
    }
  };

  const draw = (now) => {
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.drawImage(base, 0, 0);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    if (pointer) {
      const glow = ctx.createRadialGradient(pointer.x, pointer.y, 0, pointer.x, pointer.y, 220);
      glow.addColorStop(0, 'rgba(160, 172, 255, 0.22)');
      glow.addColorStop(1, 'rgba(160, 172, 255, 0)');
      ctx.fillStyle = glow;
      ctx.fillRect(pointer.x - 220, pointer.y - 220, 440, 440);
    }

    ctx.font = font();
    ctx.textBaseline = 'top';
    for (const [index, cell] of active) {
      if (now >= cell.until) {
        active.delete(index);
        continue;
      }
      const c = index % cols;
      const r = (index / cols) | 0;
      const x = c * CELL_W;
      const y = r * CELL_H;
      const t = (now - cell.born) / (cell.until - cell.born);
      ctx.fillStyle = BG;
      ctx.fillRect(x, y, CELL_W, CELL_H);
      ctx.fillStyle = `rgba(214, 220, 255, ${0.75 * (1 - t) + 0.08})`;
      ctx.fillText(cell.char, x, y + 3);
    }
  };

  const tick = (now) => {
    if (!running) return;
    if (now - last >= 33) {
      // ~30 fotogramas por segundo bastan y gastan la mitad de batería.
      const area = cols * rows;
      spawn(now, Math.max(1, Math.round(area * 0.0016)), false);
      if (pointer) spawn(now, 7, true);
      draw(now);
      last = now;
    }
    requestAnimationFrame(tick);
  };

  const play = () => {
    if (still || running || !visible || document.hidden) return;
    running = true;
    requestAnimationFrame(tick);
  };
  const pause = () => {
    running = false;
  };

  layout();
  if (still) return;

  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(layout, 150);
  });

  const band = canvas.parentElement;
  band.addEventListener('pointermove', (e) => {
    const rect = canvas.getBoundingClientRect();
    pointer = { x: e.clientX - rect.left, y: e.clientY - rect.top };
  });
  band.addEventListener('pointerleave', () => {
    pointer = null;
  });

  if ('IntersectionObserver' in window) {
    new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      if (visible) play();
      else pause();
    }).observe(band);
  }
  document.addEventListener('visibilitychange', () => (document.hidden ? pause() : play()));
  play();
}
