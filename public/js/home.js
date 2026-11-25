// Movimiento de la portada. Sin JavaScript (o con "reducir movimiento") todo se ve completo y estático.
(() => {
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduceMotion) return;
  const root = document.documentElement;

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
