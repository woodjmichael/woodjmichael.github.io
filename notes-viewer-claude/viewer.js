(() => {
    // Each page sets window.NOTES_VIEWER = { dataDir, mode: 'tree' | 'single' } before loading this file
    const CFG = window.NOTES_VIEWER;
    const DATA = CFG.dataDir;
    const SINGLE = CFG.mode === 'single';
    const KEY_STORE = 'notes-viewer-key:' + DATA;
    const $ = (id) => document.getElementById(id);

    let key = null;
    let bundle = null;
    const imageCache = new Map();

    // ---------- crypto ----------
    const b64 = {
      enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
      dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
    };

    async function fetchBytes(url) {
      const r = await fetch(url, { cache: 'no-cache' });
      if (!r.ok) throw new Error(`Could not load ${url} (${r.status})`);
      return new Uint8Array(await r.arrayBuffer());
    }

    // File layout from build.mjs: 12-byte IV, then ciphertext with the GCM tag appended
    async function decrypt(bytes) {
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, key, bytes.slice(12));
    }

    async function deriveKey(passphrase) {
      const meta = await (await fetch(DATA + 'meta.json', { cache: 'no-cache' })).json();
      const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
      return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: b64.dec(meta.salt), iterations: meta.iterations, hash: 'SHA-256' },
        base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
    }

    async function loadBundle() {
      const plain = await decrypt(await fetchBytes(DATA + 'notes.bin'));
      const stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'));
      return JSON.parse(await new Response(stream).text());
    }

    function saveKey(raw) { try { sessionStorage.setItem(KEY_STORE, b64.enc(raw)); } catch {} }
    function forgetKey() { try { sessionStorage.removeItem(KEY_STORE); } catch {} }
    function storedKey() { try { return sessionStorage.getItem(KEY_STORE); } catch { return null; } }

    async function unlockWith(k) {
      key = k;
      bundle = await loadBundle();
      $('lock').style.display = 'none';
      $('app').classList.add('open');
      if (SINGLE) {
        showSideTab('outline');
      } else {
        showSideTab('notes');
        buildTree();
      }
      route();
    }

    $('lock-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = $('unlock-btn');
      btn.disabled = true;
      btn.textContent = 'Unlocking…';
      $('lock-error').textContent = '';
      try {
        const k = await deriveKey($('pass').value);
        await unlockWith(k);
        saveKey(await crypto.subtle.exportKey('raw', k));
      } catch (err) {
        key = null;
        $('lock-error').textContent = err.name === 'OperationError' ? 'Wrong passphrase.' : err.message;
      } finally {
        btn.disabled = false;
        btn.textContent = 'Unlock';
      }
    });

    $('lock-btn').addEventListener('click', () => {
      forgetKey();
      location.hash = '';
      location.reload();
    });

    // ---------- paths ----------
    function normalize(p) {
      const out = [];
      for (const part of p.split('/')) {
        if (!part || part === '.') continue;
        if (part === '..') out.pop();
        else out.push(part);
      }
      return out.join('/');
    }
    function dirOf(p) { return p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : ''; }
    function baseOf(p) { return p.slice(p.lastIndexOf('/') + 1); }
    function title(p) { return baseOf(p).replace(/\.md$/i, ''); }
    function safeDecode(s) { try { return decodeURIComponent(s); } catch { return s; } }
    function isExternal(href) { return /^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('//'); }

    // Typora wrote many image paths that no longer match the folder layout,
    // so fall back to a unique file-name match anywhere in the notes.
    function findImage(notePath, src) {
      const clean = safeDecode(src.split(/[?#]/)[0]).replace(/\\/g, '/');
      const direct = normalize(dirOf(notePath) + '/' + clean);
      if (bundle.images[direct]) return bundle.images[direct];
      const name = baseOf(clean);
      const hits = Object.keys(bundle.images).filter((p) => baseOf(p) === name);
      return hits.length ? bundle.images[hits[0]] : null;
    }

    async function imageUrl(img) {
      if (!imageCache.has(img.id)) {
        imageCache.set(img.id, (async () => {
          const plain = await decrypt(await fetchBytes(`${DATA}img/${img.id}.bin`));
          return URL.createObjectURL(new Blob([plain], { type: img.type }));
        })());
      }
      return imageCache.get(img.id);
    }

    // ---------- sidebar ----------
    function sortedNotes() {
      return Object.keys(bundle.notes).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
    }

    function noteLink(p, extra) {
      const a = document.createElement('a');
      a.href = '#/' + encodeURI(p);
      a.dataset.path = p;
      a.textContent = title(p);
      if (extra) a.append(extra);
      return a;
    }

    function buildTree() {
      const root = { files: [], dirs: {} };
      for (const p of sortedNotes()) {
        const parts = p.split('/');
        let node = root;
        for (const d of parts.slice(0, -1)) node = node.dirs[d] ??= { files: [], dirs: {} };
        node.files.push(p);
      }
      const render = (node, container) => {
        for (const p of node.files) container.append(noteLink(p));
        const dirs = Object.keys(node.dirs).sort((a, b) => {
          // keep archive folders at the bottom
          const wa = a.toLowerCase() === 'archive', wb = b.toLowerCase() === 'archive';
          return wa - wb || a.localeCompare(b, undefined, { sensitivity: 'base' });
        });
        for (const d of dirs) {
          const det = document.createElement('details');
          const sum = document.createElement('summary');
          sum.textContent = d;
          const kids = document.createElement('div');
          kids.className = 'children';
          det.append(sum, kids);
          render(node.dirs[d], kids);
          container.append(det);
        }
      };
      const tree = $('tree');
      tree.replaceChildren();
      render(root, tree);
      markActive();
    }

    function runSearch(q) {
      const tree = $('tree');
      q = q.trim().toLowerCase();
      if (!q) return buildTree();
      const results = [];
      for (const p of sortedNotes()) {
        const inTitle = p.toLowerCase().includes(q);
        const text = bundle.notes[p].toLowerCase();
        let count = 0, i = -1;
        while ((i = text.indexOf(q, i + 1)) !== -1) count++;
        if (inTitle || count) results.push({ p, inTitle, count });
      }
      results.sort((a, b) => b.inTitle - a.inTitle || b.count - a.count);
      tree.replaceChildren();
      if (!results.length) {
        const d = document.createElement('div');
        d.className = 'empty';
        d.textContent = 'No matches.';
        tree.append(d);
        return;
      }
      for (const r of results) {
        const extra = document.createDocumentFragment();
        if (r.count) {
          const c = document.createElement('span');
          c.className = 'hit-count';
          c.textContent = `(${r.count})`;
          extra.append(c);
        }
        if (dirOf(r.p)) {
          const s = document.createElement('span');
          s.className = 'path';
          s.textContent = dirOf(r.p);
          extra.append(s);
        }
        tree.append(noteLink(r.p, extra));
      }
      markActive();
    }

    let searchTimer;
    $('search')?.addEventListener('input', (e) => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => runSearch(e.target.value), 120);
    });

    function currentPath() {
      const h = location.hash;
      return h.startsWith('#/') ? safeDecode(h.slice(2)) : null;
    }

    function markActive() {
      const cur = currentPath();
      for (const a of $('tree').querySelectorAll('a')) {
        const on = a.dataset.path === cur;
        a.classList.toggle('active', on);
        if (on) {
          for (let d = a.parentElement.closest('details'); d; d = d.parentElement.closest('details')) d.open = true;
        }
      }
    }

    // ---------- rendering ----------
    function slug(s) {
      return s.toLowerCase().trim().replace(/[^\p{L}\p{N}\s-]/gu, '').replace(/\s+/g, '-');
    }

    // The shortcodes Typora renders as emoji; unknown ones stay as text
    const EMOJI = {
      slightly_smiling_face: '🙂', slightly_frowning_face: '🙁', neutral_face: '😐', smile: '😄', happy: '😊',
      pensive: '😔', weary: '😩', flushed: '😳', sleeping: '😴', face_with_thermometer: '🤒',
      sun_with_face: '🌞', sunny: '☀️', partly_sunny: '⛅', sun_behind_small_cloud: '🌤️',
      sun_behind_large_cloud: '🌥️', sun_behind_rain_cloud: '🌦️', cloud: '☁️', cloud_with_rain: '🌧️',
      snowflake: '❄️', sunrise: '🌅', night_with_stars: '🌃', fire: '🔥', arrow_right: '➡️',
      musical_note: '🎵', memo: '📝', eye: '👁️', handshake: '🤝', dancer: '💃',
      two_men_holding_hands: '👬', no_mobile_phones: '📵',
      cyclone: '🌀', cloud_with_snow: '🌨️', cloud_with_lightning_and_rain: '⛈️', cake: '🍰', airplane: '✈️',
    };

    function emojify(root) {
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      const nodes = [];
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        if (!n.parentElement?.closest('pre, code') && n.nodeValue.includes(':')) nodes.push(n);
      }
      for (const n of nodes) {
        n.nodeValue = n.nodeValue.replace(/:([a-z0-9_+-]+):/g, (m, name) => EMOJI[name] ?? m);
      }
    }

    function preprocess(md) {
      md = md.replace(/^\uFEFF/, '');
      // Typora accepts spaces in link targets; CommonMark needs them wrapped in <...>
      md = md.replace(/(!?\[[^\]\n]*\]\()([^)<>"\n]*? [^)<>"\n]*?)\)/g, '$1<$2>)');
      // ==highlight==
      md = md.replace(/==([^=\n]+)==/g, '<mark>$1</mark>');
      return md;
    }

    function showWelcome() {
      $('crumbs').textContent = '';
      const n = Object.keys(bundle.notes).length;
      const built = new Date(bundle.built).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
      const note = $('note');
      note.replaceChildren();
      const h = document.createElement('h1');
      h.textContent = CFG.title;
      const p = document.createElement('p');
      p.textContent = `${n} notes, last built ${built}. Pick one from the list or search.`;
      note.append(h, p);
      document.title = CFG.title;
      buildOutline();
    }

    function renderNote(path) {
      const src = bundle.notes[path];
      if (src == null) {
        $('crumbs').textContent = '';
        $('note').innerHTML = '<h1>Not found</h1>';
        $('note').querySelector('h1').insertAdjacentText('afterend', `No note at "${path}".`);
        return;
      }
      document.title = SINGLE ? CFG.title : `${title(path)} · ${CFG.title}`;
      $('crumbs').textContent = dirOf(path).split('/').filter(Boolean).join(' / ');

      // Parse into a <template> so relative <img> sources are never fetched from the server
      const tpl = document.createElement('template');
      tpl.innerHTML = DOMPurify.sanitize(marked.parse(preprocess(src), { gfm: true, breaks: false }));
      const frag = tpl.content;

      const used = new Set();
      for (const h of frag.querySelectorAll('h1,h2,h3,h4,h5,h6')) {
        // The prefix keeps heading ids from colliding with the page's own ids (note, search, ...)
        const base = 'h-' + (slug(h.textContent) || 'section');
        let id = base, n = 1;
        while (used.has(id)) id = `${base}-${n++}`;
        used.add(id);
        h.id = id;
      }

      for (const t of frag.querySelectorAll('table')) {
        const wrap = document.createElement('div');
        wrap.className = 'table-wrap';
        t.replaceWith(wrap);
        wrap.append(t);
      }

      for (const a of frag.querySelectorAll('a[href]')) {
        const href = a.getAttribute('href');
        if (href.startsWith('#')) {
          a.dataset.anchor = 'h-' + slug(safeDecode(href.slice(1)));
        } else if (isExternal(href)) {
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
        } else {
          const [file, frag2] = href.split('#');
          const target = normalize(dirOf(path) + '/' + safeDecode(file));
          if (bundle.notes[target] != null) {
            a.setAttribute('href', '#/' + encodeURI(target));
            if (frag2) a.dataset.anchorAfter = 'h-' + slug(safeDecode(frag2));
          } else {
            a.removeAttribute('href');
            a.title = `${file} (not in the published notes)`;
          }
        }
      }

      const pending = [];
      for (const img of frag.querySelectorAll('img')) {
        const srcAttr = img.getAttribute('src') || '';
        img.removeAttribute('src');
        img.loading = 'lazy';
        if (srcAttr.startsWith('data:') || /^https?:/i.test(srcAttr)) { img.src = srcAttr; continue; }
        const found = findImage(path, srcAttr);
        if (!found) {
          img.classList.add('missing');
          img.alt = `[missing image: ${img.alt || baseOf(srcAttr)}]`;
          continue;
        }
        pending.push(imageUrl(found).then((u) => { img.src = u; }).catch(() => img.classList.add('missing')));
      }

      emojify(frag);
      const note = $('note');
      note.replaceChildren(frag);
      $('main').scrollTop = 0;
      buildOutline();
      return Promise.all(pending);
    }

    // ---------- outline ----------
    let spy = null;

    function goToHeading(id) {
      const el = document.getElementById(id);
      if (!el) return;
      // Images above the target load lazily and shift it, so re-aim for a moment after jumping
      let tries = 0;
      const aim = () => {
        const off = el.getBoundingClientRect().top - $('main').getBoundingClientRect().top;
        if (Math.abs(off) > 4) el.scrollIntoView({ block: 'start' });
        if (++tries < 8) setTimeout(aim, 150);
      };
      aim();
      $('app').classList.remove('nav-open');
    }

    function buildOutline() {
      const nav = $('outline');
      nav.replaceChildren();
      const heads = [...$('note').querySelectorAll('h1,h2,h3,h4,h5,h6')];
      if (!heads.length) {
        const d = document.createElement('div');
        d.className = 'empty';
        d.textContent = 'No headings in this note.';
        nav.append(d);
      }
      const top = Math.min(...heads.map((h) => +h.tagName[1]));
      const links = new Map();
      for (const h of heads) {
        const a = document.createElement('a');
        a.href = '#' + h.id;
        a.textContent = h.textContent.trim();
        a.title = a.textContent;
        a.style.paddingLeft = `calc(8px + ${(+h.tagName[1] - top) * 14}px)`;
        a.addEventListener('click', (e) => { e.preventDefault(); goToHeading(h.id); });
        nav.append(a);
        links.set(h, a);
      }
      spy?.disconnect();
      if (!heads.length) return;
      // The current section is the last heading that has scrolled past the top of the page
      let current = null;
      const update = () => {
        const line = $('main').getBoundingClientRect().top + 80;
        let hit = heads[0];
        for (const h of heads) if (h.getBoundingClientRect().top <= line) hit = h; else break;
        if (hit === current) return;
        links.get(current)?.classList.remove('active');
        current = hit;
        const a = links.get(hit);
        a.classList.add('active');
        if ($('outline').offsetParent) a.scrollIntoView({ block: 'nearest' });
      };
      const main = $('main');
      main.addEventListener('scroll', update, { passive: true });
      spy = { disconnect: () => main.removeEventListener('scroll', update) };
      update();
    }

    function showSideTab(name) {
      for (const [id, tab] of [['tree', 'notes'], ['search', 'notes'], ['outline', 'outline']]) {
        const el = $(id);
        if (el) el.hidden = name !== tab;
      }
      for (const b of document.querySelectorAll('#side-tabs button')) {
        b.classList.toggle('on', b.dataset.tab === name);
      }
    }

    for (const b of document.querySelectorAll('#side-tabs button')) {
      b.addEventListener('click', () => showSideTab(b.dataset.tab));
    }

    function route() {
      if (!bundle) return;
      $('app').classList.remove('nav-open');
      if (SINGLE) { renderNote(Object.keys(bundle.notes)[0]); return; }
      const p = currentPath();
      if (p) renderNote(p); else showWelcome();
      markActive();
    }

    window.addEventListener('hashchange', route);

    $('note').addEventListener('click', (e) => {
      const a = e.target.closest('a');
      if (!a) return;
      if (a.dataset.anchor) {
        e.preventDefault();
        goToHeading(a.dataset.anchor);
      } else if (a.dataset.anchorAfter) {
        const id = a.dataset.anchorAfter;
        setTimeout(() => document.getElementById(id)?.scrollIntoView(), 50);
      }
    });

    $('menu-btn').addEventListener('click', () => $('app').classList.toggle('nav-open'));
    $('main').addEventListener('click', (e) => {
      if (e.target.id !== 'menu-btn') $('app').classList.remove('nav-open');
    });

    // Reuse the key from earlier in this tab, if any
    const saved = storedKey();
    if (saved) {
      crypto.subtle.importKey('raw', b64.dec(saved), 'AES-GCM', true, ['decrypt'])
        .then(unlockWith)
        .catch(() => { forgetKey(); key = null; });
    }
})();
