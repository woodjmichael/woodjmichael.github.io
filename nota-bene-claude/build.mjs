#!/usr/bin/env node
// Encrypt the Nota-Bene notes for nota-bene.html.
//
// Reads every .md note and image from the Nota-Bene folder (read-only), then
// writes AES-256-GCM ciphertext to nota-bene-claude/data/. Only ciphertext is
// written, so it is safe to commit to the public github.io repo.
//
//   node nota-bene-claude/build.mjs [path/to/Nota-Bene]
//
// The passphrase is prompted for (hidden), or read from NB_PASSPHRASE.
// Re-run after editing notes, then commit nota-bene-claude/data/.

import { createCipheriv, createHash, pbkdf2Sync, randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC_DIR = path.resolve(process.argv[2] || path.join(process.env.HOME, 'Documents/Nota-Bene'));
const OUT_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data');
// OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
const PBKDF2_ITERATIONS = 600_000;
const IMAGE_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp']);
const MIME = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.svg': 'image/svg+xml', '.webp': 'image/webp' };
// Not notes: the folder's agent instructions and its git helper
const SKIP_FILES = new Set(['CLAUDE.md']);

function walk(dir, rel = '') {
  const out = [];
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ent.name === '.git' || ent.name === 'node_modules') continue;
    const r = rel ? `${rel}/${ent.name}` : ent.name;
    if (ent.isDirectory()) out.push(...walk(path.join(dir, ent.name), r));
    else if (ent.isFile()) out.push(r);
  }
  return out;
}

async function readPassphrase() {
  if (process.env.NB_PASSPHRASE) return process.env.NB_PASSPHRASE;
  const ask = (q) => new Promise((resolve) => {
    process.stdout.write(q);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    let buf = '';
    const onData = (chunk) => {
      for (const ch of chunk.toString('utf8')) {
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode(false); stdin.pause(); stdin.off('data', onData);
          process.stdout.write('\n');
          return resolve(buf);
        }
        if (ch === '\u0003') process.exit(130);
        if (ch === '\u007f') buf = buf.slice(0, -1);
        else buf += ch;
      }
    };
    stdin.on('data', onData);
  });
  const a = await ask('Passphrase: ');
  const b = await ask('Repeat passphrase: ');
  if (a !== b) { console.error('Passphrases do not match.'); process.exit(1); }
  if (a.length < 12) { console.error('Use at least 12 characters.'); process.exit(1); }
  return a;
}

function encrypt(key, plaintext) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]);
}

const files = walk(SRC_DIR);
const notes = files.filter((f) => f.endsWith('.md') && !SKIP_FILES.has(f));
const images = files.filter((f) => IMAGE_EXT.has(path.extname(f).toLowerCase()));
if (!notes.length) { console.error(`No notes found in ${SRC_DIR}`); process.exit(1); }

const passphrase = await readPassphrase();
const salt = randomBytes(16);
const key = pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, 32, 'sha256');

fs.rmSync(OUT_DIR, { recursive: true, force: true });
fs.mkdirSync(path.join(OUT_DIR, 'img'), { recursive: true });

// Image file names are salted hashes so the public repo leaks no note or file names
const imageMap = {};
for (const rel of images) {
  const id = createHash('sha256').update(salt).update(rel).digest('hex').slice(0, 24);
  const bytes = fs.readFileSync(path.join(SRC_DIR, rel));
  fs.writeFileSync(path.join(OUT_DIR, 'img', `${id}.bin`), encrypt(key, bytes));
  imageMap[rel] = { id, type: MIME[path.extname(rel).toLowerCase()] };
}

const bundle = {
  built: new Date().toISOString(),
  notes: Object.fromEntries(notes.map((rel) => [rel, fs.readFileSync(path.join(SRC_DIR, rel), 'utf8')])),
  images: imageMap,
};
fs.writeFileSync(path.join(OUT_DIR, 'notes.bin'), encrypt(key, gzipSync(JSON.stringify(bundle))));
fs.writeFileSync(path.join(OUT_DIR, 'meta.json'),
  JSON.stringify({ salt: salt.toString('base64'), iterations: PBKDF2_ITERATIONS }, null, 2) + '\n');

console.log(`Encrypted ${notes.length} notes and ${images.length} images from ${SRC_DIR} into ${OUT_DIR}`);
