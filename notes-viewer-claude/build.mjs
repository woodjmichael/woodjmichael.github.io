#!/usr/bin/env node
// Encrypt markdown notes for nota-bene.html and equanimity.html.
//
//   node notes-viewer-claude/build.mjs <source> <output-dir>
//
//   node notes-viewer-claude/build.mjs ~/Documents/Nota-Bene       notes-viewer-claude/nota-bene
//   node notes-viewer-claude/build.mjs ~/Documents/Equanimity/equanimity.md notes-viewer-claude/equanimity
//
// <source> is a folder of .md notes or a single .md file. The source is only read.
// Images are included when a note references their file name. Output is
// AES-256-GCM ciphertext, so it is safe to commit to the public github.io repo.
//
// The passphrase is prompted for (hidden), or read from NB_PASSPHRASE.
// Re-run after editing notes, then commit the output folder. The salt in meta.json
// is reused and IVs are derived from the content, so unchanged images produce
// identical files and a rebuild only adds the files that actually changed.

import { createCipheriv, createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';

const [srcArg, outArg] = process.argv.slice(2);
if (!srcArg || !outArg) {
  console.error('Usage: node notes-viewer-claude/build.mjs <notes folder or .md file> <output dir>');
  process.exit(1);
}
const SRC = path.resolve(srcArg.replace(/^~(?=\/|$)/, process.env.HOME));
const OUT_DIR = path.resolve(outArg);
const SRC_IS_FILE = fs.statSync(SRC).isFile();
const ROOT = SRC_IS_FILE ? path.dirname(SRC) : SRC;

// OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
const PBKDF2_ITERATIONS = 600_000;
const IMAGE_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp']);
const MIME = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.svg': 'image/svg+xml', '.webp': 'image/webp' };
// Not notes: a folder's agent instructions
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

// Output layout: 12-byte IV, ciphertext, 16-byte GCM tag. The IV is an HMAC of the
// plaintext, so the same content always encrypts to the same bytes (only equality of
// identical files is revealed) and an IV is never reused for different content.
function encrypt(key, plaintext) {
  const ivKey = createHash('sha256').update('iv').update(key).digest();
  const iv = createHmac('sha256', ivKey).update(plaintext).digest().subarray(0, 12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]);
}

const files = SRC_IS_FILE ? [path.basename(SRC)] : walk(ROOT);
const notes = files.filter((f) => f.endsWith('.md') && !SKIP_FILES.has(f));
if (!notes.length) { console.error(`No notes found in ${SRC}`); process.exit(1); }

// Drop a leading BOM, which would stop the first heading from parsing
const noteText = Object.fromEntries(notes.map((rel) =>
  [rel, fs.readFileSync(path.join(ROOT, rel), 'utf8').replace(/^﻿/, '')]));
const allText = Object.values(noteText).join('\n');

// Images the notes reference, matched by file name (notes often have stale folder paths)
const referenced = (name) => allText.includes(name) || allText.includes(encodeURI(name)) || allText.includes(name.replace(/ /g, '%20'));
const images = walk(ROOT).filter((f) => IMAGE_EXT.has(path.extname(f).toLowerCase()) && referenced(path.basename(f)));

const passphrase = await readPassphrase();
const metaPath = path.join(OUT_DIR, 'meta.json');
let salt;
try { salt = Buffer.from(JSON.parse(fs.readFileSync(metaPath, 'utf8')).salt, 'base64'); } catch { salt = randomBytes(16); }
const key = pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, 32, 'sha256');

fs.rmSync(OUT_DIR, { recursive: true, force: true });
fs.mkdirSync(path.join(OUT_DIR, 'img'), { recursive: true });

// File names are salted content hashes, so the public repo leaks no note or image names
// and identical images are stored once.
const imageMap = {};
const written = new Set();
for (const rel of images) {
  const bytes = fs.readFileSync(path.join(ROOT, rel));
  const id = createHash('sha256').update(salt).update(bytes).digest('hex').slice(0, 24);
  if (!written.has(id)) {
    fs.writeFileSync(path.join(OUT_DIR, 'img', `${id}.bin`), encrypt(key, bytes));
    written.add(id);
  }
  imageMap[rel] = { id, type: MIME[path.extname(rel).toLowerCase()] };
}

const bundle = { built: new Date().toISOString(), notes: noteText, images: imageMap };
fs.writeFileSync(path.join(OUT_DIR, 'notes.bin'), encrypt(key, gzipSync(JSON.stringify(bundle))));
fs.writeFileSync(metaPath,
  JSON.stringify({ salt: salt.toString('base64'), iterations: PBKDF2_ITERATIONS }, null, 2) + '\n');

console.log(`Encrypted ${notes.length} notes and ${written.size} images from ${SRC} into ${OUT_DIR}`);
