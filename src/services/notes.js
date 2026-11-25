// Notas privadas cifradas (RF-04).
// TODAS las consultas filtran por owner_id = usuario actual (A01, previene IDOR).
import { randomUUID } from 'node:crypto';
import { query } from '../db/pool.js';
import { encrypt, decrypt, aadFor, currentKeyVersion } from '../crypto/encryption.js';
import { config } from '../config.js';

const encryptNote = (id, { title, body }) => ({
  titleEnc: encrypt(title, aadFor('notes', 'title', id)),
  bodyEnc: encrypt(body, aadFor('notes', 'body', id)),
});

const decryptRow = (row) => ({
  id: row.id,
  title: decrypt(row.title_enc, aadFor('notes', 'title', row.id)),
  body: row.body_enc === undefined ? undefined : decrypt(row.body_enc, aadFor('notes', 'body', row.id)),
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

export const listNotes = async (ownerId) => {
  const { rows } = await query(
    `SELECT id, title_enc, created_at, updated_at FROM notes
      WHERE owner_id = $1 ORDER BY created_at DESC LIMIT $2`,
    [ownerId, config.limits.maxNotesPerUser],
  );
  return rows.map(decryptRow);
};

export const getNote = async (ownerId, noteId) => {
  const { rows } = await query(
    'SELECT id, title_enc, body_enc, created_at, updated_at FROM notes WHERE id = $1 AND owner_id = $2',
    [noteId, ownerId],
  );
  return rows[0] ? decryptRow(rows[0]) : null;
};

// Solo para auditoría: ¿la nota existe pero pertenece a otro usuario? (intento de IDOR)
export const noteExists = async (noteId) => {
  const { rows } = await query('SELECT 1 FROM notes WHERE id = $1', [noteId]);
  return rows.length === 1;
};

// Límite de negocio (A06): máximo de notas por usuario, comprobado de forma atómica.
export const createNote = async (ownerId, note) => {
  const id = randomUUID();
  const { titleEnc, bodyEnc } = encryptNote(id, note);
  const { rows } = await query(
    `INSERT INTO notes (id, owner_id, title_enc, body_enc, enc_key_version)
     SELECT $1, $2, $3, $4, $5
      WHERE (SELECT count(*) FROM notes WHERE owner_id = $2) < $6
     RETURNING id`,
    [id, ownerId, titleEnc, bodyEnc, currentKeyVersion(), config.limits.maxNotesPerUser],
  );
  return rows[0]?.id ?? null;
};

export const updateNote = async (ownerId, noteId, note) => {
  const { titleEnc, bodyEnc } = encryptNote(noteId, note);
  const { rowCount } = await query(
    `UPDATE notes SET title_enc = $3, body_enc = $4, enc_key_version = $5, updated_at = now()
      WHERE id = $1 AND owner_id = $2`,
    [noteId, ownerId, titleEnc, bodyEnc, currentKeyVersion()],
  );
  return rowCount === 1;
};

export const deleteNote = async (ownerId, noteId) => {
  const { rowCount } = await query('DELETE FROM notes WHERE id = $1 AND owner_id = $2', [noteId, ownerId]);
  return rowCount === 1;
};
