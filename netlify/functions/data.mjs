// Storage for the publication state of play app.
// Holds one encrypted record in Netlify Blobs. The server never sees the passcode
// or the decrypted data. If PUBLICATION_TOKEN is set, every request must carry it.
import { getStore } from "@netlify/blobs";

const KEY = "state";
const MAX_BYTES = 4 * 1024 * 1024;

const json = (status, body) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

function tokenOk(req) {
  const expected = (process.env.PUBLICATION_TOKEN || "").trim();
  if (!expected) return true;
  const given = (req.headers.get("x-site-token") || "").trim();
  if (given.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < given.length; i++) diff |= given.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

export default async (req) => {
  if (!tokenOk(req)) return json(401, { error: "Passcode not accepted by this site." });

  const store = getStore({ name: "publication", consistency: "strong" });
  const current = await store.get(KEY, { type: "json" });

  if (req.method === "GET") {
    if (!current) return json(200, { empty: true, version: 0 });
    return json(200, { ...current, tokenRequired: !!process.env.PUBLICATION_TOKEN });
  }

  if (req.method === "PUT") {
    const text = await req.text();
    if (text.length > MAX_BYTES) return json(413, { error: "Data too large." });
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      return json(400, { error: "Body is not JSON." });
    }
    if (typeof body.cipher !== "string" || typeof body.iv !== "string" || typeof body.salt !== "string") {
      return json(400, { error: "Missing cipher, iv or salt." });
    }
    const currentVersion = current?.version ?? 0;
    if (Number(body.baseVersion) !== currentVersion) {
      return json(409, {
        error: "Someone else saved first.",
        version: currentVersion,
        updatedAt: current?.updatedAt ?? null,
      });
    }
    const record = {
      salt: body.salt,
      iv: body.iv,
      cipher: body.cipher,
      version: currentVersion + 1,
      updatedAt: new Date().toISOString(),
      device: String(body.device || "").slice(0, 60),
    };
    await store.setJSON(KEY, record);
    return json(200, { version: record.version, updatedAt: record.updatedAt });
  }

  return json(405, { error: "Use GET or PUT." });
};

export const config = { path: "/api/data" };
