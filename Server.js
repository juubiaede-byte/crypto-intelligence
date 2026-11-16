
/*
 * CRYPTO INTELLIGENCE — server.js
 * Backend central pour Cloudflare Workers.
 *
 * Variables / bindings à configurer :
 * DB                 : Cloudflare D1
 * ARCHIVES           : Cloudflare R2
 * AI                 : Cloudflare Workers AI
 * APP_SECRET         : secret d'accès à l'API
 * GEMINI_API_KEY     : clé Gemini
 * GROQ_API_KEY       : clé Groq
 * SAMBANOVA_API_KEY  : clé SambaNova
 * COHERE_API_KEY     : clé Cohere
 * TELEGRAM_BOT_TOKEN : jeton du bot Telegram
 * TELEGRAM_CHAT_ID   : identifiant du canal Telegram
 * APP_ORIGIN         : origine autorisée pour le navigateur
 *
 * Aucun secret ne doit être placé dans GitHub ou dans le navigateur.
 *
 * ARCHIVES R2 :
 * - Sauvegarde des tables D1 autorisées.
 * - Liste des archives.
 * - Vérification SHA-256.
 * - Aucune suppression automatique.
 * - Aucune restauration automatique.
 */

const APP_NAME = "CRYPTO INTELLIGENCE";
const VERSION = "1.0.0";

const DEFAULT_MODELS = {
  gemini: "gemini-2.5-flash",
  groq: "llama-3.3-70b-versatile",
  sambanova: "Meta-Llama-3.3-70B-Instruct",
  cohere: "command-a"
};

const AI_ROLES = [
  {
    id: "fundamentals",
    name: "IA Fondamentale",
    instruction:
      "Analyse le projet, son équipe si les données sont disponibles, son historique, sa technologie, sa tokenomics et sa crédibilité."
  },
  {
    id: "market",
    name: "IA Marché",
    instruction:
      "Analyse le prix, le volume, la capitalisation, la liquidité, la volatilité, les tendances et les données de marché disponibles."
  },
  {
    id: "security",
    name: "IA Sécurité",
    instruction:
      "Recherche les risques de contrat, honeypot, taxes, pouvoirs du propriétaire, liquidité douteuse, concentration et manipulation. Ne déclare jamais un token sûr sans preuves."
  },
  {
    id: "growth",
    name: "IA Croissance",
    instruction:
      "Analyse l'adoption, le développement, les actualités, les partenariats et les signes de croissance. Distingue les faits des hypothèses."
  },
  {
    id: "arbiter",
    name: "IA Arbitre",
    instruction:
      "Compare les avis précédents, repère les contradictions, les données manquantes et les conclusions insuffisamment prouvées. Ne fais pas une simple moyenne."
  }
];

const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff"
};

/*
 * Tables D1 autorisées dans les sauvegardes.
 * Les noms sont fixes : aucune table fournie par une requête utilisateur
 * ne peut être injectée dans une instruction SQL.
 *
 * Les tables absentes sont simplement ignorées.
 * Les tables système Cloudflare ne sont pas archivées.
 */
const ARCHIVE_TABLES = [
  "ai_opinions",
  "alerts",
  "analyses",
  "asset_status_history",
  "assets",
  "discoveries",
  "evidence",
  "market_snapshots",
  "prediction_targets",
  "predictions",
  "sources",
  "system_events",
  "tasks",
  "watchlists",
  "ci_cache",
  "ci_provider_usage",
  "ci_tasks",
  "ci_audit"
];

const ARCHIVE_PREFIX = "conan/backups/";
const ARCHIVE_FORMAT = "crypto-intelligence-d1-backup-v1";
const ARCHIVE_MAX_ROWS_PER_TABLE = 5000;
const ARCHIVE_MAX_BYTES = 8 * 1024 * 1024;
const ARCHIVE_LIST_LIMIT = 100;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders }
  });
}

function errorResponse(message, status = 400, details = undefined) {
  return json(
    {
      success: false,
      application: APP_NAME,
      error: message,
      ...(details ? { details } : {})
    },
    status
  );
}

function nowISO() {
  return new Date().toISOString();
}

function safeString(value, max = 500) {
  if (value === undefined || value === null) return "";
  return String(value).trim().slice(0, max);
}

function safeNumber(value, fallback = null) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function getPath(request) {
  const url = new URL(request.url);
  return {
    url,
    path: url.pathname.replace(/\/+$/, "") || "/",
    method: request.method.toUpperCase()
  };
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = env.APP_ORIGIN || "";

  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };

  if (allowed && origin === allowed) {
    headers["Access-Control-Allow-Origin"] = allowed;
  }

  return headers;
}

function withHeaders(response, headers) {
  const merged = new Headers(response.headers);
  for (const [key, value] of Object.entries(headers)) {
    merged.set(key, value);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: merged
  });
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function isAuthorized(request, env) {
  if (!env.APP_SECRET) return false;

  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7).trim()
    : "";

  return constantTimeEqual(token, env.APP_SECRET);
}

async function readBody(request, maxBytes = 1000000) {
  const text = await request.text();

  if (text.length > maxBytes) {
    throw new Error("Corps de requête trop volumineux.");
  }

  if (!text.trim()) return {};

  try {
    return JSON.parse(text);
  } catch {
    throw new Error("JSON invalide.");
  }
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/* -------------------------------------------------------------------------- */
/* BASE DE DONNÉES                                                            */
/* -------------------------------------------------------------------------- */

function getDB(env) {
  if (!env.DB) {
    throw new Error("Binding D1 DB absent. Configure le binding DB dans Cloudflare.");
  }
  return env.DB;
}

async function initializeBackendTables(db) {
  await db.batch([
    db.prepare(`
      CREATE TABLE IF NOT EXISTS ci_cache (
        cache_key TEXT PRIMARY KEY,
        cache_value TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS ci_provider_usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider TEXT NOT NULL,
        endpoint TEXT,
        success INTEGER NOT NULL DEFAULT 0,
        status_code INTEGER,
        created_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS ci_tasks (
        id TEXT PRIMARY KEY,
        task_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        priority INTEGER NOT NULL DEFAULT 5,
        payload TEXT,
        result TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS ci_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        description TEXT,
        created_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_ci_tasks_status_priority
      ON ci_tasks(status, priority, created_at)
    `),
    db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_ci_usage_provider_date
      ON ci_provider_usage(provider, created_at)
    `)
  ]);
}

async function audit(db, type, description) {
  try {
    await db.prepare(`
      INSERT INTO ci_audit (event_type, description, created_at)
      VALUES (?, ?, ?)
    `).bind(type, safeString(description, 2000), nowISO()).run();
  } catch (error) {
    console.error("Audit error:", error);
  }
}

async function cacheGet(db, key) {
  const row = await db.prepare(`
    SELECT cache_value, expires_at
    FROM ci_cache
    WHERE cache_key = ?
  `).bind(key).first();

  if (!row) return null;

  if (Number(row.expires_at) < Date.now()) {
    await db.prepare("DELETE FROM ci_cache WHERE cache_key = ?")
      .bind(key).run();
    return null;
  }

  try {
    return JSON.parse(row.cache_value);
  } catch {
    return null;
  }
}

async function cacheSet(db, key, value, ttlSeconds = 60) {
  const expires = Date.now() + ttlSeconds * 1000;

  await db.prepare(`
    INSERT INTO ci_cache (cache_key, cache_value, created_at, expires_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(cache_key) DO UPDATE SET
      cache_value = excluded.cache_value,
      created_at = excluded.created_at,
      expires_at = excluded.expires_at
  `).bind(
    key,
    JSON.stringify(value),
    nowISO(),
    expires
  ).run();
}

async function recordProviderUsage(db, provider, success, statusCode) {
  try {
    await db.prepare(`
      INSERT INTO ci_provider_usage
      (provider, success, status_code, created_at)
      VALUES (?, ?, ?, ?)
    `).bind(
      provider,
      success ? 1 : 0,
      statusCode || null,
      nowISO()
    ).run();
  } catch (error) {
    console.error("Provider usage error:", error);
  }
}

/* -------------------------------------------------------------------------- */
/* ARCHIVES CONAN — CLOUDFLARE R2                                             */
/* -------------------------------------------------------------------------- */

function getArchiveBucket(env) {
  if (!env.ARCHIVES) {
    throw new Error(
      "Binding R2 ARCHIVES absent. Configure le compartiment R2 dans Cloudflare."
    );
  }

  return env.ARCHIVES;
}

/*
 * Vérifie l'existence d'une table à partir de la liste autorisée.
 * Les noms utilisés ici proviennent exclusivement de ARCHIVE_TABLES.
 */
async function getArchiveTableInfo(db, tableName) {
  if (!ARCHIVE_TABLES.includes(tableName)) {
    throw new Error("Table non autorisée pour les archives.");
  }

  const result = await db.prepare(
    `PRAGMA table_info("${tableName}")`
  ).all();

  return result.results || [];
}

/*
 * Construit une copie logique des tables D1.
 * Cette opération ne modifie et ne supprime aucune donnée.
 *
 * Limites de sécurité :
 * - 5 000 lignes maximum par table.
 * - 8 Mo maximum pour l'archive complète.
 * - En cas de dépassement, aucune archive complète n'est déclarée.
 */
async function collectDatabaseSnapshot(db) {
  const tables = {};
  const tableSummary = {};
  let totalRows = 0;

  for (const tableName of ARCHIVE_TABLES) {
    const columnsInfo = await getArchiveTableInfo(db, tableName);

    if (!columnsInfo.length) {
      continue;
    }

    const columns = columnsInfo.map((column) => column.name);

    const result = await db.prepare(
      `SELECT * FROM "${tableName}" LIMIT ${ARCHIVE_MAX_ROWS_PER_TABLE + 1}`
    ).all();

    const rows = result.results || [];

    if (rows.length > ARCHIVE_MAX_ROWS_PER_TABLE) {
      throw new Error(
        `Sauvegarde interrompue : la table ${tableName} dépasse la limite de ${ARCHIVE_MAX_ROWS_PER_TABLE} lignes. Aucune archive complète n'a été créée.`
      );
    }

    tables[tableName] = {
      columns,
      rows
    };

    tableSummary[tableName] = {
      row_count: rows.length,
      column_count: columns.length
    };

    totalRows += rows.length;
  }

  if (!Object.keys(tables).length) {
    throw new Error(
      "Aucune table D1 autorisée n'a été trouvée pour la sauvegarde."
    );
  }

  return {
    tables,
    tableSummary,
    totalRows
  };
}

/*
 * Création d'une archive D1 dans R2.
 *
 * Le contenu de l'archive est haché en SHA-256.
 * Le snapshot est écrit avant son manifeste.
 *
 * Si l'écriture du manifeste échoue après celle du snapshot,
 * le snapshot n'est pas supprimé : aucune suppression automatique
 * n'est autorisée dans le système d'archives.
 */
async function createDatabaseArchive(db, env) {
  const bucket = getArchiveBucket(env);
  const createdAt = nowISO();
  const snapshotId = crypto.randomUUID();

  const collected = await collectDatabaseSnapshot(db);

  const core = {
    format: ARCHIVE_FORMAT,
    application: APP_NAME,
    version: VERSION,
    created_at: createdAt,
    database: {
      provider: "Cloudflare D1",
      binding: "DB"
    },
    summary: {
      table_count: Object.keys(collected.tables).length,
      total_rows: collected.totalRows,
      tables: collected.tableSummary
    },
    tables: collected.tables
  };

  const coreJSON = JSON.stringify(core);
  const sizeBytes = new TextEncoder().encode(coreJSON).byteLength;

  if (sizeBytes > ARCHIVE_MAX_BYTES) {
    throw new Error(
      `Sauvegarde interrompue : l'archive ferait ${sizeBytes} octets, au-delà de la limite de ${ARCHIVE_MAX_BYTES} octets. Aucune archive complète n'a été créée.`
    );
  }

  const checksum = await sha256(coreJSON);

  const archiveDocument = {
    ...core,
    integrity: {
      algorithm: "SHA-256",
      checksum
    }
  };

  const archiveJSON = JSON.stringify(archiveDocument);
  const timestampPart = createdAt.replace(/[:.]/g, "-");
  const baseKey = `${ARCHIVE_PREFIX}${timestampPart}-${snapshotId}`;

  const snapshotKey = `${baseKey}/snapshot.json`;
  const manifestKey = `${baseKey}/manifest.json`;

  const snapshotMetadata = {
    application: APP_NAME,
    format: ARCHIVE_FORMAT,
    checksum,
    created_at: createdAt,
    snapshot_id: snapshotId
  };

  await bucket.put(snapshotKey, archiveJSON, {
    httpMetadata: {
      contentType: "application/json; charset=utf-8"
    },
    customMetadata: snapshotMetadata
  });

  const manifest = {
    application: APP_NAME,
    format: ARCHIVE_FORMAT,
    snapshot_id: snapshotId,
    created_at: createdAt,
    snapshot_key: snapshotKey,
    manifest_key: manifestKey,
    checksum,
    checksum_algorithm: "SHA-256",
    size_bytes: new TextEncoder().encode(archiveJSON).byteLength,
    table_count: Object.keys(collected.tables).length,
    total_rows: collected.totalRows,
    tables: collected.tableSummary,
    restoration: {
      available: false,
      note: "La restauration contrôlée sera ajoutée dans une étape séparée."
    }
  };

  await bucket.put(manifestKey, JSON.stringify(manifest), {
    httpMetadata: {
      contentType: "application/json; charset=utf-8"
    },
    customMetadata: {
      application: APP_NAME,
      format: ARCHIVE_FORMAT,
      snapshot_id: snapshotId,
      checksum
    }
  });

  await audit(
    db,
    "archive_created",
    `Archive R2 créée : ${snapshotKey} — ${collected.totalRows} lignes — SHA-256 ${checksum}`
  );

  return {
    snapshot_id: snapshotId,
    snapshot_key: snapshotKey,
    manifest_key: manifestKey,
    created_at: createdAt,
    checksum,
    checksum_algorithm: "SHA-256",
    size_bytes: manifest.size_bytes,
    table_count: manifest.table_count,
    total_rows: manifest.total_rows,
    tables: manifest.tables,
    restoration_available: false
  };
}

/*
 * Liste les archives R2.
 * La pagination R2 est conservée : aucune archive n'est supprimée.
 */
async function listDatabaseArchives(env, cursor = null) {
  const bucket = getArchiveBucket(env);

  const options = {
    prefix: ARCHIVE_PREFIX,
    limit: ARCHIVE_LIST_LIMIT
  };

  if (cursor) {
    options.cursor = cursor;
  }

  const listing = await bucket.list(options);
  const objects = listing.objects || [];

  const manifests = objects.filter((object) =>
    object.key.endsWith("/manifest.json")
  );

  const archives = [];

  for (const item of manifests) {
    try {
      const object = await bucket.get(item.key);

      if (!object) {
        archives.push({
          manifest_key: item.key,
          manifest_missing: true
        });
        continue;
      }

      const manifestText = await object.text();
      const manifest = JSON.parse(manifestText);

      archives.push({
        snapshot_id: manifest.snapshot_id || null,
        created_at: manifest.created_at || null,
        snapshot_key: manifest.snapshot_key || null,
        manifest_key: item.key,
        checksum: manifest.checksum || null,
        checksum_algorithm: manifest.checksum_algorithm || null,
        size_bytes: manifest.size_bytes ?? null,
        table_count: manifest.table_count ?? null,
        total_rows: manifest.total_rows ?? null,
        tables: manifest.tables || {},
        restoration_available: false
      });
    } catch (error) {
      archives.push({
        manifest_key: item.key,
        manifest_error: safeString(error.message, 300)
      });
    }
  }

  archives.sort((a, b) =>
    String(b.created_at || "").localeCompare(String(a.created_at || ""))
  );

  return {
    archives,
    count: archives.length,
    truncated: Boolean(listing.truncated),
    next_cursor: listing.truncated ? listing.cursor || null : null
  };
}

/*
 * Vérifie une archive existante.
 * Le client ne peut demander que des objets snapshot.json
 * situés sous le préfixe réservé aux sauvegardes de Conan.
 */
function validateArchiveSnapshotKey(key) {
  const value = safeString(key, 1000);

  if (
    !value.startsWith(ARCHIVE_PREFIX) ||
    !value.endsWith("/snapshot.json") ||
    value.includes("..") ||
    value.includes("\\") ||
    value.startsWith("/")
  ) {
    throw new Error("Clé d'archive invalide.");
  }

  return value;
}

async function verifyDatabaseArchive(db, env, requestedKey) {
  const bucket = getArchiveBucket(env);
  const snapshotKey = validateArchiveSnapshotKey(requestedKey);

  const object = await bucket.get(snapshotKey);

  if (!object) {
    const error = new Error("Archive introuvable dans R2.");
    error.status = 404;
    throw error;
  }

  const archiveText = await object.text();

  let archive;

  try {
    archive = JSON.parse(archiveText);
  } catch {
    throw new Error("Le contenu de l'archive n'est pas un JSON valide.");
  }

  if (
    archive.format !== ARCHIVE_FORMAT ||
    archive.application !== APP_NAME ||
    !archive.tables ||
    !archive.integrity ||
    archive.integrity.algorithm !== "SHA-256" ||
    typeof archive.integrity.checksum !== "string"
  ) {
    throw new Error(
      "Format d'archive non reconnu ou informations d'intégrité manquantes."
    );
  }

  /*
   * On reconstruit le même objet principal dans le même ordre
   * que lors de la création de l'archive.
   */
  const core = {
    format: archive.format,
    application: archive.application,
    version: archive.version,
    created_at: archive.created_at,
    database: archive.database,
    summary: archive.summary,
    tables: archive.tables
  };

  const calculatedChecksum = await sha256(JSON.stringify(core));
  const expectedChecksum = archive.integrity.checksum;

  const valid = constantTimeEqual(
    calculatedChecksum,
    expectedChecksum
  );

  const baseKey = snapshotKey.slice(
    0,
    -"/snapshot.json".length
  );

  const manifestKey = `${baseKey}/manifest.json`;
  let manifestStatus = "not_checked";

  const manifestObject = await bucket.get(manifestKey);

  if (manifestObject) {
    try {
      const manifest = JSON.parse(await manifestObject.text());

      manifestStatus =
        manifest.checksum === expectedChecksum &&
        manifest.snapshot_key === snapshotKey
          ? "consistent"
          : "inconsistent";
    } catch {
      manifestStatus = "invalid";
    }
  } else {
    manifestStatus = "missing";
  }

  await audit(
    db,
    valid ? "archive_verified" : "archive_integrity_failed",
    `Vérification SHA-256 de ${snapshotKey} : ${valid ? "valide" : "échec"}`
  );

  return {
    snapshot_key: snapshotKey,
    manifest_key: manifestKey,
    valid,
    algorithm: "SHA-256",
    expected_checksum: expectedChecksum,
    calculated_checksum: calculatedChecksum,
    manifest_status: manifestStatus,
    created_at: archive.created_at || null,
    table_count: archive.summary?.table_count ?? null,
    total_rows: archive.summary?.total_rows ?? null,
    note: valid
      ? "Le contenu de l'archive correspond à son empreinte SHA-256."
      : "L'empreinte ne correspond pas : cette archive ne doit pas être utilisée pour une restauration."
  };
}

/* -------------------------------------------------------------------------- */
/* FOURNISSEURS DE DONNÉES CRYPTO                                             */
/* -------------------------------------------------------------------------- */

async function externalJSON(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(options.headers || {})
      }
    });

    const text = await response.text();
    let data;

    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      throw new Error("Le fournisseur a renvoyé une réponse non JSON.");
    }

    if (!response.ok) {
      const error = new Error(
        `Fournisseur HTTP ${response.status}: ${safeString(data.error || data.message || text, 300)}`
      );
      error.status = response.status;
      throw error;
    }

    return { data, status: response.status };
  } finally {
    clearTimeout(timer);
  }
}

async function getDexScreenerToken(tokenAddress, db) {
  const address = safeString(tokenAddress, 150);
  if (!address) throw new Error("Adresse du token manquante.");

  const cacheKey = `dexscreener:${address.toLowerCase()}`;
  const cached = await cacheGet(db, cacheKey);
  if (cached) return { ...cached, cached: true };

  const { data } = await externalJSON(
    `https://api.dexscreener.com/latest/dex/tokens/${encodeURIComponent(address)}`
  );

  const pairs = Array.isArray(data.pairs) ? data.pairs : [];

  const result = {
    provider: "DexScreener",
    token_address: address,
    pairs: pairs.slice(0, 30).map((pair) => ({
      chain: pair.chainId || null,
      dex: pair.dexId || null,
      pair_address: pair.pairAddress || null,
      base_token: pair.baseToken || null,
      quote_token: pair.quoteToken || null,
      price_usd: safeNumber(pair.priceUsd),
      liquidity_usd: safeNumber(pair.liquidity?.usd),
      volume_24h: safeNumber(pair.volume?.h24),
      price_change_24h: safeNumber(pair.priceChange?.h24),
      fdv: safeNumber(pair.fdv),
      market_cap: safeNumber(pair.marketCap),
      pair_created_at: pair.pairCreatedAt || null,
      url: pair.url || null
    })),
    fetched_at: nowISO(),
    cached: false
  };

  await cacheSet(db, cacheKey, result, 45);
  return result;
}

async function searchDexScreener(query, db) {
  const q = safeString(query, 150);
  if (!q) throw new Error("Recherche manquante.");

  const cacheKey = `dexsearch:${q.toLowerCase()}`;
  const cached = await cacheGet(db, cacheKey);
  if (cached) return { ...cached, cached: true };

  const { data } = await externalJSON(
    `https://api.dexscreener.com/latest/dex/search?q=${encodeURIComponent(q)}`
  );

  const pairs = Array.isArray(data.pairs) ? data.pairs : [];

  const result = {
    provider: "DexScreener",
    query: q,
    pairs: pairs.slice(0, 50).map((pair) => ({
      chain: pair.chainId || null,
      dex: pair.dexId || null,
      pair_address: pair.pairAddress || null,
      base_token: pair.baseToken || null,
      quote_token: pair.quoteToken || null,
      price_usd: safeNumber(pair.priceUsd),
      liquidity_usd: safeNumber(pair.liquidity?.usd),
      volume_24h: safeNumber(pair.volume?.h24),
      price_change_24h: safeNumber(pair.priceChange?.h24),
      market_cap: safeNumber(pair.marketCap),
      fdv: safeNumber(pair.fdv),
      pair_created_at: pair.pairCreatedAt || null,
      url: pair.url || null
    })),
    fetched_at: nowISO(),
    cached: false
  };

  await cacheSet(db, cacheKey, result, 30);
  return result;
}

async function getGeckoTerminalNetworks(db) {
  const key = "geckoterminal:networks";
  const cached = await cacheGet(db, key);
  if (cached) return { ...cached, cached: true };

  const { data } = await externalJSON(
    "https://api.geckoterminal.com/api/v2/networks"
  );

  const result = {
    provider: "GeckoTerminal",
    networks: (data.data || []).map((item) => ({
      id: item.id,
      name: item.attributes?.name || null
    })),
    fetched_at: nowISO(),
    cached: false
  };

  await cacheSet(db, key, result, 3600);
  return result;
}

async function getCoinGeckoMarkets(env, db, options = {}) {
  if (!env.COINGECKO_API_KEY) {
    throw new Error("Clé CoinGecko Demo non configurée.");
  }

  const page = Math.max(1, Math.min(100, Number(options.page) || 1));
  const perPage = Math.max(1, Math.min(250, Number(options.per_page) || 100));
  const currency = safeString(options.currency || "usd", 10).toLowerCase();

  const cacheKey = `coingecko:markets:${currency}:${page}:${perPage}`;
  const cached = await cacheGet(db, cacheKey);
  if (cached) return { ...cached, cached: true };

  const url = new URL("https://api.coingecko.com/api/v3/coins/markets");
  url.searchParams.set("vs_currency", currency);
  url.searchParams.set("order", "market_cap_desc");
  url.searchParams.set("per_page", String(perPage));
  url.searchParams.set("page", String(page));
  url.searchParams.set("sparkline", "false");

  const { data } = await externalJSON(url.toString(), {
    headers: {
      "x-cg-demo-api-key": env.COINGECKO_API_KEY
    }
  });

  const result = {
    provider: "CoinGecko",
    assets: (Array.isArray(data) ? data : []).map((coin) => ({
      id: coin.id,
      name: coin.name,
      symbol: coin.symbol,
      image: coin.image,
      price: safeNumber(coin.current_price),
      market_cap: safeNumber(coin.market_cap),
      market_cap_rank: safeNumber(coin.market_cap_rank),
      volume_24h: safeNumber(coin.total_volume),
      high_24h: safeNumber(coin.high_24h),
      low_24h: safeNumber(coin.low_24h),
      price_change_24h: safeNumber(coin.price_change_percentage_24h),
      circulating_supply: safeNumber(coin.circulating_supply),
      total_supply: safeNumber(coin.total_supply),
      max_supply: safeNumber(coin.max_supply),
      last_updated: coin.last_updated
    })),
    fetched_at: nowISO(),
    cached: false
  };

  await cacheSet(db, cacheKey, result, 60);
  return result;
}

async function getGoPlusSupportedChains() {
  const { data } = await externalJSON(
    "https://api.gopluslabs.io/api/v1/supported_chains"
  );

  return {
    provider: "GoPlus",
    data,
    fetched_at: nowISO()
  };
}

async function getGoPlusTokenSecurity(chainId, contractAddress) {
  const chain = safeString(chainId, 30);
  const address = safeString(contractAddress, 150);

  if (!chain || !address) {
    throw new Error("Chain ID et adresse du contrat requis.");
  }

  const { data } = await externalJSON(
    `https://api.gopluslabs.io/api/v1/token_security/${encodeURIComponent(chain)}?contract_addresses=${encodeURIComponent(address)}`
  );

  return {
    provider: "GoPlus",
    chain_id: chain,
    contract_address: address,
    data,
    fetched_at: nowISO(),
    note: "Une absence de signal ne constitue pas une garantie de sécurité."
  };
}

/* -------------------------------------------------------------------------- */
/* FOURNISSEURS D'INTELLIGENCE ARTIFICIELLE                                   */
/* -------------------------------------------------------------------------- */

async function callGemini(env, prompt) {
  if (!env.GEMINI_API_KEY) throw new Error("Gemini non configuré.");

  const model = env.GEMINI_MODEL || DEFAULT_MODELS.gemini;
  const url =
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(env.GEMINI_API_KEY)}`;

  const { data } = await externalJSON(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.2,
        responseMimeType: "application/json"
      }
    })
  });

  return data.candidates?.[0]?.content?.parts?.map((p) => p.text).join("\n") || "";
}

async function callOpenAICompatible(url, apiKey, model, prompt) {
  if (!apiKey) throw new Error("Fournisseur IA non configuré.");

  const { data } = await externalJSON(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model,
      temperature: 0.2,
      messages: [
        {
          role: "system",
          content:
            "Tu es un analyste spécialisé en cryptomonnaies. N'invente jamais de données. Sépare les faits, hypothèses, incertitudes et données manquantes. Réponds en JSON valide."
        },
        { role: "user", content: prompt }
      ]
    })
  });

  return data.choices?.[0]?.message?.content || "";
}

async function callGroq(env, prompt) {
  return callOpenAICompatible(
    "https://api.groq.com/openai/v1/chat/completions",
    env.GROQ_API_KEY,
    env.GROQ_MODEL || DEFAULT_MODELS.groq,
    prompt
  );
}

async function callSambaNova(env, prompt) {
  return callOpenAICompatible(
    "https://api.sambanova.ai/v1/chat/completions",
    env.SAMBANOVA_API_KEY,
    env.SAMBANOVA_MODEL || DEFAULT_MODELS.sambanova,
    prompt
  );
}

async function callCohere(env, prompt) {
  if (!env.COHERE_API_KEY) throw new Error("Cohere non configuré.");

  const { data } = await externalJSON("https://api.cohere.com/v2/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${env.COHERE_API_KEY}`
    },
    body: JSON.stringify({
      model: env.COHERE_MODEL || DEFAULT_MODELS.cohere,
      temperature: 0.2,
      messages: [
        {
          role: "system",
          content:
            "Tu es un analyste crypto prudent. N'invente aucune information. Réponds en JSON valide."
        },
        { role: "user", content: prompt }
      ]
    })
  });

  return (data.message?.content || [])
    .map((item) => item.text || "")
    .join("\n");
}

async function callCloudflareAI(env, prompt) {
  if (!env.AI || typeof env.AI.run !== "function") {
    throw new Error("Binding Workers AI non configuré.");
  }

  const model = env.CF_AI_MODEL || "@cf/meta/llama-3.1-8b-instruct";
  const result = await env.AI.run(model, {
    messages: [
      {
        role: "system",
        content:
          "Tu es un analyste crypto prudent. N'invente aucune information. Réponds en JSON valide."
      },
      { role: "user", content: prompt }
    ]
  });

  return result.response || JSON.stringify(result);
}

function parseAIResponse(raw) {
  const text = safeString(raw, 30000);

  try {
    return JSON.parse(text);
  } catch {
    const match = text.match(/\{[\s\S]*\}/);
    if (match) {
      try {
        return JSON.parse(match[0]);
      } catch {
        // La réponse reste conservée comme texte non structuré.
      }
    }
  }

  return {
    unstructured_response: text,
    parsing_warning: "La réponse n'a pas pu être convertie en JSON."
  };
}

async function callAIProvider(provider, env, prompt) {
  switch (provider) {
    case "gemini":
      return callGemini(env, prompt);
    case "groq":
      return callGroq(env, prompt);
    case "sambanova":
      return callSambaNova(env, prompt);
    case "cohere":
      return callCohere(env, prompt);
    case "cloudflare":
      return callCloudflareAI(env, prompt);
    default:
      throw new Error("Fournisseur IA inconnu.");
  }
}

function availableAIProviders(env) {
  const providers = [];

  if (env.GEMINI_API_KEY) providers.push("gemini");
  if (env.GROQ_API_KEY) providers.push("groq");
  if (env.SAMBANOVA_API_KEY) providers.push("sambanova");
  if (env.COHERE_API_KEY) providers.push("cohere");
  if (env.AI) providers.push("cloudflare");

  return providers;
}

async function runExpertAnalysis(env, db, asset, marketData = {}) {
  const providers = availableAIProviders(env);

  if (!providers.length) {
    throw new Error("Aucun fournisseur IA n'est configuré.");
  }

  const evidence = {
    asset,
    market_data: marketData,
    collected_at: nowISO(),
    warning:
      "Les IA ne disposent que des informations transmises. Les données manquantes ne doivent pas être inventées."
  };

  const opinions = [];
  const providerErrors = [];

  for (let i = 0; i < AI_ROLES.length; i++) {
    const role = AI_ROLES[i];
    const provider = providers[i % providers.length];

    const prompt = `
APPLICATION : ${APP_NAME}
RÔLE : ${role.name}

MISSION :
${role.instruction}

RÈGLES :
- Ne fabrique aucun chiffre, aucune source, aucun partenariat ni aucune identité.
- Si une information manque, écris "inconnu".
- Distingue fait confirmé, hypothèse et incertitude.
- N'écris jamais qu'un token est garanti ou sans risque.
- Un risque critique confirmé ne peut pas être compensé par un avis positif.
- N'invente pas un prix cible sans données suffisantes.

DONNÉES DISPONIBLES :
${JSON.stringify(evidence)}

Retourne un objet JSON avec :
{
  "role": "${role.id}",
  "summary": "...",
  "facts": [],
  "hypotheses": [],
  "risks": [],
  "missing_data": [],
  "confidence": 0,
  "critical_risk": false,
  "conclusion": "..."
}
`;

    try {
      const raw = await callAIProvider(provider, env, prompt);
      const parsed = parseAIResponse(raw);

      opinions.push({
        role: role.id,
        role_name: role.name,
        provider,
        result: parsed,
        created_at: nowISO()
      });

      await recordProviderUsage(db, provider, true, 200);
    } catch (error) {
      providerErrors.push({
        role: role.id,
        provider,
        error: safeString(error.message, 500)
      });

      await recordProviderUsage(db, provider, false, error.status || 500);
    }
  }

  if (!opinions.length) {
    throw new Error("Tous les appels IA ont échoué.");
  }

  const criticalRisk = opinions.some(
    (opinion) => opinion.result?.critical_risk === true
  );

  const arbiterOpinion = opinions.find((item) => item.role === "arbiter");

  const report = {
    application: APP_NAME,
    asset,
    opinions,
    arbiter: arbiterOpinion?.result || null,
    critical_risk_detected: criticalRisk,
    provider_errors: providerErrors,
    created_at: nowISO(),
    reliability_note:
      "Rapport d'aide à la recherche, pas un conseil financier. Les avis IA doivent être vérifiés par les données sources."
  };

  await saveAnalysisRecord(db, report);
  return report;
}

/* -------------------------------------------------------------------------- */
/* ENREGISTREMENT DES ANALYSES                                                */
/* -------------------------------------------------------------------------- */

async function saveAnalysisRecord(db, report) {
  try {
    const info = await db.prepare("PRAGMA table_info(analyses)").all();
    const available = new Set((info.results || []).map((col) => col.name));

    if (!available.size) return;

    const candidates = {
      id: crypto.randomUUID(),
      asset_id: report.asset?.id || null,
      asset_symbol: report.asset?.symbol || null,
      report: JSON.stringify(report),
      result: JSON.stringify(report),
      content: JSON.stringify(report),
      created_at: report.created_at,
      status: "completed",
      confidence: null,
      summary: safeString(report.arbiter?.summary || "", 2000)
    };

    const entries = Object.entries(candidates)
      .filter(([key]) => available.has(key));

    if (!entries.length) return;

    const columns = entries.map(([key]) => `"${key}"`).join(", ");
    const placeholders = entries.map(() => "?").join(", ");
    const values = entries.map(([, value]) => value);

    await db.prepare(
      `INSERT INTO analyses (${columns}) VALUES (${placeholders})`
    ).bind(...values).run();
  } catch (error) {
    console.error("Impossible d'enregistrer analyses:", error);
  }
}

/* -------------------------------------------------------------------------- */
/* ACTIFS ET DÉCOUVERTES                                                      */
/* -------------------------------------------------------------------------- */

async function getAssets(db, limit = 100) {
  const info = await db.prepare("PRAGMA table_info(assets)").all();
  if (!info.results?.length) {
    return {
      assets: [],
      warning: "La table assets n'a pas été trouvée."
    };
  }

  const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));
  const result = await db.prepare(
    `SELECT * FROM assets LIMIT ${safeLimit}`
  ).all();

  return {
    assets: result.results || [],
    count: result.results?.length || 0
  };
}

async function getAssetById(db, id) {
  const info = await db.prepare("PRAGMA table_info(assets)").all();
  const columns = new Set((info.results || []).map((item) => item.name));

  if (!columns.has("id")) {
    throw new Error("La table assets ne contient pas de colonne id.");
  }

  return db.prepare("SELECT * FROM assets WHERE id = ? LIMIT 1")
    .bind(id).first();
}

async function insertAssetIfSupported(db, asset) {
  const info = await db.prepare("PRAGMA table_info(assets)").all();
  const available = new Set((info.results || []).map((item) => item.name));

  const values = {
    id: asset.id || crypto.randomUUID(),
    name: asset.name || null,
    symbol: asset.symbol || null,
    chain: asset.chain || null,
    contract_address: asset.contract_address || null,
    status: "quarantine",
    source: asset.source || "DexScreener",
    created_at: nowISO(),
    updated_at: nowISO()
  };

  const entries = Object.entries(values)
    .filter(([key]) => available.has(key));

  if (!entries.length) {
    throw new Error("Aucune colonne compatible trouvée dans assets.");
  }

  const columns = entries.map(([key]) => `"${key}"`).join(", ");
  const placeholders = entries.map(() => "?").join(", ");

  await db.prepare(
    `INSERT OR IGNORE INTO assets (${columns}) VALUES (${placeholders})`
  ).bind(...entries.map(([, value]) => value)).run();

  return values;
}

/* -------------------------------------------------------------------------- */
/* QUOTAS ET ÉTAT DES FOURNISSEURS                                            */
/* -------------------------------------------------------------------------- */

async function getProviderStatus(env, db) {
  const usage = await db.prepare(`
    SELECT provider,
           COUNT(*) AS total_requests,
           SUM(success) AS successful_requests,
           SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed_requests
    FROM ci_provider_usage
    WHERE created_at >= ?
    GROUP BY provider
  `).bind(new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()).all();

  const used = new Map(
    (usage.results || []).map((row) => [row.provider, row])
  );

  const configured = [
    {
      id: "coingecko",
      configured: Boolean(env.COINGECKO_API_KEY),
      type: "market_data"
    },
    { id: "dexscreener", configured: true, type: "market_data" },
    { id: "geckoterminal", configured: true, type: "market_data" },
    { id: "goplus", configured: true, type: "security" },
    { id: "gemini", configured: Boolean(env.GEMINI_API_KEY), type: "ai" },
    { id: "groq", configured: Boolean(env.GROQ_API_KEY), type: "ai" },
    { id: "sambanova", configured: Boolean(env.SAMBANOVA_API_KEY), type: "ai" },
    { id: "cohere", configured: Boolean(env.COHERE_API_KEY), type: "ai" },
    { id: "cloudflare_ai", configured: Boolean(env.AI), type: "ai" },
    {
      id: "telegram",
      configured: Boolean(env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID),
      type: "notifications"
    }
  ];

  return configured.map((provider) => ({
    ...provider,
    last_24h: used.get(provider.id) || {
      total_requests: 0,
      successful_requests: 0,
      failed_requests: 0
    }
  }));
}

/* -------------------------------------------------------------------------- */
/* TÂCHES                                                                     */
/* -------------------------------------------------------------------------- */

async function createTask(db, taskType, payload = {}, priority = 5) {
  const id = crypto.randomUUID();

  await db.prepare(`
    INSERT INTO ci_tasks
    (id, task_type, status, priority, payload, created_at, updated_at)
    VALUES (?, ?, 'pending', ?, ?, ?, ?)
  `).bind(
    id,
    safeString(taskType, 100),
    Math.max(1, Math.min(10, Number(priority) || 5)),
    JSON.stringify(payload),
    nowISO(),
    nowISO()
  ).run();

  return { id, status: "pending", task_type: taskType };
}

async function listTasks(db, limit = 100) {
  const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));

  const result = await db.prepare(`
    SELECT id, task_type, status, priority, created_at, updated_at
    FROM ci_tasks
    ORDER BY priority ASC, created_at ASC
    LIMIT ${safeLimit}
  `).all();

  return result.results || [];
}

/* -------------------------------------------------------------------------- */
/* TELEGRAM                                                                   */
/* -------------------------------------------------------------------------- */

async function sendTelegram(env, message) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) {
    throw new Error("Telegram n'est pas configuré.");
  }

  const text = safeString(message, 3900);

  const { data } = await externalJSON(
    `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: env.TELEGRAM_CHAT_ID,
        text,
        disable_web_page_preview: false
      })
    }
  );

  if (!data.ok) {
    throw new Error("Telegram a refusé le message.");
  }

  return {
    sent: true,
    message_id: data.result?.message_id || null,
    sent_at: nowISO()
  };
}

function buildAssetAlert(asset, category, details, appUrl) {
  const name = safeString(asset.name || "Token inconnu", 100);
  const symbol = safeString(asset.symbol || "N/A", 30);
  const chain = safeString(asset.chain || "Chaîne inconnue", 60);
  const contract = safeString(asset.contract_address || "Non disponible", 150);

  return [
    `CRYPTO INTELLIGENCE — ${category}`,
    "",
    `Actif : ${name} (${symbol})`,
    `Blockchain : ${chain}`,
    `Contrat : ${contract}`,
    "",
    safeString(details, 2000),
    "",
    appUrl ? `Analyse complète : ${appUrl}` : "Consulte l'application pour l'analyse complète.",
    "",
    `Date : ${nowISO()}`
  ].join("\n");
}

/* -------------------------------------------------------------------------- */
/* ROUTEUR                                                                    */
/* -------------------------------------------------------------------------- */

async function handlePublicRoutes(request, env, ctx, route) {
  const { path, method } = route;

  if (method === "GET" && path === "/") {
    return json({
      success: true,
      application: APP_NAME,
      version: VERSION,
      status: "online",
      message: "Backend actif."
    });
  }

  if (method === "GET" && path === "/api/health") {
    return json({
      success: true,
      application: APP_NAME,
      version: VERSION,
      status: "online",
      timestamp: nowISO(),
      database_binding: Boolean(env.DB),
      archive_binding: Boolean(env.ARCHIVES),
      workers_ai_binding: Boolean(env.AI)
    });
  }

  return null;
}

async function handleProtectedRoutes(request, env, ctx, route) {
  const { path, method, url } = route;
  const db = getDB(env);

  await initializeBackendTables(db);

  if (method === "GET" && path === "/api/status") {
    const providers = await getProviderStatus(env, db);

    return json({
      success: true,
      application: APP_NAME,
      version: VERSION,
      timestamp: nowISO(),
      services: {
        d1: Boolean(env.DB),
        r2: Boolean(env.ARCHIVES),
        workers_ai: Boolean(env.AI),
        supabase_queue: Boolean(env.SUPABASE_URL && env.SUPABASE_SERVICE_KEY),
        neon_memory: Boolean(env.NEON_DATABASE_URL)
      },
      providers
    });
  }

  if (method === "GET" && path === "/api/providers") {
    return json({
      success: true,
      providers: await getProviderStatus(env, db)
    });
  }

  /* -------------------------- ROUTES ARCHIVES R2 ------------------------- */

  if (method === "GET" && path === "/api/archives/status") {
    return json({
      success: true,
      archive_service: {
        provider: "Cloudflare R2",
        configured: Boolean(env.ARCHIVES),
        backup: Boolean(env.ARCHIVES),
        listing: Boolean(env.ARCHIVES),
        sha256_verification: Boolean(env.ARCHIVES),
        restoration: false,
        automatic_deletion: false,
        prefix: ARCHIVE_PREFIX,
        maximum_rows_per_table: ARCHIVE_MAX_ROWS_PER_TABLE,
        maximum_archive_bytes: ARCHIVE_MAX_BYTES
      },
      note:
        "La présence du binding confirme sa disponibilité pour le Worker, mais les opérations doivent encore être testées en conditions réelles."
    });
  }

  if (method === "POST" && path === "/api/archives/backup") {
    const result = await createDatabaseArchive(db, env);

    return json({
      success: true,
      message: "Sauvegarde D1 enregistrée dans R2.",
      archive: result
    }, 201);
  }

  if (method === "GET" && path === "/api/archives") {
    const cursor = url.searchParams.get("cursor") || null;
    const result = await listDatabaseArchives(env, cursor);

    return json({
      success: true,
      ...result
    });
  }

  if (method === "GET" && path === "/api/archives/verify") {
    const key = url.searchParams.get("key");

    if (!key) {
      return errorResponse(
        "Paramètre key requis. Il doit contenir la clé snapshot.json de l'archive."
      );
    }

    const result = await verifyDatabaseArchive(db, env, key);

    return json({
      success: true,
      verification: result
    });
  }

  /* ------------------------------ ACTIFS --------------------------------- */

  if (method === "GET" && path === "/api/assets") {
    const limit = url.searchParams.get("limit") || 100;
    return json({
      success: true,
      ...(await getAssets(db, limit))
    });
  }

  if (method === "GET" && path.startsWith("/api/assets/")) {
    const id = decodeURIComponent(path.slice("/api/assets/".length));
    const asset = await getAssetById(db, id);

    if (!asset) return errorResponse("Actif introuvable.", 404);

    return json({ success: true, asset });
  }

  if (method === "POST" && path === "/api/assets") {
    const body = await readBody(request);

    if (!body.name && !body.symbol && !body.contract_address) {
      return errorResponse("Nom, symbole ou contrat requis.");
    }

    const asset = await insertAssetIfSupported(db, body);
    await audit(db, "asset_added", `Actif ajouté : ${asset.symbol || asset.name}`);

    return json({ success: true, asset }, 201);
  }

  /* -------------------------- DONNÉES DE MARCHÉ -------------------------- */

  if (method === "GET" && path === "/api/market/search") {
    const query = url.searchParams.get("q");
    if (!query) return errorResponse("Paramètre q requis.");

    const result = await searchDexScreener(query, db);
    return json({ success: true, ...result });
  }

  if (method === "GET" && path === "/api/market/token") {
    const address = url.searchParams.get("address");
    if (!address) return errorResponse("Paramètre address requis.");

    const result = await getDexScreenerToken(address, db);
    return json({ success: true, ...result });
  }

  if (method === "GET" && path === "/api/market/coingecko") {
    const result = await getCoinGeckoMarkets(env, db, {
      page: url.searchParams.get("page"),
      per_page: url.searchParams.get("per_page"),
      currency: url.searchParams.get("currency")
    });

    return json({ success: true, ...result });
  }

  if (method === "GET" && path === "/api/market/networks") {
    return json({
      success: true,
      ...(await getGeckoTerminalNetworks(db))
    });
  }

  /* ------------------------------ SÉCURITÉ ------------------------------- */

  if (method === "GET" && path === "/api/security/chains") {
    return json({
      success: true,
      ...(await getGoPlusSupportedChains())
    });
  }

  if (method === "GET" && path === "/api/security/token") {
    const chain = url.searchParams.get("chain");
    const address = url.searchParams.get("address");

    if (!chain || !address) {
      return errorResponse("Paramètres chain et address requis.");
    }

    return json({
      success: true,
      ...(await getGoPlusTokenSecurity(chain, address))
    });
  }

  /* ------------------------------- ANALYSES ------------------------------ */

  if (method === "POST" && path === "/api/analysis") {
    const body = await readBody(request);

    if (!body.asset || typeof body.asset !== "object") {
      return errorResponse("Objet asset requis.");
    }

    const report = await runExpertAnalysis(
      env,
      db,
      body.asset,
      body.market_data || {}
    );

    await audit(
      db,
      "analysis_created",
      `Analyse créée pour ${body.asset.symbol || body.asset.name || "actif inconnu"}`
    );

    return json({ success: true, report }, 201);
  }

  /* -------------------------------- TÂCHES ------------------------------- */

  if (method === "POST" && path === "/api/tasks") {
    const body = await readBody(request);

    if (!body.type) return errorResponse("Type de tâche requis.");

    const task = await createTask(
      db,
      body.type,
      body.payload || {},
      body.priority || 5
    );

    return json({ success: true, task }, 201);
  }

  if (method === "GET" && path === "/api/tasks") {
    const tasks = await listTasks(db, url.searchParams.get("limit") || 100);
    return json({ success: true, tasks });
  }

  /* ------------------------------ TELEGRAM ------------------------------- */

  if (method === "POST" && path === "/api/telegram/test") {
    const result = await sendTelegram(
      env,
      `✅ ${APP_NAME}\nTest de connexion Telegram réussi.\n${nowISO()}`
    );

    return json({ success: true, telegram: result });
  }

  if (method === "POST" && path === "/api/telegram/alert") {
    const body = await readBody(request);

    if (!body.asset || !body.category || !body.details) {
      return errorResponse("asset, category et details sont requis.");
    }

    const message = buildAssetAlert(
      body.asset,
      body.category,
      body.details,
      body.app_url || env.APP_ORIGIN
    );

    const result = await sendTelegram(env, message);

    await audit(
      db,
      "telegram_alert_sent",
      `${body.category} — ${body.asset.symbol || body.asset.name || "actif inconnu"}`
    );

    return json({ success: true, telegram: result });
  }

  /* -------------------------------- AUDIT -------------------------------- */

  if (method === "GET" && path === "/api/audit") {
    const result = await db.prepare(`
      SELECT * FROM ci_audit
      ORDER BY id DESC
      LIMIT 100
    `).all();

    return json({
      success: true,
      events: result.results || []
    });
  }

  /* ------------------------------- MÉMOIRE ------------------------------- */

  if (method === "GET" && path === "/api/memory/status") {
    return json({
      success: true,
      memory_layers: {
        application_operational_memory: {
          provider: "Cloudflare D1",
          configured: Boolean(env.DB)
        },
        conan_personal_memory: {
          provider: "Neon PostgreSQL",
          configured: Boolean(env.NEON_DATABASE_URL),
          implemented: false
        },
        long_term_archives: {
          provider: "Cloudflare R2",
          configured: Boolean(env.ARCHIVES),
          implemented: Boolean(env.ARCHIVES),
          capabilities: {
            database_backup: Boolean(env.ARCHIVES),
            archive_listing: Boolean(env.ARCHIVES),
            sha256_verification: Boolean(env.ARCHIVES),
            controlled_restoration: false,
            automatic_deletion: false
          }
        }
      },
      note:
        "Les fonctions de sauvegarde D1, de liste des archives et de vérification SHA-256 sont intégrées au backend. Elles restent à tester en conditions réelles. La mémoire personnelle de Conan et la restauration contrôlée ne sont pas encore intégrées."
    });
  }

  /* -------------------------------- CONAN -------------------------------- */

  if (method === "POST" && path === "/api/conan/command") {
    const body = await readBody(request);

    if (!body.command) return errorResponse("Commande Conan requise.");

    const task = await createTask(
      db,
      "conan_command",
      {
        command: safeString(body.command, 2000),
        requested_at: nowISO()
      },
      2
    );

    return json({
      success: true,
      conan: {
        status: "queued",
        task_id: task.id,
        message:
          "Commande enregistrée. Le moteur autonome d'exécution de Conan doit encore être raccordé."
      }
    }, 202);
  }

  if (method === "GET" && path === "/api/conan/status") {
    return json({
      success: true,
      conan: {
        name: "CONAN",
        type: "IA enfant autonome",
        status: "backend_not_yet_integrated",
        personal_memory: Boolean(env.NEON_DATABASE_URL),
        independent_code: false,
        self_learning_engine: false,
        prediction_cycles: false,
        sandbox: false,
        archive_system: {
          configured: Boolean(env.ARCHIVES),
          backup_route: Boolean(env.ARCHIVES),
          listing_route: Boolean(env.ARCHIVES),
          verification_route: Boolean(env.ARCHIVES),
          restoration: false
        }
      }
    });
  }

  return errorResponse("Route API introuvable.", 404);
}

/* -------------------------------------------------------------------------- */
/* POINT D'ENTRÉE CLOUDFLARE WORKERS                                          */
/* -------------------------------------------------------------------------- */

async function handleRequest(request, env, ctx) {
  const route = getPath(request);
  const headers = corsHeaders(request, env);

  if (route.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }

  const publicResponse = await handlePublicRoutes(
    request,
    env,
    ctx,
    route
  );

  if (publicResponse) {
    return withHeaders(publicResponse, headers);
  }

  if (!isAuthorized(request, env)) {
    return withHeaders(
      errorResponse(
        "Accès refusé. Configure APP_SECRET et envoie Authorization: Bearer <APP_SECRET>.",
        401
      ),
      headers
    );
  }

  try {
    const response = await handleProtectedRoutes(
      request,
      env,
      ctx,
      route
    );

    return withHeaders(response, headers);
  } catch (error) {
    console.error("CRYPTO INTELLIGENCE ERROR:", error);

    const status =
      error.status === 429
        ? 429
        : error.status === 404
          ? 404
          : 500;

    return withHeaders(
      errorResponse(
        status === 429
          ? "Limite du fournisseur atteinte. Réessaie plus tard."
          : status === 404
            ? safeString(error.message, 500)
            : "Une erreur interne est survenue.",
        status,
        env.DEBUG === "true"
          ? safeString(error.message, 1000)
          : undefined
      ),
      headers
    );
  }
}

export default {
  async fetch(request, env, ctx) {
    const response = await handleRequest(request, env, ctx);

    const headers = new Headers(response.headers);
    headers.set("X-Frame-Options", "DENY");
    headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
    headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    headers.set("X-Content-Type-Options", "nosniff");

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers
    });
  }
};
