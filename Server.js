
/*
 * CRYPTO INTELLIGENCE — Server.js
 * Backend central pour Cloudflare Workers.
 *
 * Variables / bindings :
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
 * - Liste paginée des archives.
 * - Vérification SHA-256 et du manifeste.
 * - Prévisualisation sécurisée avant restauration.
 * - Aucune restauration automatique.
 * - Aucune suppression automatique.
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
  "ci_radar_lp_history",
  "ci_radar_asset_lifecycle",
  "ci_radar_asset_lifecycle_history",
  "ci_radar_identity_checks",
  "ci_radar_onchain_liquidity_assessments",
  "ci_radar_onchain_pool_history",
  "ci_tasks",
  "ci_audit"
];

const ARCHIVE_PREFIX = "conan/backups/";
const ARCHIVE_FORMAT = "crypto-intelligence-d1-backup-v1";
const ARCHIVE_MAX_ROWS_PER_TABLE = 5000;
const ARCHIVE_MAX_BYTES = 8 * 1024 * 1024;
const ARCHIVE_MANIFEST_MAX_BYTES = 256 * 1024;
const ARCHIVE_LIST_LIMIT = 1000;

/*
 * Limite de sécurité supplémentaire pour la prévisualisation.
 * Une archive dépassant cette limite ne sera pas déclarée
 * prévisualisable intégralement.
 */
const ARCHIVE_PREVIEW_MAX_TOTAL_ROWS = 10000;
const ARCHIVE_PREVIEW_SAMPLE_LIMIT = 10;

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
    throw new Error(
      "Binding D1 DB absent. Configure le binding DB dans Cloudflare."
    );
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
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS ci_radar_discoveries (
        discovery_key TEXT PRIMARY KEY,
        chain_id TEXT NOT NULL,
        contract_address TEXT NOT NULL,
        token_name TEXT,
        token_symbol TEXT,
        pair_addresses_json TEXT NOT NULL DEFAULT '[]',
        sources_json TEXT NOT NULL DEFAULT '[]',
        source_details_json TEXT NOT NULL DEFAULT '{}',
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        pair_created_at TEXT,
        status TEXT NOT NULL DEFAULT 'quarantine',
        review_reason TEXT NOT NULL DEFAULT 'Nouvelle découverte : vérification en attente.',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(chain_id, contract_address)
      )
    `),
    db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_ci_radar_first_seen
      ON ci_radar_discoveries(first_seen_at DESC)
    `),
    db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_ci_radar_status
      ON ci_radar_discoveries(status, last_seen_at DESC)
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS ci_radar_scans (
        id TEXT PRIMARY KEY,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL,
        discovered_count INTEGER NOT NULL DEFAULT 0,
        source_results_json TEXT NOT NULL DEFAULT '{}',
        error_summary TEXT
      )
    `)
,
    db.prepare(`
      CREATE TABLE IF NOT EXISTS ci_radar_pairs (
        pair_key TEXT PRIMARY KEY,
        chain_id TEXT NOT NULL,
        pair_address TEXT NOT NULL,
        token_address TEXT NOT NULL,
        token_name TEXT,
        token_symbol TEXT,
        provider TEXT NOT NULL,
        pair_created_at TEXT,
        pair_details_json TEXT NOT NULL DEFAULT '{}',
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'quarantine',
        UNIQUE(chain_id, pair_address)
      )
    `),
    db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_ci_radar_pairs_seen
      ON ci_radar_pairs(first_seen_at DESC)
    `)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_verifications (discovery_key TEXT PRIMARY KEY, provider TEXT NOT NULL DEFAULT 'Honeypot.is', outcome TEXT NOT NULL DEFAULT 'unknown', simulation_success INTEGER, risk TEXT, checked_at TEXT NOT NULL, next_check_at TEXT, evidence_json TEXT NOT NULL DEFAULT '{}', error_message TEXT)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_verifications_next ON ci_radar_verifications(next_check_at, outcome)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_security_checks (check_key TEXT PRIMARY KEY, discovery_key TEXT NOT NULL, provider TEXT NOT NULL, outcome TEXT NOT NULL DEFAULT 'unknown', checked_at TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}', error_message TEXT)`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_security_checks_discovery ON ci_radar_security_checks(discovery_key, checked_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_lp_history (snapshot_id TEXT PRIMARY KEY, discovery_key TEXT NOT NULL, provider TEXT NOT NULL, checked_at TEXT NOT NULL, assessment_status TEXT NOT NULL DEFAULT 'unknown', top10_locked_share_percent REAL, top10_unlocked_share_percent REAL, top10_lock_status_unknown_share_percent REAL, largest_lp_holder_percent REAL, first_three_lp_holders_percent REAL, reported_lp_holder_count REAL, unlock_events_json TEXT NOT NULL DEFAULT '[]', evidence_json TEXT NOT NULL DEFAULT '{}')`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_lp_history_discovery ON ci_radar_lp_history(discovery_key, checked_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_market_checks (check_key TEXT PRIMARY KEY, discovery_key TEXT NOT NULL, provider TEXT NOT NULL DEFAULT 'DexScreener', outcome TEXT NOT NULL DEFAULT 'unknown', pair_count INTEGER NOT NULL DEFAULT 0, liquidity_usd REAL, volume_24h_usd REAL, checked_at TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}', error_message TEXT)`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_market_checks_discovery ON ci_radar_market_checks(discovery_key, checked_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_contract_checks (check_key TEXT PRIMARY KEY, discovery_key TEXT NOT NULL UNIQUE, provider TEXT NOT NULL, outcome TEXT NOT NULL DEFAULT 'unknown', contract_code_present INTEGER, checked_at TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}', error_message TEXT)`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_contract_checks_checked ON ci_radar_contract_checks(checked_at, outcome)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_pool_metrics (metric_key TEXT PRIMARY KEY, discovery_key TEXT NOT NULL, chain_id TEXT, pair_address TEXT NOT NULL, dex_id TEXT, pair_url TEXT, base_token_address TEXT, base_token_symbol TEXT, quote_token_address TEXT, quote_token_symbol TEXT, price_usd REAL, liquidity_usd REAL, base_reserve REAL, quote_reserve REAL, volume_24h_usd REAL, buys_24h INTEGER, sells_24h INTEGER, pair_created_at TEXT, observed_at TEXT NOT NULL, source TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}' )`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_pool_metrics_discovery ON ci_radar_pool_metrics(discovery_key, observed_at DESC)`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_pool_metrics_pair ON ci_radar_pool_metrics(chain_id, pair_address, observed_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_pool_metric_assets (relation_key TEXT PRIMARY KEY, discovery_key TEXT NOT NULL, metric_key TEXT NOT NULL, linked_at TEXT NOT NULL)`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_pool_metric_assets_discovery ON ci_radar_pool_metric_assets(discovery_key, linked_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_pool_metric_history (observation_id TEXT PRIMARY KEY, discovery_key TEXT NOT NULL, chain_id TEXT, pair_address TEXT NOT NULL, dex_id TEXT, price_usd REAL, liquidity_usd REAL, base_reserve REAL, quote_reserve REAL, volume_24h_usd REAL, buys_24h INTEGER, sells_24h INTEGER, observed_at TEXT NOT NULL, source TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT "{}")`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_pool_metric_history_discovery ON ci_radar_pool_metric_history(discovery_key, observed_at DESC)`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_pool_metric_history_pair ON ci_radar_pool_metric_history(chain_id, pair_address, observed_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_onchain_pool_checks (check_key TEXT PRIMARY KEY, discovery_key TEXT NOT NULL, chain_id TEXT, pair_address TEXT NOT NULL, dex_id TEXT, outcome TEXT NOT NULL, checked_at TEXT NOT NULL, token0_address TEXT, token1_address TEXT, reserve0_raw TEXT, reserve1_raw TEXT, reserve0_adjusted REAL, reserve1_adjusted REAL, token0_decimals INTEGER, token1_decimals INTEGER, block_timestamp INTEGER, evidence_json TEXT NOT NULL DEFAULT '{}', error_message TEXT)`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_onchain_pool_checks_discovery ON ci_radar_onchain_pool_checks(discovery_key, checked_at DESC)`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_onchain_pool_checks_pair ON ci_radar_onchain_pool_checks(chain_id, pair_address, checked_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_onchain_pool_history (snapshot_id TEXT PRIMARY KEY, discovery_key TEXT NOT NULL, chain_id TEXT NOT NULL, pair_address TEXT NOT NULL, checked_at TEXT NOT NULL, outcome TEXT NOT NULL, token0_address TEXT, token1_address TEXT, reserve0_adjusted REAL, reserve1_adjusted REAL, token0_decimals INTEGER, token1_decimals INTEGER, block_timestamp INTEGER, previous_snapshot_id TEXT, reserve0_change_percent REAL, reserve1_change_percent REAL, risk_signal TEXT NOT NULL DEFAULT 'none', evidence_json TEXT NOT NULL DEFAULT '{}')`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_onchain_pool_history_pair ON ci_radar_onchain_pool_history(chain_id, pair_address, checked_at DESC)`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_onchain_pool_history_discovery ON ci_radar_onchain_pool_history(discovery_key, checked_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_identity_checks (check_key TEXT PRIMARY KEY, discovery_key TEXT NOT NULL, provider TEXT NOT NULL DEFAULT 'GeckoTerminal', outcome TEXT NOT NULL DEFAULT 'unknown', checked_at TEXT NOT NULL, network_id TEXT, token_address TEXT, metadata_json TEXT NOT NULL DEFAULT '{}', error_message TEXT)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_asset_lifecycle (discovery_key TEXT PRIMARY KEY, current_stage TEXT NOT NULL DEFAULT 'quarantine', entered_stage_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_transition_reason TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}')`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_asset_lifecycle_stage ON ci_radar_asset_lifecycle(current_stage, updated_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_asset_lifecycle_history (event_id TEXT PRIMARY KEY, discovery_key TEXT NOT NULL, from_stage TEXT NOT NULL, to_stage TEXT NOT NULL, reason TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}', transitioned_at TEXT NOT NULL, actor TEXT NOT NULL DEFAULT 'api')`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_asset_lifecycle_history_discovery ON ci_radar_asset_lifecycle_history(discovery_key, transitioned_at DESC)`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_identity_checks_discovery ON ci_radar_identity_checks(discovery_key, checked_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_radar_onchain_liquidity_assessments (assessment_key TEXT PRIMARY KEY, discovery_key TEXT NOT NULL, chain_id TEXT NOT NULL, pair_address TEXT NOT NULL, checked_at TEXT NOT NULL, outcome TEXT NOT NULL, estimated_pool_depth_usd REAL, quote_token_price_usd REAL, base_token_price_usd REAL, estimated_buy_impact_json TEXT NOT NULL DEFAULT '[]', estimated_sell_impact_json TEXT NOT NULL DEFAULT '[]', evidence_json TEXT NOT NULL DEFAULT '{}')`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_radar_onchain_liquidity_discovery ON ci_radar_onchain_liquidity_assessments(discovery_key, checked_at DESC)`)

  ]);
}

async function audit(db, type, description) {
  try {
    await db.prepare(`
      INSERT INTO ci_audit (event_type, description, created_at)
      VALUES (?, ?, ?)
    `).bind(
      type,
      safeString(description, 2000),
      nowISO()
    ).run();
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
    await db.prepare(
      "DELETE FROM ci_cache WHERE cache_key = ?"
    ).bind(key).run();

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

async function getArchiveTableInfo(db, tableName) {
  if (!ARCHIVE_TABLES.includes(tableName)) {
    throw new Error("Table non autorisée pour les archives.");
  }

  const result = await db.prepare(
    `PRAGMA table_info("${tableName}")`
  ).all();

  return result.results || [];
}

async function collectDatabaseSnapshot(db) {
  const tables = {};
  const tableSummary = {};
  let totalRows = 0;

  for (const tableName of ARCHIVE_TABLES) {
    const columnsInfo = await getArchiveTableInfo(db, tableName);

    if (!columnsInfo.length) continue;

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
  const checksum = await sha256(coreJSON);

  const archiveDocument = {
    ...core,
    integrity: {
      algorithm: "SHA-256",
      checksum
    }
  };

  const archiveJSON = JSON.stringify(archiveDocument);
  const archiveBytes = new TextEncoder().encode(archiveJSON).byteLength;

  if (archiveBytes > ARCHIVE_MAX_BYTES) {
    throw new Error(
      `Sauvegarde interrompue : l'archive ferait ${archiveBytes} octets, au-delà de la limite de ${ARCHIVE_MAX_BYTES} octets. Aucune archive complète n'a été créée.`
    );
  }

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
    size_bytes: archiveBytes,
    table_count: Object.keys(collected.tables).length,
    total_rows: collected.totalRows,
    tables: collected.tableSummary,
    restoration: {
      available: false,
      preview_available: true,
      note: "La restauration contrôlée nécessite une prévisualisation et une validation préalables."
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
    size_bytes: archiveBytes,
    table_count: manifest.table_count,
    total_rows: manifest.total_rows,
    tables: manifest.tables,
    preview_available: true,
    restoration_available: false
  };
}

async function listDatabaseArchives(env, cursor = null) {
  const bucket = getArchiveBucket(env);

  const options = {
    prefix: ARCHIVE_PREFIX,
    limit: ARCHIVE_LIST_LIMIT
  };

  if (cursor) {
    options.cursor = safeString(cursor, 2000);
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

      const manifestValid =
        manifest.application === APP_NAME &&
        manifest.format === ARCHIVE_FORMAT &&
        typeof manifest.snapshot_key === "string" &&
        manifest.snapshot_key.startsWith(ARCHIVE_PREFIX) &&
        manifest.snapshot_key.endsWith("/snapshot.json") &&
        manifest.manifest_key === item.key;

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
        manifest_valid: manifestValid,
        preview_available: true,
        restoration_available: false
      });
    } catch (error) {
      archives.push({
        manifest_key: item.key,
        manifest_error: safeString(error.message, 300),
        manifest_valid: false
      });
    }
  }

  archives.sort((a, b) =>
    String(b.created_at || "").localeCompare(String(a.created_at || ""))
  );

  return {
    archives,
    count: archives.length,
    objects_scanned: objects.length,
    page_limit: ARCHIVE_LIST_LIMIT,
    truncated: Boolean(listing.truncated),
    has_more: Boolean(listing.truncated),
    next_cursor: listing.truncated ? listing.cursor || null : null
  };
}

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

/*
 * Vérification complète d'une archive existante.
 * recordAudit=false est utilisé par la prévisualisation :
 * cette dernière ne doit effectuer aucune écriture dans D1.
 */
async function verifyDatabaseArchive(
  db,
  env,
  requestedKey,
  options = {}
) {
  const recordAudit = options.recordAudit !== false;
  const bucket = getArchiveBucket(env);
  const snapshotKey = validateArchiveSnapshotKey(requestedKey);

  const object = await bucket.get(snapshotKey);

  if (!object) {
    const error = new Error("Archive introuvable dans R2.");
    error.status = 404;
    throw error;
  }

  const archiveText = await object.text();

  if (new TextEncoder().encode(archiveText).byteLength > ARCHIVE_MAX_BYTES) {
    throw new Error("L'archive dépasse la taille maximale autorisée.");
  }

  let archive;

  try {
    archive = JSON.parse(archiveText);
  } catch {
    throw new Error("Le contenu de l'archive n'est pas un JSON valide.");
  }

  if (
    archive.format !== ARCHIVE_FORMAT ||
    archive.application !== APP_NAME ||
    !archive.database ||
    !archive.summary ||
    !archive.tables ||
    !archive.integrity ||
    archive.integrity.algorithm !== "SHA-256" ||
    typeof archive.integrity.checksum !== "string" ||
    !/^[a-f0-9]{64}$/i.test(archive.integrity.checksum)
  ) {
    throw new Error(
      "Format d'archive non reconnu ou informations d'intégrité manquantes."
    );
  }

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

  const contentChecksumValid = constantTimeEqual(
    calculatedChecksum,
    expectedChecksum
  );

  const snapshotMetadata = object.customMetadata || {};

  const snapshotMetadataStatus =
    snapshotMetadata.application === APP_NAME &&
    snapshotMetadata.format === ARCHIVE_FORMAT &&
    snapshotMetadata.checksum === expectedChecksum
      ? "consistent"
      : "inconsistent";

  const baseKey = snapshotKey.slice(
    0,
    -"/snapshot.json".length
  );

  const manifestKey = `${baseKey}/manifest.json`;
  let manifestStatus = "not_checked";

  const manifestObject = await bucket.get(manifestKey);

  if (
    manifestObject &&
    Number.isFinite(Number(manifestObject.size)) &&
    Number(manifestObject.size) > ARCHIVE_MANIFEST_MAX_BYTES
  ) {
    throw new Error("Le manifeste dépasse la taille maximale autorisée.");
  }

  if (manifestObject) {
    try {
      const manifest = JSON.parse(await manifestObject.text());

      if (
        typeof snapshotMetadata.snapshot_id !== "string" ||
        !snapshotMetadata.snapshot_id.trim() ||
        typeof manifest.snapshot_id !== "string" ||
        !manifest.snapshot_id.trim()
      ) {
        throw new Error("Identifiant de snapshot absent ou invalide dans le manifeste.");
      }

      const manifestValid =
        manifest.application === APP_NAME &&
        manifest.format === ARCHIVE_FORMAT &&
        manifest.snapshot_key === snapshotKey &&
        manifest.manifest_key === manifestKey &&
        manifest.checksum === expectedChecksum &&
        manifest.checksum_algorithm === "SHA-256" &&
        manifest.snapshot_id === snapshotMetadata.snapshot_id;

      manifestStatus = manifestValid
        ? "consistent"
        : "inconsistent";

      const manifestMetadata = manifestObject.customMetadata || {};

      const manifestMetadataValid =
        manifestMetadata.application === APP_NAME &&
        manifestMetadata.format === ARCHIVE_FORMAT &&
        manifestMetadata.checksum === expectedChecksum &&
        manifestMetadata.snapshot_id === manifest.snapshot_id;

      if (!manifestMetadataValid) {
        manifestStatus = "inconsistent";
      }
    } catch {
      manifestStatus = "invalid";
    }
  } else {
    manifestStatus = "missing";
  }

  const valid =
    contentChecksumValid &&
    snapshotMetadataStatus === "consistent" &&
    manifestStatus === "consistent";

  if (recordAudit) {
    await audit(
      db,
      valid ? "archive_verified" : "archive_integrity_failed",
      `Vérification de ${snapshotKey} : ${valid ? "valide" : "échec"} — SHA-256 ${contentChecksumValid ? "valide" : "invalide"} — manifeste ${manifestStatus}`
    );
  }

  return {
    snapshot_key: snapshotKey,
    manifest_key: manifestKey,
    valid,
    content_checksum_valid: contentChecksumValid,
    snapshot_metadata_status: snapshotMetadataStatus,
    manifest_status: manifestStatus,
    algorithm: "SHA-256",
    expected_checksum: expectedChecksum,
    calculated_checksum: calculatedChecksum,
    created_at: archive.created_at || null,
    table_count: archive.summary?.table_count ?? null,
    total_rows: archive.summary?.total_rows ?? null,
    note: valid
      ? "Le contenu, les métadonnées R2 et le manifeste sont cohérents."
      : "La vérification complète a échoué ou un élément est manquant. Cette archive ne doit pas être utilisée pour une restauration."
  };
}

/* -------------------------------------------------------------------------- */
/* PRÉVISUALISATION SÉCURISÉE AVANT RESTAURATION                              */
/* -------------------------------------------------------------------------- */

/*
 * Protège les identifiants SQL.
 * Les noms de tables et colonnes sont en plus contrôlés
 * contre les listes et schémas D1 connus.
 */
function quoteSQLIdentifier(identifier) {
  const value = String(identifier);

  if (!value || value.includes("\0")) {
    throw new Error("Identifiant SQL invalide.");
  }

  return `"${value.replace(/"/g, '""')}"`;
}

function archiveValuesEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function getPrimaryKeyColumns(columnsInfo) {
  return columnsInfo
    .filter((column) => Number(column.pk) > 0)
    .sort((a, b) => Number(a.pk) - Number(b.pk))
    .map((column) => column.name);
}

/*
 * Charge et vérifie l'archive avant toute comparaison.
 * Cette fonction ne modifie ni R2 ni D1.
 */
async function loadArchiveForPreview(env, snapshotKey) {
  const bucket = getArchiveBucket(env);
  const safeKey = validateArchiveSnapshotKey(snapshotKey);

  const object = await bucket.get(safeKey);

  if (!object) {
    const error = new Error("Archive introuvable dans R2.");
    error.status = 404;
    throw error;
  }

  const archiveText = await object.text();
  const archiveBytes = new TextEncoder().encode(archiveText).byteLength;

  if (archiveBytes > ARCHIVE_MAX_BYTES) {
    throw new Error(
      "Prévisualisation refusée : l'archive dépasse la taille maximale autorisée."
    );
  }

  let archive;

  try {
    archive = JSON.parse(archiveText);
  } catch {
    throw new Error("Le contenu de l'archive n'est pas un JSON valide.");
  }

  const verification = await verifyDatabaseArchive(
    null,
    env,
    safeKey,
    { recordAudit: false }
  );

  if (!verification.valid) {
    const error = new Error(
      "Prévisualisation refusée : l'intégrité SHA-256, les métadonnées ou le manifeste ne sont pas valides."
    );

    error.verification = verification;
    throw error;
  }

  if (
    !archive.tables ||
    typeof archive.tables !== "object" ||
    Array.isArray(archive.tables)
  ) {
    throw new Error("Structure des tables de l'archive invalide.");
  }

  return {
    archive,
    verification,
    snapshotKey: safeKey
  };
}

/*
 * Prévisualise les données de l'archive face à D1.
 *
 * Catégories :
 * - insertable : ligne absente de D1 et pouvant être insérée.
 * - already_present : ligne déjà présente et identique.
 * - conflict : même clé primaire mais contenu différent.
 * - unidentifiable : table sans clé primaire exploitable.
 * - invalid : structure de ligne ou de table incompatible.
 *
 * Aucune instruction INSERT, UPDATE ou DELETE n'est exécutée.
 */
async function previewDatabaseArchive(db, env, requestedKey) {
  const loaded = await loadArchiveForPreview(env, requestedKey);
  const archive = loaded.archive;

  const archiveTableNames = Object.keys(archive.tables);

  if (!archiveTableNames.length) {
    throw new Error("L'archive ne contient aucune table.");
  }

  for (const tableName of archiveTableNames) {
    if (!ARCHIVE_TABLES.includes(tableName)) {
      throw new Error(
        `Prévisualisation refusée : table non autorisée dans l'archive (${safeString(tableName, 100)}).`
      );
    }
  }

  let archivedTotalRows = 0;

  for (const tableName of archiveTableNames) {
    const table = archive.tables[tableName];

    if (
      !table ||
      !Array.isArray(table.columns) ||
      !Array.isArray(table.rows)
    ) {
      throw new Error(
        `Structure invalide dans l'archive pour la table ${tableName}.`
      );
    }

    if (table.rows.length > ARCHIVE_MAX_ROWS_PER_TABLE) {
      throw new Error(
        `La table ${tableName} dépasse la limite de lignes autorisée.`
      );
    }

    archivedTotalRows += table.rows.length;
  }

  if (archivedTotalRows > ARCHIVE_PREVIEW_MAX_TOTAL_ROWS) {
    throw new Error(
      `Prévisualisation interrompue : ${archivedTotalRows} lignes dépassent la limite de sécurité de ${ARCHIVE_PREVIEW_MAX_TOTAL_ROWS} lignes par opération de prévisualisation.`
    );
  }

  if (
    Number(archive.summary?.total_rows) !== archivedTotalRows ||
    Number(archive.summary?.table_count) !== archiveTableNames.length
  ) {
    throw new Error(
      "Les totaux déclarés dans l'archive ne correspondent pas à son contenu."
    );
  }

  const tableReports = [];

  const totals = {
    archived_rows: archivedTotalRows,
    insertable_rows: 0,
    already_present_rows: 0,
    conflict_rows: 0,
    unidentifiable_rows: 0,
    invalid_rows: 0,
    missing_tables: 0,
    incompatible_tables: 0
  };

  for (const tableName of archiveTableNames) {
    const archivedTable = archive.tables[tableName];
    const archivedColumns = archivedTable.columns;
    const archivedRows = archivedTable.rows;

    const uniqueArchivedColumns = new Set(archivedColumns);

    if (
      uniqueArchivedColumns.size !== archivedColumns.length ||
      archivedColumns.some((column) => typeof column !== "string" || !column)
    ) {
      tableReports.push({
        table: tableName,
        status: "invalid_archive_schema",
        archived_rows: archivedRows.length,
        insertable_rows: 0,
        already_present_rows: 0,
        conflict_rows: 0,
        unidentifiable_rows: 0,
        invalid_rows: archivedRows.length,
        issues: ["Colonnes invalides ou dupliquées dans l'archive."]
      });

      totals.invalid_rows += archivedRows.length;
      totals.incompatible_tables++;
      continue;
    }

    const liveColumnsInfo = await getArchiveTableInfo(db, tableName);

    if (!liveColumnsInfo.length) {
      tableReports.push({
        table: tableName,
        status: "missing_in_database",
        archived_rows: archivedRows.length,
        insertable_rows: 0,
        already_present_rows: 0,
        conflict_rows: 0,
        unidentifiable_rows: archivedRows.length,
        invalid_rows: 0,
        issues: [
          "La table n'existe pas dans D1. La prévisualisation ne créera aucune table."
        ]
      });

      totals.missing_tables++;
      totals.unidentifiable_rows += archivedRows.length;
      continue;
    }

    const liveColumnNames = new Set(
      liveColumnsInfo.map((column) => column.name)
    );

    const archivedColumnNames = new Set(archivedColumns);

    const missingLiveColumns = archivedColumns.filter(
      (column) => !liveColumnNames.has(column)
    );

    const extraLiveColumns = liveColumnsInfo
      .map((column) => column.name)
      .filter((column) => !archivedColumnNames.has(column));

    const primaryKeys = getPrimaryKeyColumns(liveColumnsInfo);

    const missingPrimaryKeys = primaryKeys.filter(
      (column) => !archivedColumnNames.has(column)
    );

    const missingRequiredColumns = liveColumnsInfo
      .filter((column) => {
        return (
          Number(column.notnull) === 1 &&
          column.dflt_value === null &&
          Number(column.pk) === 0 &&
          !archivedColumnNames.has(column.name)
        );
      })
      .map((column) => column.name);

    const issues = [];

    if (missingLiveColumns.length) {
      issues.push(
        `Colonnes de l'archive absentes de D1 : ${missingLiveColumns.join(", ")}`
      );
    }

    if (missingPrimaryKeys.length) {
      issues.push(
        `Clés primaires absentes de l'archive : ${missingPrimaryKeys.join(", ")}`
      );
    }

    if (missingRequiredColumns.length) {
      issues.push(
        `Colonnes obligatoires absentes de l'archive : ${missingRequiredColumns.join(", ")}`
      );
    }

    if (!primaryKeys.length) {
      issues.push(
        "Aucune clé primaire trouvée dans D1 : identification fiable des doublons impossible."
      );
    }

    const schemaCompatible =
      missingLiveColumns.length === 0 &&
      missingPrimaryKeys.length === 0 &&
      missingRequiredColumns.length === 0 &&
      primaryKeys.length > 0;

    if (!schemaCompatible) {
      tableReports.push({
        table: tableName,
        status: "incompatible_schema",
        archived_rows: archivedRows.length,
        insertable_rows: 0,
        already_present_rows: 0,
        conflict_rows: 0,
        unidentifiable_rows: primaryKeys.length
          ? 0
          : archivedRows.length,
        invalid_rows: primaryKeys.length
          ? archivedRows.length
          : 0,
        primary_key: primaryKeys,
        archived_columns: archivedColumns,
        live_columns: Array.from(liveColumnNames),
        extra_live_columns: extraLiveColumns,
        missing_live_columns: missingLiveColumns,
        issues
      });

      totals.incompatible_tables++;

      if (primaryKeys.length) {
        totals.invalid_rows += archivedRows.length;
      } else {
        totals.unidentifiable_rows += archivedRows.length;
      }

      continue;
    }

    let insertableRows = 0;
    let alreadyPresentRows = 0;
    let conflictRows = 0;
    let invalidRows = 0;

    const seenArchiveKeys = new Set();
    const conflictSamples = [];

    const tableSQL = quoteSQLIdentifier(tableName);
    const whereSQL = primaryKeys
      .map((column) => `${quoteSQLIdentifier(column)} = ?`)
      .join(" AND ");

    const selectSQL =
      `SELECT * FROM ${tableSQL} WHERE ${whereSQL} LIMIT 1`;

    for (const row of archivedRows) {
      if (
        !row ||
        typeof row !== "object" ||
        Array.isArray(row)
      ) {
        invalidRows++;
        continue;
      }

      const rowColumns = Object.keys(row);

      const hasUnknownRowColumns = rowColumns.some(
        (column) => !archivedColumnNames.has(column)
      );

      const hasMissingRowColumns = archivedColumns.some(
        (column) => !Object.prototype.hasOwnProperty.call(row, column)
      );

      if (hasMissingRowColumns) {
        invalidRows++;
        continue;
      }

      if (hasUnknownRowColumns) {
        invalidRows++;
        continue;
      }

      const keyValues = primaryKeys.map((column) => row[column]);

      if (keyValues.some((value) => value === undefined || value === null)) {
        invalidRows++;
        continue;
      }

      const archiveKey = JSON.stringify(keyValues);

      if (seenArchiveKeys.has(archiveKey)) {
        conflictRows++;

        if (conflictSamples.length < ARCHIVE_PREVIEW_SAMPLE_LIMIT) {
          conflictSamples.push({
            reason: "duplicate_inside_archive",
            primary_key: keyValues
          });
        }

        continue;
      }

      seenArchiveKeys.add(archiveKey);

      const existing = await db.prepare(selectSQL)
        .bind(...keyValues)
        .first();

      if (!existing) {
        insertableRows++;
        continue;
      }

      const identical = archivedColumns.every((column) =>
        archiveValuesEqual(row[column], existing[column])
      );

      if (identical) {
        alreadyPresentRows++;
      } else {
        conflictRows++;

        if (conflictSamples.length < ARCHIVE_PREVIEW_SAMPLE_LIMIT) {
          conflictSamples.push({
            reason: "existing_row_differs",
            primary_key: keyValues
          });
        }
      }
    }

    const status =
      conflictRows > 0
        ? "conflicts_detected"
        : "compatible";

    tableReports.push({
      table: tableName,
      status,
      archived_rows: archivedRows.length,
      insertable_rows: insertableRows,
      already_present_rows: alreadyPresentRows,
      conflict_rows: conflictRows,
      unidentifiable_rows: 0,
      invalid_rows: invalidRows,
      primary_key: primaryKeys,
      archived_columns: archivedColumns,
      live_columns: Array.from(liveColumnNames),
      extra_live_columns: extraLiveColumns,
      missing_live_columns: [],
      conflict_samples: conflictSamples,
      issues
    });

    totals.insertable_rows += insertableRows;
    totals.already_present_rows += alreadyPresentRows;
    totals.conflict_rows += conflictRows;
    totals.invalid_rows += invalidRows;
  }

  const allTablesCompatible =
    totals.missing_tables === 0 &&
    totals.incompatible_tables === 0 &&
    totals.invalid_rows === 0 &&
    totals.unidentifiable_rows === 0;

  return {
    success: true,
    application: APP_NAME,
    operation: "archive_restore_preview",
    preview_only: true,
    restoration_executed: false,
    database_modified: false,
    archive: {
      snapshot_key: loaded.snapshotKey,
      manifest_key: loaded.verification.manifest_key,
      created_at: loaded.verification.created_at,
      checksum_algorithm: loaded.verification.algorithm,
      checksum: loaded.verification.expected_checksum,
      calculated_checksum: loaded.verification.calculated_checksum,
      integrity_valid: loaded.verification.valid
    },
    compatibility: {
      compatible: allTablesCompatible,
      missing_tables: totals.missing_tables,
      incompatible_tables: totals.incompatible_tables
    },
    totals,
    tables: tableReports,
    safety: {
      insertions_executed: false,
      updates_executed: false,
      deletions_executed: false,
      tables_created: false,
      existing_rows_overwritten: false,
      archive_modified: false,
      original_archive_preserved: true
    },
    next_step:
      allTablesCompatible && totals.conflict_rows === 0
        ? "La prévisualisation est compatible. Une étape distincte devra encore autoriser et exécuter la restauration."
        : "Des incompatibilités, conflits ou lignes non identifiables doivent être examinés avant toute restauration.",
    generated_at: nowISO()
  };
}


/* -------------------------------------------------------------------------- */
/* RESTAURATION RÉELLE CONTRÔLÉE — INSERTIONS UNIQUEMENT                       */
/* -------------------------------------------------------------------------- */

/*
 * La restauration exige une confirmation distincte de l'utilisateur.
 * Elle ne met jamais à jour ni ne supprime une ligne existante.
 * D1 batch exécute l'ensemble des insertions dans une transaction atomique.
 */
async function restoreDatabaseArchive(
  db,
  env,
  requestedKey,
  expectedChecksum,
  confirmation
) {
  const confirmationPhrase = "RESTAURER CETTE ARCHIVE";

  if (confirmation !== confirmationPhrase) {
    throw new Error(
      "Confirmation refusée. La phrase exacte requise est : " +
      confirmationPhrase
    );
  }

  const loaded = await loadArchiveForPreview(env, requestedKey);

  if (
    typeof expectedChecksum !== "string" ||
    !constantTimeEqual(
      expectedChecksum,
      loaded.verification.expected_checksum
    )
  ) {
    throw new Error(
      "Le checksum fourni ne correspond pas à l'archive vérifiée."
    );
  }

  const initialPreview = await previewDatabaseArchive(
    db,
    env,
    loaded.snapshotKey
  );

  const previewIsSafe = (preview) =>
    preview.compatibility?.compatible === true &&
    Number(preview.totals?.conflict_rows) === 0 &&
    Number(preview.totals?.invalid_rows) === 0 &&
    Number(preview.totals?.unidentifiable_rows) === 0 &&
    Number(preview.totals?.missing_tables) === 0 &&
    Number(preview.totals?.incompatible_tables) === 0;

  if (!previewIsSafe(initialPreview)) {
    throw new Error(
      "Restauration bloquée : la prévisualisation détecte une incompatibilité, " +
      "un conflit ou une ligne invalide. Aucune donnée n'a été restaurée."
    );
  }

  const safetyBackup = await createDatabaseArchive(db, env);
  let batchCommitted = false;

  try {
    const freshPreview = await previewDatabaseArchive(
      db,
      env,
      loaded.snapshotKey
    );

    if (!previewIsSafe(freshPreview)) {
      throw new Error(
        "Restauration annulée : l'état D1 a changé depuis le premier contrôle. " +
        "Aucune insertion de restauration n'a été lancée."
      );
    }

    const archive = loaded.archive;
    const pendingByTable = new Map();
    const columnsByTable = new Map();

    for (const tableReport of freshPreview.tables) {
      const tableName = tableReport.table;
      const archivedTable = archive.tables[tableName];
      const columns = archivedTable.columns;
      const primaryKeys = tableReport.primary_key;

      if (!Array.isArray(primaryKeys) || !primaryKeys.length) {
        throw new Error(
          "Restauration bloquée : clé primaire absente pour " + tableName + "."
        );
      }

      const tableSQL = quoteSQLIdentifier(tableName);
      const whereSQL = primaryKeys
        .map((column) => quoteSQLIdentifier(column) + " = ?")
        .join(" AND ");
      const selectSQL =
        "SELECT * FROM " + tableSQL + " WHERE " + whereSQL + " LIMIT 1";

      const pendingRows = [];

      for (const row of archivedTable.rows) {
        const keyValues = primaryKeys.map((column) => row[column]);

        if (keyValues.some((value) => value === undefined || value === null)) {
          throw new Error(
            "Restauration bloquée : clé primaire invalide dans " + tableName + "."
          );
        }

        const existing = await db.prepare(selectSQL)
          .bind(...keyValues)
          .first();

        if (!existing) {
          pendingRows.push(row);
          continue;
        }

        const identical = columns.every((column) =>
          archiveValuesEqual(row[column], existing[column])
        );

        if (!identical) {
          throw new Error(
            "Restauration bloquée : une ligne existante a changé dans " +
            tableName + ". Aucune ligne ne sera écrasée."
          );
        }
      }

      pendingByTable.set(tableName, pendingRows);
      columnsByTable.set(tableName, columns);
    }

    const pendingTableNames = Array.from(pendingByTable.keys())
      .filter((tableName) => pendingByTable.get(tableName).length > 0);
    const pendingSet = new Set(pendingTableNames);

    /*
     * Refuse toute restauration si un trigger pourrait produire des effets
     * secondaires non visibles dans la liste des INSERT de cette opération.
     */
    const guardedTableNames = Array.from(
      new Set([...pendingTableNames, "ci_audit"])
    );
    const triggerPlaceholders = guardedTableNames.map(() => "?").join(", ");
    const triggerCheck = await db.prepare(
      "SELECT name, tbl_name FROM sqlite_master " +
      "WHERE type = 'trigger' AND tbl_name IN (" + triggerPlaceholders + ")"
    ).bind(...guardedTableNames).all();

    if ((triggerCheck.results || []).length) {
      throw new Error(
        "Restauration bloquée : un trigger SQL pourrait produire des effets " +
        "secondaires sur les tables concernées."
      );
    }

    const foreignKeySetting = await db.prepare(
      "PRAGMA foreign_keys"
    ).first();
    const foreignKeyValue = foreignKeySetting
      ? Number(Object.values(foreignKeySetting)[0])
      : 0;

    if (foreignKeyValue !== 1) {
      throw new Error(
        "Restauration bloquée : l'application effective des clés étrangères " +
        "n'a pas pu être confirmée dans D1."
      );
    }

    const dependencies = new Map();

    for (const tableName of pendingTableNames) {
      const foreignKeys = await db.prepare(
        "PRAGMA foreign_key_list(" + quoteSQLIdentifier(tableName) + ")"
      ).all();

      const parents = new Set();

      for (const foreignKey of foreignKeys.results || []) {
        if (
          typeof foreignKey.table === "string" &&
          pendingSet.has(foreignKey.table)
        ) {
          parents.add(foreignKey.table);
        }
      }

      dependencies.set(tableName, parents);
    }

    const orderedTables = [];
    const remaining = new Set(pendingTableNames);

    while (remaining.size) {
      const ready = pendingTableNames.filter((tableName) =>
        remaining.has(tableName) &&
        Array.from(dependencies.get(tableName) || [])
          .every((parent) => !remaining.has(parent))
      );

      if (!ready.length) {
        throw new Error(
          "Restauration bloquée : dépendance circulaire entre clés étrangères. " +
          "Aucune insertion n'a été exécutée."
        );
      }

      for (const tableName of ready) {
        orderedTables.push(tableName);
        remaining.delete(tableName);
      }
    }

    const statements = [];
    let plannedInsertRows = 0;
    const maximumBindingsPerStatement = 900;
    const maximumBatchStatements = 500;

    for (const tableName of orderedTables) {
      const columns = columnsByTable.get(tableName);
      const rows = pendingByTable.get(tableName);

      if (!columns.length) {
        throw new Error("Aucune colonne restaurable dans " + tableName + ".");
      }

      if (columns.length > maximumBindingsPerStatement) {
        throw new Error(
          "Restauration bloquée : trop de colonnes dans " + tableName + "."
        );
      }

      const tableSQL = quoteSQLIdentifier(tableName);
      const columnsSQL = columns
        .map((column) => quoteSQLIdentifier(column))
        .join(", ");
      const rowsPerStatement = Math.max(
        1,
        Math.floor(maximumBindingsPerStatement / columns.length)
      );

      for (let offset = 0; offset < rows.length; offset += rowsPerStatement) {
        const chunk = rows.slice(offset, offset + rowsPerStatement);
        const bindings = [];

        const valuesSQL = chunk.map((row) => {
          const placeholders = columns.map((column) => {
            const value = row[column];

            if (
              value !== null &&
              typeof value !== "string" &&
              typeof value !== "number" &&
              typeof value !== "boolean"
            ) {
              throw new Error(
                "Restauration bloquée : valeur non scalaire non prise en charge " +
                "dans " + tableName + "." + column + "."
              );
            }

            if (typeof value === "number" && !Number.isFinite(value)) {
              throw new Error(
                "Restauration bloquée : valeur numérique invalide dans " +
                tableName + "." + column + "."
              );
            }

            bindings.push(typeof value === "boolean" ? Number(value) : value);
            return "?";
          });

          return "(" + placeholders.join(", ") + ")";
        });

        statements.push(
          db.prepare(
            "INSERT INTO " + tableSQL + " (" + columnsSQL + ") VALUES " +
            valuesSQL.join(", ")
          ).bind(...bindings)
        );

        plannedInsertRows += chunk.length;
      }
    }

    if (statements.length + 1 > maximumBatchStatements) {
      throw new Error(
        "Restauration bloquée : le nombre d'instructions dépasse la limite " +
        "transactionnelle de sécurité."
      );
    }

    statements.push(
      db.prepare(
        "INSERT INTO ci_audit (event_type, description, created_at) VALUES (?, ?, ?)"
      ).bind(
        "archive_restore_applied",
        safeString(
          "Restauration demandée pour " + loaded.snapshotKey +
          "; " + plannedInsertRows + " ligne(s) à insérer; sauvegarde de sécurité " +
          safetyBackup.snapshot_key,
          2000
        ),
        nowISO()
      )
    );

    await db.batch(statements);
    batchCommitted = true;

    const postRestorePreview = await previewDatabaseArchive(
      db,
      env,
      loaded.snapshotKey
    );
    const postRestoreForeignKeyCheck = await db.prepare(
      "PRAGMA foreign_key_check"
    ).all();
    const postRestoreForeignKeyViolations =
      (postRestoreForeignKeyCheck.results || []).length;

    const postRestoreVerified =
      previewIsSafe(postRestorePreview) &&
      Number(postRestorePreview.totals?.insertable_rows) === 0 &&
      Number(postRestorePreview.totals?.conflict_rows) === 0 &&
      postRestoreForeignKeyViolations === 0;

    await audit(
      db,
      postRestoreVerified
        ? "archive_restore_verified"
        : "archive_restore_postcheck_failed",
      "Contrôle après restauration de " + loaded.snapshotKey + " : " +
      (postRestoreVerified ? "validé" : "échec") +
      "; " + plannedInsertRows + " ligne(s) insérée(s); sauvegarde de sécurité " +
      safetyBackup.snapshot_key
    );

    return {
      success: postRestoreVerified,
      application: APP_NAME,
      operation: "archive_restore",
      restoration_executed: true,
      database_modified: plannedInsertRows > 0,
      inserted_rows: plannedInsertRows,
      post_restore_verified: postRestoreVerified,
      archive: {
        snapshot_key: loaded.snapshotKey,
        checksum: loaded.verification.expected_checksum
      },
      safety_backup: {
        snapshot_key: safetyBackup.snapshot_key,
        checksum: safetyBackup.checksum,
        created_at: safetyBackup.created_at
      },
      safety: {
        existing_rows_overwritten: false,
        rows_deleted: false,
        tables_created: false,
        original_archive_preserved: true,
        transaction_used: true
      },
      post_restore_totals: postRestorePreview.totals,
      post_restore_foreign_key_violations: postRestoreForeignKeyViolations,
      message: postRestoreVerified
        ? "Restauration terminée et vérifiée. Aucune ligne existante n'a été écrasée."
        : "Les insertions transactionnelles ont été exécutées, mais le contrôle final nécessite une vérification."
    };
  } catch (error) {
    await audit(
      db,
      "archive_restore_failed",
      "Restauration de " + loaded.snapshotKey + " interrompue : " +
      safeString(error.message, 1000) +
      "; sauvegarde de sécurité " + safetyBackup.snapshot_key
    );

    return {
      success: false,
      application: APP_NAME,
      operation: "archive_restore",
      restoration_executed: batchCommitted,
      database_modified: batchCommitted && plannedInsertRows > 0,
      archive: {
        snapshot_key: loaded.snapshotKey,
        checksum: loaded.verification.expected_checksum
      },
      safety_backup: {
        snapshot_key: safetyBackup.snapshot_key,
        checksum: safetyBackup.checksum,
        created_at: safetyBackup.created_at
      },
      message: safeString(error.message, 1000),
      safety: {
        existing_rows_overwritten: false,
        rows_deleted: false,
        tables_created: false,
        original_archive_preserved: true
      }
    };
  }
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
/* RADAR AUTOMATIQUE DES NOUVEAUX TOKENS ET PAIRES                             */
/* -------------------------------------------------------------------------- */

async function fetchRadarSource(db, provider, url) {
  try {
    const { data, status } = await externalJSON(url);
    await recordProviderUsage(db, provider, true, status);
    return { ok: true, data };
  } catch (error) {
    await recordProviderUsage(db, provider, false, error.status || 500);
    return { ok: false, error: safeString(error.message || "Erreur fournisseur.", 500) };
  }
}

function radarArray(value) {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.data)) return value.data;
  return [];
}

function normalizeRadarToken(chain, address, name, symbol, source, details = {}) {
  const chainId = safeString(chain, 80).trim();
  const contract = safeString(address, 200).trim();
  if (!chainId || !contract) return null;
  return {
    chain_id: chainId,
    contract_address: contract,
    token_name: safeString(name || "", 180) || null,
    token_symbol: safeString(symbol || "", 60) || null,
    source,
    pair_address: safeString(details.pair_address || "", 200) || null,
    pair_created_at: details.pair_created_at || null,
    details
  };
}

function geckoTokenAddress(pool, included) {
  const relation = pool.relationships?.base_token?.data ||
    pool.relationships?.quote_token?.data;
  if (!relation?.id) return null;
  const token = (included || []).find((item) => item.id === relation.id);
  const attrs = token?.attributes || {};
  const id = String(relation.id);
  return {
    address: attrs.address || id.slice(id.indexOf("_") + 1),
    name: attrs.name || null,
    symbol: attrs.symbol || null
  };
}


function cryptoRandomId() { return crypto.randomUUID(); }

const RADAR_LIFECYCLE_STAGES = [
  "crypto_universe",
  "quarantine",
  "precursors",
  "investigation_lab",
  "potential_investment_circle"
];

async function syncRadarAssetLifecycle(db, limit = 1000) {
  const rows = await db.prepare(
    "SELECT discovery_key, first_seen_at FROM ci_radar_discoveries ORDER BY first_seen_at ASC LIMIT ?"
  ).bind(Math.max(1, Math.min(5000, Number(limit) || 1000))).all();
  let initialized = 0;
  for (const row of rows.results || []) {
    const existing = await db.prepare(
      "SELECT discovery_key FROM ci_radar_asset_lifecycle WHERE discovery_key = ?"
    ).bind(row.discovery_key).first();
    if (existing) continue;
    const timestamp = row.first_seen_at || nowISO();
    const reason = "Actif découvert par le radar et placé en quarantaine pour vérification; étape précédente enregistrée comme univers crypto.";
    await db.prepare(
      "INSERT OR IGNORE INTO ci_radar_asset_lifecycle (discovery_key, current_stage, entered_stage_at, updated_at, last_transition_reason, evidence_json) VALUES (?, 'quarantine', ?, ?, ?, '{}')"
    ).bind(row.discovery_key, timestamp, timestamp, reason).run();
    await db.prepare(
      "INSERT OR IGNORE INTO ci_radar_asset_lifecycle_history (event_id, discovery_key, from_stage, to_stage, reason, evidence_json, transitioned_at, actor) VALUES (?, ?, 'crypto_universe', 'quarantine', ?, '{}', ?, 'radar')"
    ).bind(cryptoRandomId(), row.discovery_key, reason, timestamp).run();
    initialized++;
  }
  return { scanned: rows.results?.length || 0, initialized };
}


async function syncRadarAssetLifecycleMissing(db, limit = 1000) {
  const batchLimit = Math.max(1, Math.min(1000, Number(limit) || 1000));
  const rows = await db.prepare(
    "SELECT d.discovery_key, d.first_seen_at FROM ci_radar_discoveries d " +
    "WHERE NOT EXISTS (SELECT 1 FROM ci_radar_asset_lifecycle l WHERE l.discovery_key = d.discovery_key) " +
    "ORDER BY d.first_seen_at ASC LIMIT ?"
  ).bind(batchLimit).all();
  let initialized = 0;
  for (const row of rows.results || []) {
    const timestamp = row.first_seen_at || nowISO();
    const reason = "Actif historique découvert par le radar; initialisation de son cycle en quarantaine avec traçabilité.";
    await db.prepare(
      "INSERT OR IGNORE INTO ci_radar_asset_lifecycle (discovery_key, current_stage, entered_stage_at, updated_at, last_transition_reason, evidence_json) VALUES (?, 'quarantine', ?, ?, ?, '{}')"
    ).bind(row.discovery_key, timestamp, timestamp, reason).run();
    await db.prepare(
      "INSERT OR IGNORE INTO ci_radar_asset_lifecycle_history (event_id, discovery_key, from_stage, to_stage, reason, evidence_json, transitioned_at, actor) VALUES (?, ?, 'crypto_universe', 'quarantine', ?, '{}', ?, 'radar_backfill')"
    ).bind(cryptoRandomId(), row.discovery_key, reason, timestamp).run();
    initialized++;
  }
  return { scanned: rows.results?.length || 0, initialized, has_more: (rows.results || []).length === batchLimit };
}

function validateRadarLifecycleEvidence(evidence) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
    return "Les preuves doivent être un objet structuré.";
  }
  const entries = Object.entries(evidence).filter(([key, value]) =>
    key && value !== null && value !== undefined &&
    !(typeof value === "string" && !value.trim()) &&
    !(Array.isArray(value) && value.length === 0)
  );
  if (entries.length < 2) {
    return "Chaque transition exige au moins deux éléments de preuve distincts.";
  }
  const sourceKeys = ["source", "sources", "provider", "providers", "source_url", "urls"];
  const observationKeys = ["observation", "observations", "finding", "findings", "checks", "metrics", "identity", "contract", "liquidity", "security", "onchain", "holders", "volume", "market_data"];
  const normalizedKeys = entries.map(([key]) => key.toLowerCase());
  if (!normalizedKeys.some(key => sourceKeys.includes(key))) {
    return "Les preuves doivent identifier au moins une source vérifiable.";
  }
  if (!normalizedKeys.some(key => observationKeys.includes(key))) {
    return "Les preuves doivent contenir au moins une observation ou vérification concrète.";
  }
  const substantive = normalizedKeys.filter(key =>
    !["price", "price_change", "price_change_24h", "price_increase", "variation", "pump"].includes(key)
  );
  if (substantive.length < 2) {
    return "Une hausse de prix seule ne peut jamais justifier une transition.";
  }
  return null;
}

async function transitionRadarAssetLifecycle(db, body) {
  const discoveryKey = safeString(body.discovery_key || "", 200);
  const targetStage = safeString(body.to_stage || "", 80);
  const reason = safeString(body.reason || "", 2000).trim();
  if (!discoveryKey || !RADAR_LIFECYCLE_STAGES.includes(targetStage) || !reason) {
    return { error: "discovery_key, to_stage valide et reason documentée sont requis." };
  }
  const lowerReason = reason.toLowerCase();
  if ((lowerReason.includes("hausse du prix") || lowerReason.includes("price increase") || lowerReason.includes("pump")) &&
      !(body.evidence && typeof body.evidence === "object" && !Array.isArray(body.evidence))) {
    return { error: "Une hausse de prix seule ne justifie pas un changement d'étape; des preuves complémentaires sont requises." };
  }
  const asset = await db.prepare(
    "SELECT discovery_key FROM ci_radar_discoveries WHERE discovery_key = ?"
  ).bind(discoveryKey).first();
  if (!asset) return { error: "Actif radar introuvable." };
  let state = await db.prepare(
    "SELECT * FROM ci_radar_asset_lifecycle WHERE discovery_key = ?"
  ).bind(discoveryKey).first();
  if (!state) {
    await syncRadarAssetLifecycle(db, 5000);
    await syncRadarAssetLifecycleMissing(db, 1000);
    state = await db.prepare(
      "SELECT * FROM ci_radar_asset_lifecycle WHERE discovery_key = ?"
    ).bind(discoveryKey).first();
  }
  if (!state) return { error: "État du cycle de vie indisponible." };
  const fromIndex = RADAR_LIFECYCLE_STAGES.indexOf(state.current_stage);
  const toIndex = RADAR_LIFECYCLE_STAGES.indexOf(targetStage);
  if (fromIndex < 0 || Math.abs(toIndex - fromIndex) !== 1) {
    return { error: "Transition refusée : les étapes doivent être parcourues dans l'ordre, sans saut." };
  }
  const evidence = body.evidence && typeof body.evidence === "object" && !Array.isArray(body.evidence) ? body.evidence : {};
  const evidenceError = validateRadarLifecycleEvidence(evidence);
  if (evidenceError) return { error: evidenceError };
  const evidenceJson = JSON.stringify(evidence);
  const timestamp = nowISO();
  const eventId = cryptoRandomId();
  await db.prepare(
    "INSERT INTO ci_radar_asset_lifecycle_history (event_id, discovery_key, from_stage, to_stage, reason, evidence_json, transitioned_at, actor) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(eventId, discoveryKey, state.current_stage, targetStage, reason, evidenceJson, timestamp, safeString(body.actor || "api", 80)).run();
  await db.prepare(
    "UPDATE ci_radar_asset_lifecycle SET current_stage = ?, entered_stage_at = ?, updated_at = ?, last_transition_reason = ?, evidence_json = ? WHERE discovery_key = ?"
  ).bind(targetStage, timestamp, timestamp, reason, evidenceJson, discoveryKey).run();
  await db.prepare(
    "UPDATE ci_radar_discoveries SET status = ?, review_reason = ?, updated_at = ? WHERE discovery_key = ?"
  ).bind(targetStage, reason, timestamp, discoveryKey).run();
  await audit(db, "radar_lifecycle_transition", discoveryKey + ": " + state.current_stage + " -> " + targetStage + " — " + reason);
  return { event_id: eventId, discovery_key: discoveryKey, from_stage: state.current_stage, to_stage: targetStage, transitioned_at: timestamp, reason, evidence };
}

async function persistRadarDiscoveries(db, discoveries) {
  let inserted = 0;
  for (const item of discoveries) {
    if (!item) continue;
    const key = (item.chain_id + ":" + item.contract_address).toLowerCase();
    const existing = await db.prepare(
      "SELECT pair_addresses_json, sources_json, source_details_json " +
      "FROM ci_radar_discoveries WHERE discovery_key = ?"
    ).bind(key).first();

    const pairs = new Set();
    const sources = new Set();
    let sourceDetails = {};
    if (existing) {
      try { for (const value of JSON.parse(existing.pair_addresses_json || "[]")) pairs.add(value); } catch {}
      try { for (const value of JSON.parse(existing.sources_json || "[]")) sources.add(value); } catch {}
      try { sourceDetails = JSON.parse(existing.source_details_json || "{}"); } catch {}
    }
    if (item.pair_address) pairs.add(item.pair_address);
    for (const source of String(item.source).split("+")) sources.add(source);
    sourceDetails = { ...sourceDetails, ...(item.details || {}) };

    const timestamp = nowISO();
    if (!existing) {
      await db.prepare(`
        INSERT INTO ci_radar_discoveries
        (discovery_key, chain_id, contract_address, token_name, token_symbol,
         pair_addresses_json, sources_json, source_details_json, first_seen_at,
         last_seen_at, pair_created_at, status, review_reason, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'quarantine',
                'Nouvelle découverte : identité, contrat, liquidité et possibilité de vente à vérifier.',
                ?, ?)
      `).bind(
        key, item.chain_id, item.contract_address, item.token_name,
        item.token_symbol, JSON.stringify([...pairs]), JSON.stringify([...sources]),
        JSON.stringify(sourceDetails), timestamp, timestamp,
        item.pair_created_at, timestamp, timestamp
      ).run();
      const lifecycleReason = "Première détection : actif enregistré dans l'univers crypto puis placé en quarantaine pour vérification.";
      await db.prepare(
        "INSERT OR IGNORE INTO ci_radar_asset_lifecycle (discovery_key, current_stage, entered_stage_at, updated_at, last_transition_reason, evidence_json) VALUES (?, 'quarantine', ?, ?, ?, '{}')"
      ).bind(key, timestamp, timestamp, lifecycleReason).run();
      await db.prepare(
        "INSERT OR IGNORE INTO ci_radar_asset_lifecycle_history (event_id, discovery_key, from_stage, to_stage, reason, evidence_json, transitioned_at, actor) VALUES (?, ?, 'crypto_universe', 'quarantine', ?, '{}', ?, 'radar')"
      ).bind(cryptoRandomId(), key, lifecycleReason, timestamp).run();
      inserted++;
    } else {
      await db.prepare(`
        UPDATE ci_radar_discoveries
        SET token_name = COALESCE(token_name, ?),
            token_symbol = COALESCE(token_symbol, ?),
            pair_addresses_json = ?, sources_json = ?,
            source_details_json = ?, last_seen_at = ?, updated_at = ?,
            pair_created_at = COALESCE(pair_created_at, ?)
        WHERE discovery_key = ?
      `).bind(
        item.token_name, item.token_symbol, JSON.stringify([...pairs]),
        JSON.stringify([...sources]), JSON.stringify(sourceDetails),
        timestamp, timestamp, item.pair_created_at, key
      ).run();
    }
  }
  return inserted;
}


async function persistRadarPairs(db, discoveries) {
  let inserted = 0;
  for (const item of discoveries) {
    if (!item?.pair_address) continue;
    const pairKey = (item.chain_id + ":" + item.pair_address).toLowerCase();
    const existing = await db.prepare(
      "SELECT pair_details_json FROM ci_radar_pairs WHERE pair_key = ?"
    ).bind(pairKey).first();
    const timestamp = nowISO();
    const details = JSON.stringify(item.details || {});
    if (!existing) {
      await db.prepare(`
        INSERT INTO ci_radar_pairs
        (pair_key, chain_id, pair_address, token_address, token_name,
         token_symbol, provider, pair_created_at, pair_details_json,
         first_seen_at, last_seen_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'quarantine')
      `).bind(
        pairKey, item.chain_id, item.pair_address, item.contract_address,
        item.token_name, item.token_symbol, item.source,
        item.pair_created_at, details, timestamp, timestamp
      ).run();
      inserted++;
    } else {
      await db.prepare(`
        UPDATE ci_radar_pairs
        SET last_seen_at = ?, pair_details_json = ?,
            token_name = COALESCE(token_name, ?),
            token_symbol = COALESCE(token_symbol, ?),
            pair_created_at = COALESCE(pair_created_at, ?)
        WHERE pair_key = ?
      `).bind(
        timestamp, details, item.token_name, item.token_symbol,
        item.pair_created_at, pairKey
      ).run();
    }
  }
  return inserted;
}
function honeypotChainId(chain) {
  const normalized = safeString(chain, 80).trim().toLowerCase();
  const supported = { ethereum: '1', eth: '1', '1': '1', bsc: '56', binance: '56', 'binance-smart-chain': '56', '56': '56', base: '8453', '8453': '8453' };
  return supported[normalized] || null;
}
async function verifyRadarTokenWithHoneypot(db, item) {
  const chainId = honeypotChainId(item.chain_id); const checkedAt = nowISO();
  if (!chainId) return { discovery_key: item.discovery_key, outcome: 'unsupported', simulation_success: null, risk: 'unknown', checked_at: checkedAt, next_check_at: null, evidence: { chain_id: item.chain_id, reason: 'Réseau non pris en charge par Honeypot.is.' }, error_message: null };
  const params = new URLSearchParams({ address: item.contract_address, chainID: chainId });
  let pairAddress = null; try { const pairs = JSON.parse(item.pair_addresses_json || '[]'); if (Array.isArray(pairs) && pairs.length) pairAddress = pairs[0]; } catch {}
  if (pairAddress) params.set('pair', pairAddress);
  try {
    const { data, status } = await externalJSON('https://api.honeypot.is/v2/IsHoneypot?' + params.toString());
    await recordProviderUsage(db, 'honeypot_is', true, status);
    const simulationSuccess = data?.simulationSuccess === true; const hasVerdict = typeof data?.honeypotResult?.isHoneypot === 'boolean';
    const isHoneypot = data?.honeypotResult?.isHoneypot === true;
    const outcome = isHoneypot ? 'honeypot_detected' : simulationSuccess && hasVerdict ? 'simulation_passed' : 'unknown';
    return { discovery_key: item.discovery_key, outcome, simulation_success: simulationSuccess ? 1 : 0, risk: safeString(data?.summary?.risk || 'unknown', 40), checked_at: checkedAt, next_check_at: new Date(Date.now() + (outcome === 'unknown' ? 6 : 24) * 60 * 60 * 1000).toISOString(), evidence: { provider: 'Honeypot.is', chain_id: chainId, token: data?.token || null, summary: data?.summary || null, honeypot_result: data?.honeypotResult || null, simulation_result: data?.simulationResult || null, contract_code: data?.contractCode || null, pair: data?.pair || null, flags: data?.summary?.flags || data?.flags || [], simulation_error: data?.simulationError || null }, error_message: null };
  } catch (error) {
    await recordProviderUsage(db, 'honeypot_is', false, error.status || 500);
    return { discovery_key: item.discovery_key, outcome: 'unknown', simulation_success: null, risk: 'unknown', checked_at: checkedAt, next_check_at: new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString(), evidence: { provider: 'Honeypot.is', chain_id: chainId }, error_message: safeString(error.message || 'Vérification indisponible.', 500) };
  }
}function goPlusChainId(chain) {
  const normalized = safeString(chain, 80).trim().toLowerCase();
  const supported = { ethereum: '1', eth: '1', '1': '1', bsc: '56', binance: '56', 'binance-smart-chain': '56', '56': '56', polygon: '137', matic: '137', '137': '137', arbitrum: '42161', '42161': '42161', optimism: '10', '10': '10', base: '8453', '8453': '8453', avalanche: '43114', '43114': '43114', fantom: '250', '250': '250', linea: '59144', '59144': '59144', scroll: '534352', '534352': '534352' };
  return supported[normalized] || (/^\\d+$/.test(normalized) ? normalized : null);
}
async function verifyRadarTokenWithGoPlus(db, item) {
  const chainId = goPlusChainId(item.chain_id); const checkedAt = nowISO();
  const checkKey = item.discovery_key + ':goplus';
  if (!chainId) return { check_key: checkKey, discovery_key: item.discovery_key, provider: 'GoPlus', outcome: 'unsupported', checked_at: checkedAt, evidence: { chain_id: item.chain_id, reason: 'Identifiant de réseau non reconnu.' }, error_message: null };
  try {
    const result = await getGoPlusTokenSecurity(chainId, item.contract_address);
    await recordProviderUsage(db, 'goplus', true, 200);
    const payload = result.data || {}; const resultMap = payload.result || {};
    const contractData = resultMap[item.contract_address] || resultMap[item.contract_address.toLowerCase()] || Object.values(resultMap)[0] || null;
    const hasData = !!contractData && typeof contractData === 'object';
    const flagged = hasData && Object.entries(contractData).some(([key, value]) => /is_honeypot|cannot_sell_all|hidden_owner|selfdestruct|external_call|owner_change_balance|is_blacklisted|is_whitelisted|trading_cooldown|transfer_pausable|is_mintable|slippage_modifiable|personal_slippage_modifiable|buy_tax|sell_tax/i.test(key) && value !== '0' && value !== 0 && value !== false && value !== null && value !== '');
    return { check_key: checkKey, discovery_key: item.discovery_key, provider: 'GoPlus', outcome: !hasData ? 'unknown' : flagged ? 'risk_signals' : 'no_flags_returned', checked_at: checkedAt, evidence: { chain_id: chainId, api_code: payload.code ?? null, api_message: payload.message ?? null, token_security: contractData, note: 'Absence de signal GoPlus ne garantit pas la sécurité.' }, error_message: null };
  } catch (error) {
    await recordProviderUsage(db, 'goplus', false, error.status || 500);
    return { check_key: checkKey, discovery_key: item.discovery_key, provider: 'GoPlus', outcome: 'unknown', checked_at: checkedAt, evidence: { chain_id: chainId }, error_message: safeString(error.message || 'Vérification GoPlus indisponible.', 500) };
  }
}
async function persistRadarSecurityCheck(db, result) {
  await db.prepare(`INSERT INTO ci_radar_security_checks (check_key, discovery_key, provider, outcome, checked_at, evidence_json, error_message) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(check_key) DO UPDATE SET outcome = excluded.outcome, checked_at = excluded.checked_at, evidence_json = excluded.evidence_json, error_message = excluded.error_message`).bind(result.check_key, result.discovery_key, result.provider, result.outcome, result.checked_at, JSON.stringify(result.evidence || {}), result.error_message).run();
}
function dexScreenerChainId(chain) {
  const normalized = safeString(chain, 80).trim().toLowerCase();
  const supported = { eth: 'ethereum', ethereum: 'ethereum', '1': 'ethereum', bsc: 'bsc', binance: 'bsc', '56': 'bsc', base: 'base', '8453': 'base', polygon: 'polygon', matic: 'polygon', '137': 'polygon', arbitrum: 'arbitrum', '42161': 'arbitrum', optimism: 'optimism', '10': 'optimism', avalanche: 'avalanche', '43114': 'avalanche', solana: 'solana', sonic: 'sonic', fantom: 'fantom', '250': 'fantom', linea: 'linea', scroll: 'scroll' };
  return supported[normalized] || normalized;
}
async function verifyRadarMarketData(db, item) {
  const checkedAt = nowISO(); const checkKey = item.discovery_key + ':dexscreener';
  const chain = dexScreenerChainId(item.chain_id);
  try {
    const { data, status } = await externalJSON('https://api.dexscreener.com/token-pairs/v1/' + encodeURIComponent(chain) + '/' + encodeURIComponent(item.contract_address));
    await recordProviderUsage(db, 'dexscreener_token_pairs', true, status);
    const pairs = Array.isArray(data) ? data : [];
    const matching = pairs.filter((pair) => String(pair.baseToken?.address || '').toLowerCase() === item.contract_address.toLowerCase() || String(pair.quoteToken?.address || '').toLowerCase() === item.contract_address.toLowerCase());
    const liquidities = matching.map((pair) => Number(pair.liquidity?.usd)).filter((value) => Number.isFinite(value) && value >= 0);
    const volumes = matching.map((pair) => Number(pair.volume?.h24)).filter((value) => Number.isFinite(value) && value >= 0);
    const outcome = pairs.length === 0 ? 'no_pair_returned' : matching.length > 0 ? 'pair_identity_confirmed_by_provider' : 'identity_unconfirmed';
    return { check_key: checkKey, discovery_key: item.discovery_key, provider: 'DexScreener', outcome, pair_count: matching.length, liquidity_usd: liquidities.length ? liquidities.reduce((sum, value) => sum + value, 0) : null, volume_24h_usd: volumes.length ? volumes.reduce((sum, value) => sum + value, 0) : null, checked_at: checkedAt, evidence: { requested_chain: item.chain_id, dex_chain: chain, returned_pairs: pairs, matching_pair_count: matching.length, note: 'Liquidité et volume rapportés par DexScreener; ils ne prouvent ni la profondeur réelle ni la possibilité de vendre.' }, error_message: null };
  } catch (error) {
    await recordProviderUsage(db, 'dexscreener_token_pairs', false, error.status || 500);
    return { check_key: checkKey, discovery_key: item.discovery_key, provider: 'DexScreener', outcome: 'unknown', pair_count: 0, liquidity_usd: null, volume_24h_usd: null, checked_at: checkedAt, evidence: { requested_chain: item.chain_id }, error_message: safeString(error.message || 'Données de marché indisponibles.', 500) };
  }
}
async function persistRadarMarketCheck(db, result) {
  await db.prepare(`INSERT INTO ci_radar_market_checks (check_key, discovery_key, provider, outcome, pair_count, liquidity_usd, volume_24h_usd, checked_at, evidence_json, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(check_key) DO UPDATE SET outcome = excluded.outcome, pair_count = excluded.pair_count, liquidity_usd = excluded.liquidity_usd, volume_24h_usd = excluded.volume_24h_usd, checked_at = excluded.checked_at, evidence_json = excluded.evidence_json, error_message = excluded.error_message`).bind(result.check_key, result.discovery_key, result.provider, result.outcome, result.pair_count, result.liquidity_usd, result.volume_24h_usd, result.checked_at, JSON.stringify(result.evidence || {}), result.error_message).run();
}


function radarFiniteMetric(value) {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}
async function persistRadarPoolMetrics(db, discoveryKey, marketResult) {
  const pairs = Array.isArray(marketResult?.evidence?.returned_pairs) ? marketResult.evidence.returned_pairs.slice(0, 20) : [];
  let saved = 0;
  for (const pair of pairs) {
    const pairAddress = safeString(pair.pairAddress || "", 160);
    if (!pairAddress) continue;
    const chainId = safeString(pair.chainId || marketResult.evidence?.dex_chain || "", 80);
    const metricKey = (chainId + ":" + pairAddress).toLowerCase();
    const txns = pair.txns?.h24 || {};
    const evidence = {
      provider: "DexScreener",
      liquidity_is_provider_reported: true,
      depth_is_not_independently_verified: true,
      price_impact_not_measured: true,
      pair_created_at_raw: pair.pairCreatedAt || null,
      price_change_24h_percent: radarFiniteMetric(pair.priceChange?.h24),
      fdv_usd: radarFiniteMetric(pair.fdv),
      market_cap_usd: radarFiniteMetric(pair.marketCap),
      transaction_window: "h24"
    };
    await db.prepare("INSERT INTO ci_radar_pool_metrics (metric_key, discovery_key, chain_id, pair_address, dex_id, pair_url, base_token_address, base_token_symbol, quote_token_address, quote_token_symbol, price_usd, liquidity_usd, base_reserve, quote_reserve, volume_24h_usd, buys_24h, sells_24h, pair_created_at, observed_at, source, evidence_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(metric_key) DO UPDATE SET discovery_key = excluded.discovery_key, dex_id = excluded.dex_id, pair_url = excluded.pair_url, base_token_address = excluded.base_token_address, base_token_symbol = excluded.base_token_symbol, quote_token_address = excluded.quote_token_address, quote_token_symbol = excluded.quote_token_symbol, price_usd = excluded.price_usd, liquidity_usd = excluded.liquidity_usd, base_reserve = excluded.base_reserve, quote_reserve = excluded.quote_reserve, volume_24h_usd = excluded.volume_24h_usd, buys_24h = excluded.buys_24h, sells_24h = excluded.sells_24h, pair_created_at = excluded.pair_created_at, observed_at = excluded.observed_at, evidence_json = excluded.evidence_json").bind(
      metricKey, discoveryKey, chainId, pairAddress, safeString(pair.dexId || "", 100) || null,
      safeString(pair.url || "", 1000) || null,
      safeString(pair.baseToken?.address || "", 160) || null,
      safeString(pair.baseToken?.symbol || "", 80) || null,
      safeString(pair.quoteToken?.address || "", 160) || null,
      safeString(pair.quoteToken?.symbol || "", 80) || null,
      radarFiniteMetric(pair.priceUsd), radarFiniteMetric(pair.liquidity?.usd),
      radarFiniteMetric(pair.liquidity?.base), radarFiniteMetric(pair.liquidity?.quote),
      radarFiniteMetric(pair.volume?.h24), radarFiniteMetric(txns.buys),
      radarFiniteMetric(txns.sells), pair.pairCreatedAt ? String(pair.pairCreatedAt) : null,
      nowISO(), "DexScreener", JSON.stringify(evidence)
    ).run();
    saved++;
  }
  return { pairs_received: Array.isArray(marketResult?.evidence?.returned_pairs) ? marketResult.evidence.returned_pairs.length : 0, pair_metrics_saved: saved, per_token_storage_limit: 20, liquidity_semantics: "provider-reported pool liquidity, not verified executable depth" };
}


/* Estimation indicative de l'impact AMM à partir des réserves observées.
 * Les résultats restent des estimations théoriques, jamais une preuve d'exécution.
 */
async function estimateRadarPoolExecutionImpact(db, discoveryKey) {
  const rows = await db.prepare(`
    SELECT metric_key, chain_id, pair_address, base_token_address,
           quote_token_address, price_usd, base_reserve, quote_reserve,
           evidence_json
    FROM ci_radar_pool_metrics
    WHERE discovery_key = ?
    ORDER BY liquidity_usd DESC
    LIMIT 20
  `).bind(discoveryKey).all();
  const tradeSizesUsd = [100, 500, 1000, 5000];
  let assessed = 0;
  let insufficient = 0;
  for (const row of rows.results || []) {
    const baseReserve = radarFiniteMetric(row.base_reserve);
    const quoteReserve = radarFiniteMetric(row.quote_reserve);
    const basePriceUsd = radarFiniteMetric(row.price_usd);
    const baseAddress = safeString(row.base_token_address || "", 160).toLowerCase();
    const quoteAddress = safeString(row.quote_token_address || "", 160).toLowerCase();
    const targetAddress = safeString(
      (await db.prepare("SELECT contract_address FROM ci_radar_discoveries WHERE discovery_key = ?")
        .bind(discoveryKey).first())?.contract_address || "", 160
    ).toLowerCase();
    let tokenReserve = null;
    let counterReserve = null;
    let tokenPriceUsd = null;
    let counterPriceUsd = null;
    if (baseAddress && baseAddress === targetAddress && baseReserve > 0 &&
        quoteReserve > 0 && basePriceUsd > 0) {
      tokenReserve = baseReserve;
      counterReserve = quoteReserve;
      tokenPriceUsd = basePriceUsd;
      counterPriceUsd = basePriceUsd * baseReserve / quoteReserve;
    } else if (quoteAddress && quoteAddress === targetAddress && baseReserve > 0 &&
        quoteReserve > 0 && basePriceUsd > 0) {
      tokenReserve = quoteReserve;
      counterReserve = baseReserve;
      tokenPriceUsd = basePriceUsd * baseReserve / quoteReserve;
      counterPriceUsd = basePriceUsd;
    }
    if (!(tokenReserve > 0 && counterReserve > 0 &&
          tokenPriceUsd > 0 && counterPriceUsd > 0)) {
      insufficient++;
      continue;
    }
    const scenarios = tradeSizesUsd.map((tradeUsd) => {
      const inputCounter = tradeUsd / counterPriceUsd;
      const inputToken = tradeUsd / tokenPriceUsd;
      const feeAdjustedCounter = inputCounter * 0.997;
      const feeAdjustedToken = inputToken * 0.997;
      const boughtToken = tokenReserve * feeAdjustedCounter /
        (counterReserve + feeAdjustedCounter);
      const receivedCounter = counterReserve * feeAdjustedToken /
        (tokenReserve + feeAdjustedToken);
      const spotCounterPerToken = counterReserve / tokenReserve;
      const buyImpact = boughtToken > 0
        ? Math.max(0, ((inputCounter / boughtToken) / spotCounterPerToken - 1) * 100)
        : null;
      const sellImpact = inputToken > 0
        ? Math.max(0, (1 - (receivedCounter / inputToken) / spotCounterPerToken) * 100)
        : null;
      return {
        trade_size_usd: tradeUsd,
        estimated_buy_price_impact_percent: buyImpact,
        estimated_sell_price_impact_percent: sellImpact
      };
    });
    let prior = {};
    try { prior = JSON.parse(row.evidence_json || "{}"); } catch { prior = {}; }
    const enriched = {
      ...prior,
      amm_execution_impact_estimate: {
        status: "estimated_from_reported_reserves",
        model: "constant_product_xy_k",
        assumed_fee_percent: 0.3,
        trade_sizes_usd: tradeSizesUsd,
        scenarios,
        token_reserve: tokenReserve,
        counter_reserve: counterReserve,
        token_price_usd_reference: tokenPriceUsd,
        counter_price_usd_inferred: counterPriceUsd,
        reserve_source: "DexScreener",
        independently_verified_reserves: false,
        gas_and_router_fees_included: false,
        warning: "Estimation indicative; réserves rapportées par le fournisseur, frais supposés à 0,3 %, hors gas, taxes token, MEV, routage et variation de réserves."
      }
    };
    await db.prepare("UPDATE ci_radar_pool_metrics SET evidence_json = ? WHERE metric_key = ?")
      .bind(JSON.stringify(enriched), row.metric_key).run();
    assessed++;
  }
  return {
    pools_assessed: assessed,
    pools_without_sufficient_reserves: insufficient,
    trade_sizes_usd: tradeSizesUsd,
    model: "constant_product_xy_k",
    status: assessed ? "estimated_not_executable_quote" : "insufficient_data"
  };
}


async function persistRadarPoolMetricAssetLinks(db, discoveryKey, marketResult) {
  const pairs = Array.isArray(marketResult?.evidence?.returned_pairs) ? marketResult.evidence.returned_pairs.slice(0, 20) : [];
  let linked = 0;
  for (const pair of pairs) {
    const address = safeString(pair.pairAddress || "", 160);
    if (!address) continue;
    const chain = safeString(pair.chainId || marketResult.evidence?.dex_chain || "", 80);
    const metricKey = (chain + ":" + address).toLowerCase();
    const relationKey = discoveryKey + ":" + metricKey;
    await db.prepare("INSERT INTO ci_radar_pool_metric_assets (relation_key, discovery_key, metric_key, linked_at) VALUES (?, ?, ?, ?) ON CONFLICT(relation_key) DO UPDATE SET linked_at = excluded.linked_at").bind(relationKey, discoveryKey, metricKey, nowISO()).run();
    linked++;
  }
  return linked;
}

async function persistRadarPoolMetricHistory(db, discoveryKey, marketResult) {
  const pairs = Array.isArray(marketResult?.evidence?.returned_pairs) ? marketResult.evidence.returned_pairs.slice(0, 20) : [];
  let saved = 0;
  for (const pair of pairs) {
    const pairAddress = safeString(pair.pairAddress || "", 160);
    if (!pairAddress) continue;
    const chainId = safeString(pair.chainId || marketResult.evidence?.dex_chain || "", 80);
    const txns = pair.txns?.h24 || {};
    const observedAt = nowISO();
    const evidence = {
      provider: "DexScreener",
      observation_type: "append_only_pool_snapshot",
      liquidity_is_provider_reported: true,
      reserves_are_provider_reported: true,
      executable_depth_not_verified: true,
      price_impact_not_measured: true,
      pair_created_at: pair.pairCreatedAt || null,
      price_change_24h_percent: radarFiniteMetric(pair.priceChange?.h24),
      fdv_usd: radarFiniteMetric(pair.fdv),
      market_cap_usd: radarFiniteMetric(pair.marketCap)
    };
    await db.prepare("INSERT INTO ci_radar_pool_metric_history (observation_id, discovery_key, chain_id, pair_address, dex_id, price_usd, liquidity_usd, base_reserve, quote_reserve, volume_24h_usd, buys_24h, sells_24h, observed_at, source, evidence_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(
      crypto.randomUUID(), discoveryKey, chainId, pairAddress,
      safeString(pair.dexId || "", 100) || null,
      radarFiniteMetric(pair.priceUsd), radarFiniteMetric(pair.liquidity?.usd),
      radarFiniteMetric(pair.liquidity?.base), radarFiniteMetric(pair.liquidity?.quote),
      radarFiniteMetric(pair.volume?.h24), radarFiniteMetric(txns.buys),
      radarFiniteMetric(txns.sells), observedAt, "DexScreener",
      JSON.stringify(evidence)
    ).run();
    saved++;
  }
  return { observations_saved: saved, per_token_batch_limit: 20, history_mode: "append_only", note: "Valeurs rapportées par DexScreener; aucune profondeur exécutable on-chain n'est déduite." };
}


function radarHexWord(hex, index) {
  const value = safeString(hex || "", 10000).replace(/^0x/i, "");
  const word = value.slice(index * 64, index * 64 + 64);
  return word.length === 64 && /^[0-9a-fA-F]+$/.test(word) ? word : null;
}
function radarDecodeAddress(hex) {
  const word = radarHexWord(hex, 0);
  return word ? "0x" + word.slice(-40) : null;
}
async function radarRpcCall(rpcUrl, method, params) {
  const response = await externalJSON(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
  }, 10000);
  const payload = response.data || {};
  if (payload.error) throw new Error(safeString(payload.error.message || "Erreur RPC.", 300));
  if (typeof payload.result !== "string") throw new Error("Réponse RPC sans résultat hexadécimal.");
  return payload.result;
}
async function verifyRadarOnchainPool(db, item, pair) {
  const checkedAt = nowISO();
  const pairAddress = safeString(pair?.pairAddress || "", 160);
  const chainId = safeString(pair?.chainId || item.chain_id || "", 80);
  const dexId = safeString(pair?.dexId || "", 100);
  const checkKey = (item.discovery_key + ":" + chainId + ":" + pairAddress).toLowerCase();
  const rpc = radarPublicRpc(chainId);
  const base = { check_key: checkKey, discovery_key: item.discovery_key, chain_id: chainId, pair_address: pairAddress, dex_id: dexId || null, checked_at: checkedAt };
  if (!rpc) return { ...base, outcome: "unsupported_chain", evidence: { reason: "RPC configuré uniquement pour Ethereum, BSC et Base." }, error_message: null };
  if (!/^0x[a-fA-F0-9]{40}$/.test(pairAddress)) return { ...base, outcome: "invalid_pair_address", evidence: {}, error_message: null };
  try {
    const results = await Promise.all([
      radarRpcCall(rpc.url, "eth_call", [{ to: pairAddress, data: "0x0902f1ac" }, "latest"]),
      radarRpcCall(rpc.url, "eth_call", [{ to: pairAddress, data: "0x0dfe1681" }, "latest"]),
      radarRpcCall(rpc.url, "eth_call", [{ to: pairAddress, data: "0xd21220a7" }, "latest"])
    ]);
    await recordProviderUsage(db, "publicnode_rpc", true, 200);
    const reserve0Word = radarHexWord(results[0], 0);
    const reserve1Word = radarHexWord(results[0], 1);
    const timestampWord = radarHexWord(results[0], 2);
    const token0 = radarDecodeAddress(results[1]);
    const token1 = radarDecodeAddress(results[2]);
    if (!reserve0Word || !reserve1Word || !timestampWord || !token0 || !token1) {
      return { ...base, outcome: "unsupported_pair_interface", evidence: { abi: "Uniswap-V2-compatible", note: "Réponse incompatible; réserves non interprétées." }, error_message: null };
    }
    const decimalsResults = await Promise.all([
      radarRpcCall(rpc.url, "eth_call", [{ to: token0, data: "0x313ce567" }, "latest"]),
      radarRpcCall(rpc.url, "eth_call", [{ to: token1, data: "0x313ce567" }, "latest"])
    ]);
    const decimalsWord0 = radarHexWord(decimalsResults[0], 0);
    const decimalsWord1 = radarHexWord(decimalsResults[1], 0);
    const decimals0 = decimalsWord0 ? Number(BigInt("0x" + decimalsWord0)) : NaN;
    const decimals1 = decimalsWord1 ? Number(BigInt("0x" + decimalsWord1)) : NaN;
    const reserve0 = BigInt("0x" + reserve0Word);
    const reserve1 = BigInt("0x" + reserve1Word);
    const common = {
      ...base, token0_address: token0, token1_address: token1,
      reserve0_raw: reserve0.toString(), reserve1_raw: reserve1.toString(),
      token0_decimals: Number.isInteger(decimals0) && decimals0 >= 0 && decimals0 <= 255 ? decimals0 : null,
      token1_decimals: Number.isInteger(decimals1) && decimals1 >= 0 && decimals1 <= 255 ? decimals1 : null,
      block_timestamp: Number(BigInt("0x" + timestampWord))
    };
    if (common.token0_decimals === null || common.token1_decimals === null) {
      return { ...common, outcome: "reserves_read_decimals_unknown", evidence: { method: "eth_call", raw_reserves_are_onchain: true, adjusted_units_unavailable: true }, error_message: null };
    }
    const adjusted0 = Number(reserve0) / Math.pow(10, decimals0);
    const adjusted1 = Number(reserve1) / Math.pow(10, decimals1);
    return {
      ...common, outcome: "onchain_reserves_read",
      reserve0_adjusted: Number.isFinite(adjusted0) ? adjusted0 : null,
      reserve1_adjusted: Number.isFinite(adjusted1) ? adjusted1 : null,
      evidence: { method: "eth_call", provider: "PublicNode", pair_abi: "Uniswap-V2-compatible", raw_reserves_are_onchain: true, usd_depth_not_calculated: true, price_impact_not_calculated: true },
      error_message: null
    };
  } catch (error) {
    await recordProviderUsage(db, "publicnode_rpc", false, error.status || 500);
    return { ...base, outcome: "unknown", evidence: { rpc_chain_id: rpc.chain_id, method: "eth_call" }, error_message: safeString(error.message || "Lecture on-chain impossible.", 500) };
  }
}


async function persistRadarOnchainPoolHistory(db, result) {
  if (!result || result.outcome !== "onchain_reserves_read" ||
      !(result.reserve0_adjusted > 0) || !(result.reserve1_adjusted > 0)) {
    return { saved: false, reason: "onchain_reserves_not_verified" };
  }
  const previous = await db.prepare(`SELECT snapshot_id, token0_address, token1_address,
      reserve0_adjusted, reserve1_adjusted, checked_at
    FROM ci_radar_onchain_pool_history
    WHERE chain_id = ? AND pair_address = ? AND outcome = 'onchain_reserves_read'
    ORDER BY checked_at DESC LIMIT 1`)
    .bind(result.chain_id, result.pair_address).first();
  let reserve0Change = null;
  let reserve1Change = null;
  let riskSignal = "none";
  const sameTokenOrder = previous &&
    String(previous.token0_address || "").toLowerCase() === String(result.token0_address || "").toLowerCase() &&
    String(previous.token1_address || "").toLowerCase() === String(result.token1_address || "").toLowerCase();
  if (sameTokenOrder) {
    if (Number(previous.reserve0_adjusted) > 0) {
      reserve0Change = ((result.reserve0_adjusted / Number(previous.reserve0_adjusted)) - 1) * 100;
    }
    if (Number(previous.reserve1_adjusted) > 0) {
      reserve1Change = ((result.reserve1_adjusted / Number(previous.reserve1_adjusted)) - 1) * 100;
    }
    if ((reserve0Change !== null && reserve0Change <= -25) ||
        (reserve1Change !== null && reserve1Change <= -25)) {
      riskSignal = "large_onchain_reserve_reduction_observed";
    }
  }
  const snapshotId = crypto.randomUUID();
  const evidence = {
    source: "PublicNode eth_call",
    reserve_values: "onchain_read",
    previous_snapshot_comparison: Boolean(sameTokenOrder),
    same_token_order: Boolean(sameTokenOrder),
    interpretation: riskSignal === "none"
      ? "Aucune baisse individuelle de réserve supérieure ou égale à 25 % observée depuis le dernier relevé comparable."
      : "Baisse importante de réserve observée. Cela peut provenir d'un retrait de liquidité, d'un swap ou d'une autre activité; ce signal seul ne prouve pas un rug pull.",
    previous_checked_at: sameTokenOrder ? previous.checked_at : null
  };
  await db.prepare(`INSERT INTO ci_radar_onchain_pool_history
    (snapshot_id, discovery_key, chain_id, pair_address, checked_at, outcome,
     token0_address, token1_address, reserve0_adjusted, reserve1_adjusted,
     token0_decimals, token1_decimals, block_timestamp, previous_snapshot_id,
     reserve0_change_percent, reserve1_change_percent, risk_signal, evidence_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      snapshotId, result.discovery_key, result.chain_id, result.pair_address,
      result.checked_at, result.outcome, result.token0_address || null,
      result.token1_address || null, result.reserve0_adjusted, result.reserve1_adjusted,
      result.token0_decimals ?? null, result.token1_decimals ?? null,
      result.block_timestamp ?? null, sameTokenOrder ? previous.snapshot_id : null,
      reserve0Change, reserve1Change, riskSignal, JSON.stringify(evidence)
    ).run();
  return {
    saved: true,
    snapshot_id: snapshotId,
    compared_with_previous: Boolean(sameTokenOrder),
    reserve0_change_percent: reserve0Change,
    reserve1_change_percent: reserve1Change,
    risk_signal: riskSignal
  };
}


async function persistRadarOnchainLiquidityAssessment(db,item,pair,result) {
  if (!result || result.outcome!=="onchain_reserves_read" ||
      !(result.reserve0_adjusted>0) || !(result.reserve1_adjusted>0)) {
    return {saved:false,outcome:"onchain_reserves_unavailable"};
  }
  const baseAddress=safeString(pair?.baseToken?.address || "",160).toLowerCase();
  const quoteAddress=safeString(pair?.quoteToken?.address || "",160).toLowerCase();
  const token0=safeString(result.token0_address || "",160).toLowerCase();
  const token1=safeString(result.token1_address || "",160).toLowerCase();
  let baseReserve=null,quoteReserve=null;
  if(token0===baseAddress && token1===quoteAddress) {
    baseReserve=result.reserve0_adjusted; quoteReserve=result.reserve1_adjusted;
  } else if(token1===baseAddress && token0===quoteAddress) {
    baseReserve=result.reserve1_adjusted; quoteReserve=result.reserve0_adjusted;
  } else {
    return {saved:false,outcome:"reserve_token_identity_mismatch"};
  }
  const basePriceUsd=radarFiniteMetric(pair?.priceUsd);
  if(!(basePriceUsd>0) || !(baseReserve>0) || !(quoteReserve>0)) {
    return {saved:false,outcome:"usd_conversion_unavailable"};
  }
  const quotePriceUsd=basePriceUsd*baseReserve/quoteReserve;
  if(!(quotePriceUsd>0) || !Number.isFinite(quotePriceUsd)) {
    return {saved:false,outcome:"quote_price_unavailable"};
  }
  const sizes=[100,500,1000,5000];
  const buy=sizes.map(tradeUsd=>{
    const quoteIn=tradeUsd/quotePriceUsd;
    const received=baseReserve*(quoteIn*0.997)/(quoteReserve+quoteIn*0.997);
    const impact=received>0?Math.max(0,((tradeUsd/received)/basePriceUsd-1)*100):null;
    return {trade_size_usd:tradeUsd,estimated_price_impact_percent:impact};
  });
  const sell=sizes.map(tradeUsd=>{
    const tokenIn=tradeUsd/basePriceUsd;
    const quoteOut=quoteReserve*(tokenIn*0.997)/(baseReserve+tokenIn*0.997);
    const outputUsd=quoteOut*quotePriceUsd;
    return {trade_size_usd:tradeUsd,estimated_price_impact_percent:Math.max(0,(1-outputUsd/tradeUsd)*100)};
  });
  const depthUsd=2*quoteReserve*quotePriceUsd;
  const evidence={
    reserve_source:"PublicNode on-chain eth_call",
    price_reference_source:"DexScreener pair priceUsd",
    quote_price_method:"derived_from_base_price_and_onchain_reserve_ratio",
    pool_depth_usd_is_estimate:true,
    model:"constant_product_xy_k",
    assumed_fee_percent:0.3,
    gas_router_tax_mev_and_slippage_tolerance_excluded:true,
    executable_quote_not_requested:true,
    token0_address:token0,token1_address:token1,
    base_token_address:baseAddress,quote_token_address:quoteAddress,
    warning:"Estimation USD hybride : réserves lues on-chain, prix de référence fourni par DexScreener. Ce n'est ni une cotation exécutable ni une garantie de vente."
  };
  const key=(item.discovery_key+":"+result.chain_id+":"+result.pair_address).toLowerCase();
  await db.prepare(`INSERT INTO ci_radar_onchain_liquidity_assessments
    (assessment_key,discovery_key,chain_id,pair_address,checked_at,outcome,
     estimated_pool_depth_usd,quote_token_price_usd,base_token_price_usd,
     estimated_buy_impact_json,estimated_sell_impact_json,evidence_json)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(assessment_key) DO UPDATE SET checked_at=excluded.checked_at,outcome=excluded.outcome,
    estimated_pool_depth_usd=excluded.estimated_pool_depth_usd,
    quote_token_price_usd=excluded.quote_token_price_usd,
    base_token_price_usd=excluded.base_token_price_usd,
    estimated_buy_impact_json=excluded.estimated_buy_impact_json,
    estimated_sell_impact_json=excluded.estimated_sell_impact_json,evidence_json=excluded.evidence_json`).bind(
      key,item.discovery_key,result.chain_id,result.pair_address,result.checked_at,
      "estimated_from_onchain_reserves_and_provider_price",depthUsd,quotePriceUsd,basePriceUsd,
      JSON.stringify(buy),JSON.stringify(sell),JSON.stringify(evidence)
    ).run();
  return {saved:true,outcome:"estimated_from_onchain_reserves_and_provider_price",
    estimated_pool_depth_usd:depthUsd,buy_impact:buy,sell_impact:sell,evidence};
}

async function runRadarOnchainPoolChecks(db, item, marketResult) {
  const pairs = Array.isArray(marketResult?.evidence?.returned_pairs) ? marketResult.evidence.returned_pairs.filter((pair) => pair?.pairAddress).slice(0, 2) : [];
  const summary = { attempted: 0, onchain_reserves_read: 0, unsupported_pair_interface: 0, unsupported_chain: 0, unknown: 0, batch_limit_per_token: 2 };
  for (const pair of pairs) {
    const result = await verifyRadarOnchainPool(db, item, pair);
    await db.prepare("INSERT INTO ci_radar_onchain_pool_checks (check_key, discovery_key, chain_id, pair_address, dex_id, outcome, checked_at, token0_address, token1_address, reserve0_raw, reserve1_raw, reserve0_adjusted, reserve1_adjusted, token0_decimals, token1_decimals, block_timestamp, evidence_json, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(check_key) DO UPDATE SET outcome = excluded.outcome, checked_at = excluded.checked_at, token0_address = excluded.token0_address, token1_address = excluded.token1_address, reserve0_raw = excluded.reserve0_raw, reserve1_raw = excluded.reserve1_raw, reserve0_adjusted = excluded.reserve0_adjusted, reserve1_adjusted = excluded.reserve1_adjusted, token0_decimals = excluded.token0_decimals, token1_decimals = excluded.token1_decimals, block_timestamp = excluded.block_timestamp, evidence_json = excluded.evidence_json, error_message = excluded.error_message").bind(
      result.check_key, result.discovery_key, result.chain_id, result.pair_address, result.dex_id, result.outcome, result.checked_at,
      result.token0_address || null, result.token1_address || null, result.reserve0_raw || null, result.reserve1_raw || null,
      result.reserve0_adjusted ?? null, result.reserve1_adjusted ?? null, result.token0_decimals ?? null, result.token1_decimals ?? null,
      result.block_timestamp ?? null, JSON.stringify(result.evidence || {}), result.error_message
    ).run();
    const onchainHistory = await persistRadarOnchainPoolHistory(db, result);
    result.history_snapshot = onchainHistory;
    result.usd_liquidity_assessment = await persistRadarOnchainLiquidityAssessment(db, item, pair, result);
    summary.attempted++;
    if (result.outcome === "onchain_reserves_read") summary.onchain_reserves_read++;
    if (result.outcome === "unsupported_pair_interface" || result.outcome === "reserves_read_decimals_unknown") summary.unsupported_pair_interface++;
    if (result.outcome === "unsupported_chain") summary.unsupported_chain++;
    if (result.outcome === "unknown") summary.unknown++;
  }
  return summary;
}


async function verifyRadarTokenIdentityWithGeckoTerminal(db, item) {
  const aliases = {
    "1":"eth", ethereum:"eth", eth:"eth",
    "56":"bsc", bsc:"bsc", binance:"bsc", "binance-smart-chain":"bsc",
    "8453":"base", base:"base",
    "solana":"solana", "42161":"arbitrum", arbitrum:"arbitrum",
    "137":"polygon_pos", polygon:"polygon_pos", polygon_pos:"polygon_pos",
    "10":"optimism", optimism:"optimism",
    "43114":"avax", avalanche:"avax", avax:"avax",
    "250":"ftm", fantom:"ftm", "59144":"linea", linea:"linea",
    "534352":"scroll", scroll:"scroll"
  };
  const network = aliases[safeString(item.chain_id || "",80).toLowerCase()] || null;
  const address = safeString(item.contract_address || "",160);
  const checkedAt = nowISO();
  const checkKey = item.discovery_key + ":geckoterminal_identity";
  if (!network || !address) {
    return { check_key:checkKey, discovery_key:item.discovery_key, provider:"GeckoTerminal",
      outcome:"unsupported", checked_at:checkedAt, network_id:network, token_address:address,
      metadata:{}, error_message:null };
  }
  try {
    const url = "https://api.geckoterminal.com/api/v2/networks/" +
      encodeURIComponent(network) + "/tokens/" + encodeURIComponent(address) + "/info";
    const {data,status}=await externalJSON(url);
    await recordProviderUsage(db,"geckoterminal_token_info",true,status);
    const attrs=data?.data?.attributes || {};
    const metadata={
      name:attrs.name || null,
      symbol:attrs.symbol || null,
      address:attrs.address || address,
      description:attrs.description || null,
      image_url:attrs.image_url || null,
      websites:Array.isArray(attrs.websites)?attrs.websites:[],
      discord_url:attrs.discord_url || null,
      telegram_handle:attrs.telegram_handle || null,
      twitter_handle:attrs.twitter_handle || null,
      coingecko_coin_id:attrs.coingecko_coin_id || null,
      categories:Array.isArray(attrs.categories)?attrs.categories:[],
      gt_score:radarFiniteMetric(attrs.gt_score),
      gt_verified:typeof attrs.gt_verified==="boolean"?attrs.gt_verified:null,
      provider_updated_at:attrs.updated_at || null
    };
    const hasMetadata=Boolean(metadata.name || metadata.symbol || metadata.description ||
      metadata.websites.length || metadata.twitter_handle || metadata.coingecko_coin_id);
    return {check_key:checkKey,discovery_key:item.discovery_key,provider:"GeckoTerminal",
      outcome:hasMetadata?"metadata_returned":"metadata_empty",checked_at:checkedAt,
      network_id:network,token_address:address,metadata,error_message:null};
  } catch(error) {
    await recordProviderUsage(db,"geckoterminal_token_info",false,error.status || 500);
    return {check_key:checkKey,discovery_key:item.discovery_key,provider:"GeckoTerminal",
      outcome:"unknown",checked_at:checkedAt,network_id:network,token_address:address,
      metadata:{},error_message:safeString(error.message || "Métadonnées indisponibles.",500)};
  }
}

async function persistRadarIdentityCheck(db,result) {
  await db.prepare(`INSERT INTO ci_radar_identity_checks
    (check_key,discovery_key,provider,outcome,checked_at,network_id,token_address,metadata_json,error_message)
    VALUES(?,?,?,?,?,?,?,?,?)
    ON CONFLICT(check_key) DO UPDATE SET outcome=excluded.outcome,checked_at=excluded.checked_at,
    network_id=excluded.network_id,token_address=excluded.token_address,
    metadata_json=excluded.metadata_json,error_message=excluded.error_message`).bind(
      result.check_key,result.discovery_key,result.provider,result.outcome,result.checked_at,
      result.network_id,result.token_address,JSON.stringify(result.metadata || {}),result.error_message
    ).run();
  return {outcome:result.outcome,provider:result.provider,checked_at:result.checked_at};
}

async function runRadarVerification(db) {
  const pending = await db.prepare(`SELECT d.discovery_key, d.chain_id, d.contract_address, d.pair_addresses_json FROM ci_radar_discoveries d LEFT JOIN ci_radar_verifications v ON v.discovery_key = d.discovery_key WHERE d.status = 'quarantine' AND (v.discovery_key IS NULL OR (v.next_check_at IS NOT NULL AND v.next_check_at <= ?)) ORDER BY d.first_seen_at ASC LIMIT 5`).bind(nowISO()).all();
  const summary = { attempted: 0, honeypot_detected: 0, simulation_passed: 0, unknown: 0, unsupported: 0, errors: 0, batch_limit: 5 };
  for (const item of pending.results || []) {
    const result = await verifyRadarTokenWithHoneypot(db, item);
    const identityResult = await verifyRadarTokenIdentityWithGeckoTerminal(db, item);
    await persistRadarIdentityCheck(db, identityResult);
    const goPlusResult = await verifyRadarTokenWithGoPlus(db, item);
    const goPlusSignals = goPlusRiskSignals(goPlusResult.evidence?.token_security);
    if (goPlusResult.outcome !== 'unsupported' && goPlusResult.outcome !== 'unknown') {
      goPlusResult.outcome = goPlusSignals.length ? 'risk_signals' : 'no_flags_returned';
      goPlusResult.evidence = { ...(goPlusResult.evidence || {}), interpreted_risk_signals: goPlusSignals, risk_assessment_version: 2 };
      goPlusResult.evidence.liquidity_assessment = goPlusLiquidityAssessment(goPlusResult.evidence.token_security);
      goPlusResult.evidence.liquidity_assessment = goPlusLiquidityAssessmentV2(goPlusResult.evidence.token_security);
    }
    await persistRadarLpHistory(db, goPlusResult);
    const marketResult = await verifyRadarMarketData(db, item);
    await persistRadarMarketCheck(db, marketResult);
    marketResult.pool_metrics = await persistRadarPoolMetrics(db, item.discovery_key, marketResult);
    marketResult.execution_impact_estimates = await estimateRadarPoolExecutionImpact(db, item.discovery_key);
    marketResult.pool_metrics.asset_links_saved = await persistRadarPoolMetricAssetLinks(db, item.discovery_key, marketResult);
    marketResult.pool_metric_history = await persistRadarPoolMetricHistory(db, item.discovery_key, marketResult);
    marketResult.onchain_pool_checks = await runRadarOnchainPoolChecks(db, item, marketResult);
    marketResult.onchain_pool_checks = await runRadarOnchainPoolChecks(db, item, marketResult);
    await persistRadarSecurityCheck(db, goPlusResult);
    await db.prepare(`INSERT INTO ci_radar_verifications (discovery_key, provider, outcome, simulation_success, risk, checked_at, next_check_at, evidence_json, error_message) VALUES (?, 'Honeypot.is', ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(discovery_key) DO UPDATE SET provider = excluded.provider, outcome = excluded.outcome, simulation_success = excluded.simulation_success, risk = excluded.risk, checked_at = excluded.checked_at, next_check_at = excluded.next_check_at, evidence_json = excluded.evidence_json, error_message = excluded.error_message`).bind(result.discovery_key, result.outcome, result.simulation_success, result.risk, result.checked_at, result.next_check_at, JSON.stringify(result.evidence), result.error_message).run();
    summary.attempted++;
    if (result.outcome === 'honeypot_detected') summary.honeypot_detected++; else if (result.outcome === 'simulation_passed') summary.simulation_passed++; else if (result.outcome === 'unsupported') summary.unsupported++; else summary.unknown++;
    if (result.error_message) summary.errors++;
    if (goPlusResult.error_message) summary.errors++;
    if (marketResult.error_message) summary.errors++;
  }
  return summary;
}

async function runRadarDiscovery(db) {
  await initializeBackendTables(db);
  const scanId = crypto.randomUUID();
  const startedAt = nowISO();
  await db.prepare(`
    INSERT INTO ci_radar_scans (id, started_at, status)
    VALUES (?, ?, 'running')
  `).bind(scanId, startedAt).run();

  const endpoints = [
    { provider: "dexscreener_profiles", url: "https://api.dexscreener.com/token-profiles/latest/v1" },
    { provider: "dexscreener_boosts", url: "https://api.dexscreener.com/token-boosts/latest/v1" },
    { provider: "dexscreener_boosts_top", url: "https://api.dexscreener.com/token-boosts/top/v1" },
    { provider: "geckoterminal_new_pools", url: "https://api.geckoterminal.com/api/v2/networks/new_pools?include=base_token,quote_token,network,dex" }
  ];
  // Sept réseaux supplémentaires parcourus par rotation pour élargir progressivement
  // la couverture sans dépasser huit appels GeckoTerminal par cycle (flux global inclus).
  let radarNetworks = ["eth", "bsc", "base", "solana", "arbitrum", "polygon_pos", "optimism"];
  try {
    const networkCatalog = await getGeckoTerminalNetworks(db);
    const availableNetworks = [...new Set(
      (networkCatalog.networks || []).map((item) => safeString(item.id, 80)).filter(Boolean)
    )];
    if (availableNetworks.length) {
      const rotation = Math.floor(Date.now() / (5 * 60 * 1000)) % availableNetworks.length;
      radarNetworks = Array.from({ length: Math.min(7, availableNetworks.length) }, (_, index) =>
        availableNetworks[(rotation + index) % availableNetworks.length]
      );
    }
  } catch {
    // Le radar conserve les sept réseaux de repli si le catalogue est indisponible.
  }
  for (const network of radarNetworks) {
    endpoints.push({
      provider: "geckoterminal_network_new_pools_" + network,
      url: "https://api.geckoterminal.com/api/v2/networks/" +
        encodeURIComponent(network) + "/new_pools?include=base_token,quote_token,network,dex"
    });
  }

  // Deuxième flux GeckoTerminal sur les mêmes réseaux : pools récemment actifs.
  // Il complète les nouvelles paires sans déclarer ces pools comme nouvellement créés.
  for (const network of radarNetworks) {
    endpoints.push({
      provider: "geckoterminal_network_trending_pools_" + network,
      url: "https://api.geckoterminal.com/api/v2/networks/" +
        encodeURIComponent(network) + "/trending_pools?include=base_token,quote_token,network,dex"
    });
  }

  const responses = await Promise.all(
    endpoints.map((source) => fetchRadarSource(db, source.provider, source.url))
  );
  const discoveries = [];
  const sourceResults = {};

  for (let index = 0; index < responses.length; index++) {
    const response = responses[index];
    const provider = endpoints[index].provider;
    sourceResults[provider] = response.ok
      ? { success: true, items: radarArray(response.data).length }
      : { success: false, error: response.error };
    if (!response.ok) continue;

    if (provider === "dexscreener_profiles" || provider === "dexscreener_boosts") {
      for (const token of radarArray(response.data)) {
        discoveries.push(normalizeRadarToken(
          token.chainId, token.tokenAddress, token.name, token.symbol, provider,
          { url: token.url || null, description: token.description || null,
            icon: token.icon || null, links: token.links || [] }
        ));
      }
    }

    if (provider === "dexscreener_boosts_top") {
      for (const token of radarArray(response.data)) {
        discoveries.push(normalizeRadarToken(
          token.chainId, token.tokenAddress, token.name, token.symbol, provider,
          { url: token.url || null, icon: token.icon || null,
            links: token.links || [], total_amount: token.totalAmount ?? null }
        ));
      }
    }

    if (provider === "geckoterminal_new_pools") {
      const pools = radarArray(response.data);
      const included = response.data?.included || [];
      for (const pool of pools) {
        const token = geckoTokenAddress(pool, included);
        if (!token) continue;
        const network = pool.relationships?.network?.data?.id ||
          String(pool.id || "").split("_")[0];
        const attrs = pool.attributes || {};
        discoveries.push(normalizeRadarToken(
          network, token.address, token.name, token.symbol, provider,
          { pair_address: attrs.address || null, pair_name: attrs.name || null,
            pair_created_at: attrs.pool_created_at || null,
            reserve_in_usd: attrs.reserve_in_usd ?? null,
            volume_usd: attrs.volume_usd || null }
        ));
      }
    }

    if (provider.startsWith("geckoterminal_network_trending_pools_")) {
      const pools = radarArray(response.data);
      const included = response.data?.included || [];
      for (const pool of pools) {
        const token = geckoTokenAddress(pool, included);
        if (!token) continue;
        const network = pool.relationships?.network?.data?.id ||
          String(pool.id || "").split("_")[0] ||
          provider.slice("geckoterminal_network_trending_pools_".length);
        const attrs = pool.attributes || {};
        discoveries.push(normalizeRadarToken(
          network, token.address, token.name, token.symbol, provider,
          { pair_address: attrs.address || null, pair_name: attrs.name || null,
            pair_created_at: attrs.pool_created_at || null,
            reserve_in_usd: attrs.reserve_in_usd ?? null,
            volume_usd: attrs.volume_usd || null,
            trending_pool_discovery: true,
            discovery_type: "trending_pool_not_confirmed_new" }
        ));
      }
    }

    if (provider.startsWith("geckoterminal_network_new_pools_")) {
      const pools = radarArray(response.data);
      const included = response.data?.included || [];
      for (const pool of pools) {
        const token = geckoTokenAddress(pool, included);
        if (!token) continue;
        const network = pool.relationships?.network?.data?.id ||
          String(pool.id || "").split("_")[0] ||
          provider.slice("geckoterminal_network_new_pools_".length);
        const attrs = pool.attributes || {};
        discoveries.push(normalizeRadarToken(
          network, token.address, token.name, token.symbol, provider,
          { pair_address: attrs.address || null, pair_name: attrs.name || null,
            pair_created_at: attrs.pool_created_at || null,
            reserve_in_usd: attrs.reserve_in_usd ?? null,
            volume_usd: attrs.volume_usd || null,
            network_specific_discovery: true }
        ));
      }
    }
  }

  const unique = new Map();
  for (const item of discoveries) {
    if (!item) continue;
    const key = (item.chain_id + ":" + item.contract_address).toLowerCase();
    const previous = unique.get(key);
    if (!previous) unique.set(key, item);
    else {
      if (item.pair_address) previous.pair_address = item.pair_address;
      if (item.token_name && !previous.token_name) previous.token_name = item.token_name;
      if (item.token_symbol && !previous.token_symbol) previous.token_symbol = item.token_symbol;
      previous.details = { ...(previous.details || {}), [item.source]: item.details };
      previous.source = previous.source + "+" + item.source;
    }
  }

  let inserted = 0;
  let status = "partial";
  let errorSummary = null;
  try {
    inserted = await persistRadarDiscoveries(db, [...unique.values()]);
    const discoveredPairs = await persistRadarPairs(db, discoveries);
    const securityVerification = await runRadarVerification(db);
    const contractVerification = await runRadarContractVerification(db);
    sourceResults.discovered_pairs = discoveredPairs;
    const successfulSources = Object.values(sourceResults).filter((value) => value.success).length;
    status = successfulSources === endpoints.length ? "completed" :
      successfulSources > 0 ? "partial" : "failed";
    sourceResults.security_verification = securityVerification;
    sourceResults.contract_code_verification = contractVerification;
    if (status === "failed") errorSummary = "Aucune source de découverte n'a répondu correctement.";
  } catch (error) {
    status = "failed";
    errorSummary = safeString(error.message || "Erreur d'enregistrement.", 1000);
  }

  await db.prepare(`
    UPDATE ci_radar_scans
    SET completed_at = ?, status = ?, discovered_count = ?,
        source_results_json = ?, error_summary = ?
    WHERE id = ?
  `).bind(
    nowISO(), status, inserted, JSON.stringify(sourceResults), errorSummary, scanId
  ).run();
  await audit(
    db, "radar_scan_" + status,
    "Radar : " + inserted + " nouveau(x) contrat(s) ; sources : " +
    Object.keys(sourceResults).filter((key) => sourceResults[key].success).join(", ")
  );
  return {
    scan_id: scanId, status, newly_discovered_contracts: inserted,
    newly_discovered_pairs: discoveredPairs,
    newly_discovered_pairs: sourceResults.discovered_pairs || 0,
    candidates_received: discoveries.length, sources: sourceResults,
    quarantine: true, scanned_at: startedAt, completed_at: nowISO()
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

  const arbiterOpinion = opinions.find(
    (item) => item.role === "arbiter"
  );

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
    const available = new Set(
      (info.results || []).map((col) => col.name)
    );

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

  const columns = new Set(
    (info.results || []).map((item) => item.name)
  );

  if (!columns.has("id")) {
    throw new Error("La table assets ne contient pas de colonne id.");
  }

  return db.prepare(
    "SELECT * FROM assets WHERE id = ? LIMIT 1"
  ).bind(id).first();
}

async function insertAssetIfSupported(db, asset) {
  const info = await db.prepare("PRAGMA table_info(assets)").all();

  const available = new Set(
    (info.results || []).map((item) => item.name)
  );

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
  `).bind(
    new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
  ).all();

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

  return {
    id,
    status: "pending",
    task_type: taskType
  };
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
  const contract = safeString(
    asset.contract_address || "Non disponible",
    150
  );

  return [
    `CRYPTO INTELLIGENCE — ${category}`,
    "",
    `Actif : ${name} (${symbol})`,
    `Blockchain : ${chain}`,
    `Contrat : ${contract}`,
    "",
    safeString(details, 2000),
    "",
    appUrl
      ? `Analyse complète : ${appUrl}`
      : "Consulte l'application pour l'analyse complète.",
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
        restoration_preview: Boolean(env.ARCHIVES),
        restoration: false,
        automatic_deletion: false,
        prefix: ARCHIVE_PREFIX,
        maximum_rows_per_table: ARCHIVE_MAX_ROWS_PER_TABLE,
        maximum_archive_bytes: ARCHIVE_MAX_BYTES,
        maximum_preview_rows: ARCHIVE_PREVIEW_MAX_TOTAL_ROWS,
        listing_page_limit: ARCHIVE_LIST_LIMIT
      },
      note:
        "La prévisualisation compare une archive vérifiée avec D1 sans exécuter d'insertion, de modification ou de suppression. La restauration réelle reste désactivée."
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

  /*
   * PRÉVISUALISATION :
   * GET /api/archives/preview?key=...
   *
   * Cette route est protégée par APP_SECRET.
   * Elle ne réalise aucune écriture dans D1 ou R2.
   */
  if (method === "GET" && path === "/api/archives/preview") {
    const key = url.searchParams.get("key");

    if (!key) {
      return errorResponse(
        "Paramètre key requis. Il doit contenir la clé snapshot.json de l'archive."
      );
    }

    const result = await previewDatabaseArchive(db, env, key);

    return json({
      success: true,
      preview: result
    });
  }


  if (method === "GET" && path === "/api/archives/restore/status") {
    return json({
      success: true,
      restoration: {
        implemented: true,
        enabled: true,
        requires_explicit_confirmation: true,
        confirmation_phrase: "RESTAURER CETTE ARCHIVE",
        safety_backup_required: true,
        inserts_only: true,
        updates: false,
        deletions: false,
        transactional_batch: true,
        post_restore_verification: true
      }
    });
  }

  if (method === "POST" && path === "/api/archives/restore") {
    const body = await readBody(request, 20000);

    if (!body.snapshot_key || !body.checksum || !body.confirmation) {
      return errorResponse(
        "snapshot_key, checksum et confirmation explicite sont requis."
      );
    }

    const result = await restoreDatabaseArchive(
      db,
      env,
      body.snapshot_key,
      body.checksum,
      body.confirmation
    );

    return json(result, result.success ? 200 : 409);
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
    const id = decodeURIComponent(
      path.slice("/api/assets/".length)
    );

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

    await audit(
      db,
      "asset_added",
      `Actif ajouté : ${asset.symbol || asset.name}`
    );

    return json({ success: true, asset }, 201);
  }

  /* ------------------------------ RADAR ---------------------------------- */

  if (method === "GET" && path === "/api/radar/discoveries") {
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    const status = url.searchParams.get("status");
    const result = status
      ? await db.prepare(
          "SELECT * FROM ci_radar_discoveries WHERE status = ? ORDER BY first_seen_at DESC LIMIT ?"
        ).bind(status, limit).all()
      : await db.prepare(
          "SELECT * FROM ci_radar_discoveries ORDER BY first_seen_at DESC LIMIT ?"
        ).bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, discoveries: result.results || [] });
  }

  if (method === "GET" && path === "/api/radar/pairs") {
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    const result = await db.prepare(
      "SELECT * FROM ci_radar_pairs ORDER BY first_seen_at DESC LIMIT ?"
    ).bind(limit).all();
    return json({
      success: true,
      count: result.results?.length || 0,
      pairs: result.results || []
    });
  }

  if (method === "GET" && path === "/api/radar/market-checks") {
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    const result = await db.prepare(`SELECT m.*, d.chain_id, d.contract_address, d.token_name, d.token_symbol FROM ci_radar_market_checks m JOIN ci_radar_discoveries d ON d.discovery_key = m.discovery_key ORDER BY m.checked_at DESC LIMIT ?`).bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, checks: result.results || [] });
  }
  if (method === "GET" && path === "/api/radar/security-checks") {
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    const result = await db.prepare(`SELECT s.*, d.chain_id, d.contract_address, d.token_name, d.token_symbol FROM ci_radar_security_checks s JOIN ci_radar_discoveries d ON d.discovery_key = s.discovery_key ORDER BY s.checked_at DESC LIMIT ?`).bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, checks: result.results || [] });
  }
  if (method === "GET" && path === "/api/radar/verifications") {
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    const result = await db.prepare(`SELECT v.*, d.chain_id, d.contract_address, d.token_name, d.token_symbol FROM ci_radar_verifications v JOIN ci_radar_discoveries d ON d.discovery_key = v.discovery_key ORDER BY v.checked_at DESC LIMIT ?`).bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, verifications: result.results || [] });
  }
  if (method === "GET" && path === "/api/radar/pool-metric-history") {
    const limit = Math.max(1, Math.min(1000, Number(url.searchParams.get("limit")) || 200));
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const pairAddress = safeString(url.searchParams.get("pair_address") || "", 160);
    let query = "SELECT h.* FROM ci_radar_pool_metric_history h WHERE 1 = 1";
    const values = [];
    if (discoveryKey) {
      query += " AND h.discovery_key = ?";
      values.push(discoveryKey);
    }
    if (pairAddress) {
      query += " AND lower(h.pair_address) = lower(?)";
      values.push(pairAddress);
    }
    query += " ORDER BY h.observed_at DESC LIMIT ?";
    values.push(limit);
    const result = await db.prepare(query).bind(...values).all();
    return json({
      success: true,
      count: result.results?.length || 0,
      observations: result.results || [],
      note: "Historique append-only des observations DexScreener. Les liquidités et réserves restent des valeurs déclarées par le fournisseur, pas une mesure indépendante de profondeur exécutable."
    });
  }

  if (method === "GET" && path === "/api/radar/pool-metrics") {
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const result = discoveryKey
      ? await db.prepare("SELECT m.* FROM ci_radar_pool_metric_assets a JOIN ci_radar_pool_metrics m ON m.metric_key = a.metric_key WHERE a.discovery_key = ? ORDER BY m.observed_at DESC LIMIT ?").bind(discoveryKey, limit).all()
      : await db.prepare("SELECT * FROM ci_radar_pool_metrics ORDER BY observed_at DESC LIMIT ?").bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, metrics: result.results || [], note: "Liquidités déclarées par DexScreener; profondeur exécutable et impact de prix non vérifiés." });
  }

  if (method === "GET" && path === "/api/radar/pool-metrics") {
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const result = discoveryKey
      ? await db.prepare("SELECT * FROM ci_radar_pool_metrics WHERE discovery_key = ? ORDER BY observed_at DESC LIMIT ?").bind(discoveryKey, limit).all()
      : await db.prepare("SELECT * FROM ci_radar_pool_metrics ORDER BY observed_at DESC LIMIT ?").bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, metrics: result.results || [], note: "Liquidités déclarées par DexScreener; profondeur exécutable et impact de prix non vérifiés." });
  }

  if (method === "GET" && path === "/api/radar/onchain-pool-checks") {
    const limit = Math.max(1, Math.min(1000, Number(url.searchParams.get("limit")) || 200));
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const pairAddress = safeString(url.searchParams.get("pair_address") || "", 160);
    let query = "SELECT * FROM ci_radar_onchain_pool_checks WHERE 1 = 1";
    const values = [];
    if (discoveryKey) { query += " AND discovery_key = ?"; values.push(discoveryKey); }
    if (pairAddress) { query += " AND lower(pair_address) = lower(?)"; values.push(pairAddress); }
    query += " ORDER BY checked_at DESC LIMIT ?";
    values.push(limit);
    const result = await db.prepare(query).bind(...values).all();
    return json({ success: true, count: result.results?.length || 0, checks: result.results || [], note: "Réserves brutes lues sur la blockchain via une ABI compatible Uniswap V2; ce résultat n'est pas une profondeur exécutable en USD ni une simulation d'impact de prix." });
  }

  if (method === "GET" && path === "/api/radar/contract-checks") {
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    const result = await db.prepare("SELECT c.*, d.chain_id, d.contract_address, d.token_name, d.token_symbol FROM ci_radar_contract_checks c JOIN ci_radar_discoveries d ON d.discovery_key = c.discovery_key ORDER BY c.checked_at DESC LIMIT ?").bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, checks: result.results || [] });
  }


  if (method === "GET" && path === "/api/radar/identity-checks") {
    const limit=Math.max(1,Math.min(500,Number(url.searchParams.get("limit"))||100));
    const discoveryKey=safeString(url.searchParams.get("discovery_key")||"",200);
    const result=discoveryKey
      ? await db.prepare("SELECT * FROM ci_radar_identity_checks WHERE discovery_key = ? ORDER BY checked_at DESC LIMIT ?").bind(discoveryKey,limit).all()
      : await db.prepare("SELECT * FROM ci_radar_identity_checks ORDER BY checked_at DESC LIMIT ?").bind(limit).all();
    return json({success:true,count:result.results?.length||0,checks:result.results||[]});
  }
  if (method === "GET" && path === "/api/radar/lp-history") {
    const limit=Math.max(1,Math.min(1000,Number(url.searchParams.get("limit"))||200));
    const discoveryKey=safeString(url.searchParams.get("discovery_key")||"",200);
    const result=discoveryKey
      ? await db.prepare("SELECT * FROM ci_radar_lp_history WHERE discovery_key = ? ORDER BY checked_at DESC LIMIT ?").bind(discoveryKey,limit).all()
      : await db.prepare("SELECT * FROM ci_radar_lp_history ORDER BY checked_at DESC LIMIT ?").bind(limit).all();
    return json({success:true,count:result.results?.length||0,history:result.results||[],
      note:"Les données de verrouillage reflètent uniquement les détenteurs et lockers rapportés par GoPlus; les inconnues restent inconnues."});
  }
  if (method === "GET" && path === "/api/radar/onchain-pool-history") {
    const limit=Math.max(1,Math.min(1000,Number(url.searchParams.get("limit"))||200));
    const discoveryKey=safeString(url.searchParams.get("discovery_key")||"",200);
    const pairAddress=safeString(url.searchParams.get("pair_address")||"",160);
    let query="SELECT * FROM ci_radar_onchain_pool_history WHERE 1=1";
    const values=[];
    if(discoveryKey){query+=" AND discovery_key = ?";values.push(discoveryKey);}
    if(pairAddress){query+=" AND lower(pair_address)=lower(?)";values.push(pairAddress);}
    query+=" ORDER BY checked_at DESC LIMIT ?";values.push(limit);
    const result=await db.prepare(query).bind(...values).all();
    return json({success:true,count:result.results?.length||0,history:result.results||[],
      note:"Historique append-only des réserves observées on-chain; une baisse ne prouve pas à elle seule un retrait LP frauduleux."});
  }
  if (method === "GET" && path === "/api/radar/onchain-liquidity-assessments") {
    const limit=Math.max(1,Math.min(1000,Number(url.searchParams.get("limit"))||200));
    const discoveryKey=safeString(url.searchParams.get("discovery_key")||"",200);
    const result=discoveryKey
      ? await db.prepare("SELECT * FROM ci_radar_onchain_liquidity_assessments WHERE discovery_key = ? ORDER BY checked_at DESC LIMIT ?").bind(discoveryKey,limit).all()
      : await db.prepare("SELECT * FROM ci_radar_onchain_liquidity_assessments ORDER BY checked_at DESC LIMIT ?").bind(limit).all();
    return json({success:true,count:result.results?.length||0,assessments:result.results||[],
      note:"Profondeur USD estimée à partir de réserves on-chain et d'un prix fournisseur; estimation non exécutable."});
  }


  if (method === "GET" && path === "/api/radar/lifecycle") {
    const synchronization = await syncRadarAssetLifecycle(db, 5000);
    const missingSynchronization = await syncRadarAssetLifecycleMissing(db, 1000);
    const stage = safeString(url.searchParams.get("stage") || "", 80);
    if (stage && !RADAR_LIFECYCLE_STAGES.includes(stage)) return errorResponse("Étape de cycle de vie invalide.");
    const limit = Math.max(1, Math.min(1000, Number(url.searchParams.get("limit")) || 200));
    const result = stage
      ? await db.prepare("SELECT l.*, d.chain_id, d.contract_address, d.token_name, d.token_symbol, d.first_seen_at FROM ci_radar_asset_lifecycle l JOIN ci_radar_discoveries d ON d.discovery_key = l.discovery_key WHERE l.current_stage = ? ORDER BY l.updated_at DESC LIMIT ?").bind(stage, limit).all()
      : await db.prepare("SELECT l.*, d.chain_id, d.contract_address, d.token_name, d.token_symbol, d.first_seen_at FROM ci_radar_asset_lifecycle l JOIN ci_radar_discoveries d ON d.discovery_key = l.discovery_key ORDER BY l.updated_at DESC LIMIT ?").bind(limit).all();
    const counts = await db.prepare("SELECT current_stage, COUNT(*) AS count FROM ci_radar_asset_lifecycle GROUP BY current_stage").all();
    return json({ success: true, stages: RADAR_LIFECYCLE_STAGES, counts: counts.results || [], count: result.results?.length || 0, assets: result.results || [], synchronization, missing_synchronization: missingSynchronization });
  }

  if (method === "GET" && path === "/api/radar/lifecycle-history") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const limit = Math.max(1, Math.min(1000, Number(url.searchParams.get("limit")) || 200));
    const result = discoveryKey
      ? await db.prepare("SELECT * FROM ci_radar_asset_lifecycle_history WHERE discovery_key = ? ORDER BY transitioned_at DESC LIMIT ?").bind(discoveryKey, limit).all()
      : await db.prepare("SELECT * FROM ci_radar_asset_lifecycle_history ORDER BY transitioned_at DESC LIMIT ?").bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, history: result.results || [] });
  }

  if (method === "POST" && path === "/api/radar/lifecycle/transition") {
    const body = await readBody(request);
    if (!body.evidence || typeof body.evidence !== "object" || Array.isArray(body.evidence) || Object.keys(body.evidence).length === 0) return errorResponse("Des preuves structurées non vides sont obligatoires pour chaque transition.");
    const result = await transitionRadarAssetLifecycle(db, body);
    if (result.error) return errorResponse(result.error, 400);
    return json({ success: true, transition: result }, 201);
  }

  if (method === "GET" && path === "/api/radar/status") {
    const [totals, latest] = await Promise.all([
      db.prepare("SELECT status, COUNT(*) AS count FROM ci_radar_discoveries GROUP BY status").all(),
      db.prepare("SELECT * FROM ci_radar_scans ORDER BY started_at DESC LIMIT 1").first()
    ]);
    return json({
      success: true,
      radar: {
        implemented: true,
        automatic_schedule: "*/5 * * * *",
        sources: ["DexScreener token profiles", "DexScreener latest boosts", "GeckoTerminal new pools"],
        status_counts: totals.results || [],
        latest_scan: latest || null
      }
    });
  }

  if (method === "POST" && path === "/api/radar/scan") {
    return json({ success: true, scan: await runRadarDiscovery(db) });
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
    const tasks = await listTasks(
      db,
      url.searchParams.get("limit") || 100
    );

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
      return errorResponse(
        "asset, category et details sont requis."
      );
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
            manifest_verification: Boolean(env.ARCHIVES),
            restoration_preview: Boolean(env.ARCHIVES),
            controlled_restoration: false,
            automatic_deletion: false
          }
        }
      },
      note:
        "Les fonctions de sauvegarde D1, de liste paginée, de vérification SHA-256 et de prévisualisation sans modification de D1 sont intégrées au backend. La restauration contrôlée et la mémoire personnelle de Conan ne sont pas encore intégrées."
    });
  }

  /* -------------------------------- CONAN -------------------------------- */

  if (method === "POST" && path === "/api/conan/command") {
    const body = await readBody(request);

    if (!body.command) {
      return errorResponse("Commande Conan requise.");
    }

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
          preview_route: Boolean(env.ARCHIVES),
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
    return new Response(null, {
      status: 204,
      headers
    });
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
          ? {
              message: safeString(error.message, 1000),
              verification: error.verification || undefined
            }
          : undefined
      ),
      headers
    );
  }
}


/* RADAR: vérification on-chain indépendante du fournisseur de marché */
function radarPublicRpc(chain) {
  const normalized = safeString(chain, 80).trim().toLowerCase();
  const networks = {
    ethereum: ["1", "https://ethereum-rpc.publicnode.com"],
    eth: ["1", "https://ethereum-rpc.publicnode.com"],
    "1": ["1", "https://ethereum-rpc.publicnode.com"],
    bsc: ["56", "https://bsc-rpc.publicnode.com"],
    binance: ["56", "https://bsc-rpc.publicnode.com"],
    "56": ["56", "https://bsc-rpc.publicnode.com"],
    base: ["8453", "https://base-rpc.publicnode.com"],
    "8453": ["8453", "https://base-rpc.publicnode.com"]
  };
  return networks[normalized] ? { chain_id: networks[normalized][0], url: networks[normalized][1] } : null;
}
function goPlusValueIsEnabled(value) {
  if (value === true || value === 1) return true;
  if (value === false || value === 0 || value === null || value === undefined) return false;
  const normalized = String(value).trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes";
}
function goPlusLiquidityAssessment(token) {
  if (!token || typeof token !== "object" || !Array.isArray(token.lp_holders)) {
    return {
      status: "unknown",
      reason: "GoPlus n'a pas fourni de liste lp_holders exploitable.",
      provider: "GoPlus",
      coverage: "Aucune conclusion sur le verrouillage ou la distribution des LP."
    };
  }
  const holders = token.lp_holders.filter((holder) => holder && typeof holder === "object");
  const parsed = holders.map((holder) => ({
    percent: radarFiniteMetric(holder.percent),
    locked: goPlusValueIsEnabled(holder.is_locked),
    address: safeString(holder.address || "", 160) || null,
    tag: safeString(holder.tag || "", 120) || null,
    locked_detail: Array.isArray(holder.locked_detail) ? holder.locked_detail : []
  }));
  const known = parsed.filter((holder) => holder.percent !== null);
  const lockedShare = known.filter((holder) => holder.locked).reduce((sum, holder) => sum + holder.percent, 0);
  const unlockedShare = known.filter((holder) => !holder.locked).reduce((sum, holder) => sum + holder.percent, 0);
  const topHolderShare = known.length ? Math.max(...known.map((holder) => holder.percent)) : null;
  const topThreeShare = known.slice(0, 3).reduce((sum, holder) => sum + holder.percent, 0);
  const unlockEvents = parsed.flatMap((holder) => holder.locked_detail.map((detail) => ({
    holder: holder.address,
    tag: holder.tag,
    end_time: detail?.end_time ?? null,
    amount: detail?.amount ?? null
  })));
  return {
    status: holders.length ? "observed" : "unknown",
    provider: "GoPlus",
    lp_holder_count_reported: radarFiniteMetric(token.lp_holder_count),
    lp_total_supply_reported: token.lp_total_supply ?? null,
    top_lp_holders_returned: holders.length,
    top_holders_with_percentage: known.length,
    top10_locked_share_percent: known.length ? lockedShare * 100 : null,
    top10_unlocked_share_percent: known.length ? unlockedShare * 100 : null,
    largest_reported_lp_holder_percent: topHolderShare === null ? null : topHolderShare * 100,
    first_three_reported_lp_holders_percent: known.length ? topThreeShare * 100 : null,
    unlock_events: unlockEvents,
    coverage: "Analyse limitée aux détenteurs LP renvoyés par GoPlus (jusqu'aux dix premiers) et aux lockers reconnus par ce fournisseur. Les absences de données ne prouvent pas l'absence de verrouillage."
  };
}


function goPlusLiquidityAssessmentV2(token) {
  const assessment = goPlusLiquidityAssessment(token);
  if (!token || !Array.isArray(token.lp_holders)) return assessment;
  const holders = token.lp_holders.filter((holder) => holder && typeof holder === "object");
  const known = holders.map((holder) => ({
    percent: radarFiniteMetric(holder.percent),
    locked: holder.is_locked === undefined || holder.is_locked === null || holder.is_locked === "" ? null : goPlusValueIsEnabled(holder.is_locked)
  })).filter((holder) => holder.percent !== null);
  const lockKnown = known.filter((holder) => holder.locked !== null);
  const locked = lockKnown.filter((holder) => holder.locked === true).reduce((sum, holder) => sum + holder.percent, 0);
  const unlocked = lockKnown.filter((holder) => holder.locked === false).reduce((sum, holder) => sum + holder.percent, 0);
  const unknown = known.filter((holder) => holder.locked === null).reduce((sum, holder) => sum + holder.percent, 0);
  return {
    ...assessment,
    top10_locked_share_percent: lockKnown.length ? locked * 100 : null,
    top10_unlocked_share_percent: lockKnown.length ? unlocked * 100 : null,
    top10_lock_status_unknown_share_percent: known.length ? unknown * 100 : null,
    lock_status_interpretation: "Les détenteurs sans indicateur is_locked explicite restent non classés; ils ne sont pas considérés comme déverrouillés."
  };
}

async function persistRadarLpHistory(db, goPlusResult) {
  const assessment = goPlusResult?.evidence?.liquidity_assessment || {};
  const checkedAt = goPlusResult?.checked_at || nowISO();
  const tokenSecurity = goPlusResult?.evidence?.token_security || null;
  const evidence = {
    assessment,
    provider_outcome: goPlusResult?.outcome || "unknown",
    provider_error: goPlusResult?.error_message || null,
    token_security_available: Boolean(tokenSecurity),
    interpretation: "Historique append-only des observations LP. Les données absentes restent inconnues et ne sont pas interprétées comme une absence de risque."
  };
  await db.prepare(`INSERT INTO ci_radar_lp_history
    (snapshot_id, discovery_key, provider, checked_at, assessment_status,
     top10_locked_share_percent, top10_unlocked_share_percent,
     top10_lock_status_unknown_share_percent, largest_lp_holder_percent,
     first_three_lp_holders_percent, reported_lp_holder_count,
     unlock_events_json, evidence_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      crypto.randomUUID(),
      goPlusResult?.discovery_key || "",
      goPlusResult?.provider || "GoPlus",
      checkedAt,
      safeString(assessment.status || "unknown", 40),
      radarFiniteMetric(assessment.top10_locked_share_percent),
      radarFiniteMetric(assessment.top10_unlocked_share_percent),
      radarFiniteMetric(assessment.top10_lock_status_unknown_share_percent),
      radarFiniteMetric(assessment.largest_reported_lp_holder_percent),
      radarFiniteMetric(assessment.first_three_reported_lp_holders_percent),
      radarFiniteMetric(assessment.lp_holder_count_reported),
      JSON.stringify(assessment.unlock_events || []),
      JSON.stringify(evidence)
    ).run();
  return {
    saved: true,
    snapshot_id_created: true,
    assessment_status: assessment.status || "unknown",
    history_mode: "append_only"
  };
}


function goPlusRiskSignals(token) {
  if (!token || typeof token !== "object") return [];
  const signals = [];
  const fields = ["is_honeypot", "cannot_buy", "cannot_sell_all", "hidden_owner", "selfdestruct", "external_call", "owner_change_balance", "can_take_back_ownership", "is_blacklisted", "transfer_pausable", "is_mintable", "slippage_modifiable", "personal_slippage_modifiable", "trading_cooldown", "is_anti_whale", "anti_whale_modifiable", "is_airdrop_scam", "is_proxy"];
  for (const key of fields) if (goPlusValueIsEnabled(token[key])) signals.push(key);
  for (const key of ["buy_tax", "sell_tax", "transfer_tax"]) {
    const raw = token[key];
    if (raw === "" || raw === null || raw === undefined) continue;
    const numeric = Number(raw);
    if (Number.isFinite(numeric) && numeric > 0) signals.push(key);
  }
  if (token.is_open_source === "0" || token.is_open_source === 0 || token.is_open_source === false) signals.push("is_open_source_false");
  if (token.other_potential_risks) signals.push("other_potential_risks");
  if (token.fake_token && goPlusValueIsEnabled(token.fake_token.value)) signals.push("fake_token");
  return [...new Set(signals)];
}
async function verifyRadarContractCode(db, item) {
  const checkedAt = nowISO();
  const checkKey = item.discovery_key + ":publicnode_code";
  const rpc = radarPublicRpc(item.chain_id);
  const address = safeString(item.contract_address, 100);
  if (!rpc) return { check_key: checkKey, discovery_key: item.discovery_key, provider: "PublicNode RPC", outcome: "unsupported", checked_at: checkedAt, contract_code_present: null, evidence: { requested_chain: item.chain_id, reason: "Réseau EVM non encore configuré pour cette vérification RPC." }, error_message: null };
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return { check_key: checkKey, discovery_key: item.discovery_key, provider: "PublicNode RPC", outcome: "invalid_address", checked_at: checkedAt, contract_code_present: null, evidence: { requested_chain: item.chain_id, address_format: "invalid_evm_address" }, error_message: null };
  try {
    const response = await externalJSON(rpc.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getCode", params: [address, "latest"] })
    }, 10000);
    const payload = response.data || {};
    if (payload.error) throw new Error(safeString(payload.error.message || "Erreur RPC.", 300));
    const code = typeof payload.result === "string" ? payload.result : null;
    if (code === null || !/^0x[0-9a-fA-F]*$/.test(code)) throw new Error("Réponse eth_getCode invalide.");
    const hasCode = code.length > 2;
    await recordProviderUsage(db, "publicnode_rpc", true, response.status);
    return { check_key: checkKey, discovery_key: item.discovery_key, provider: "PublicNode RPC", outcome: hasCode ? "contract_code_present" : "no_contract_code", checked_at: checkedAt, contract_code_present: hasCode ? 1 : 0, evidence: { chain_id: rpc.chain_id, address, bytecode_bytes: hasCode ? Math.max(0, (code.length - 2) / 2) : 0, method: "eth_getCode", block: "latest", note: "Bytecode présent ne signifie pas que le contrat est un token ERC-20 légitime ni qu'il est sûr." }, error_message: null };
  } catch (error) {
    await recordProviderUsage(db, "publicnode_rpc", false, error.status || 500);
    return { check_key: checkKey, discovery_key: item.discovery_key, provider: "PublicNode RPC", outcome: "unknown", checked_at: checkedAt, contract_code_present: null, evidence: { chain_id: rpc.chain_id, address, rpc_url: rpc.url }, error_message: safeString(error.message || "Vérification RPC indisponible.", 500) };
  }
}
async function runRadarContractVerification(db) {
  const threshold = new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString();
  const pending = await db.prepare("SELECT d.discovery_key, d.chain_id, d.contract_address FROM ci_radar_discoveries d LEFT JOIN ci_radar_contract_checks c ON c.discovery_key = d.discovery_key WHERE d.status = 'quarantine' AND (c.checked_at IS NULL OR c.checked_at <= ?) ORDER BY d.first_seen_at ASC LIMIT 5").bind(threshold).all();
  const summary = { attempted: 0, contract_code_present: 0, no_contract_code: 0, unknown: 0, unsupported: 0, invalid_address: 0, errors: 0, batch_limit: 5 };
  for (const item of pending.results || []) {
    const result = await verifyRadarContractCode(db, item);
    await db.prepare("INSERT INTO ci_radar_contract_checks (check_key, discovery_key, provider, outcome, contract_code_present, checked_at, evidence_json, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(check_key) DO UPDATE SET outcome = excluded.outcome, contract_code_present = excluded.contract_code_present, checked_at = excluded.checked_at, evidence_json = excluded.evidence_json, error_message = excluded.error_message").bind(result.check_key, result.discovery_key, result.provider, result.outcome, result.contract_code_present, result.checked_at, JSON.stringify(result.evidence || {}), result.error_message).run();
    summary.attempted++;
    if (Object.prototype.hasOwnProperty.call(summary, result.outcome)) summary[result.outcome]++;
    if (result.error_message) summary.errors++;
  }
  return summary;
}

export default {
  async fetch(request, env, ctx) {
    const response = await handleRequest(request, env, ctx);

    const headers = new Headers(response.headers);

    headers.set("X-Frame-Options", "DENY");
    headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
    headers.set(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=()"
    );
    headers.set("X-Content-Type-Options", "nosniff");

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers
    });
  },

  async scheduled(controller, env, ctx) {
    const db = getDB(env);
    const task = runRadarDiscovery(db);
    if (ctx?.waitUntil) ctx.waitUntil(task);
    else await task;
  }
};
