
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
  "ci_investigation_reports",
  "ci_investigation_evidence",
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
  ,"ci_investment_evaluations"
  ,"ci_investment_decisions"
  ,"ci_ai_council_sessions"
  ,"ci_ai_council_opinions"
  ,"ci_collective_opportunity_runs"
  ,"ci_collective_opportunity_signals"
  ,"ci_collective_opportunity_history"

  ,"ci_wallet_watchlist"
  ,"ci_wallet_scan_cursors"
  ,"ci_wallet_events"
  ,"ci_wallet_behavior_signals"
  ,"ci_wallet_clusters"
  ,"ci_conan_prediction_cycles"
  ,"ci_conan_prediction_assets"
  ,"ci_conan_prediction_observations"
  ,"ci_conan_predictions"
  ,"ci_conan_prediction_opinions"
  ,"ci_conan_prediction_progress"
  ,"ci_conan_prediction_results"
  ,"ci_conan_learning_history"
  ,"ci_conan_score_history"
  ,"ci_conan_growth_state"
  ,"ci_conan_growth_history"
  ,"ci_conan_surveillance_windows"
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

    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_investment_evaluations (
      evaluation_id TEXT PRIMARY KEY,
      discovery_key TEXT NOT NULL,
      overall_score REAL NOT NULL DEFAULT 0,
      coverage_percent REAL NOT NULL DEFAULT 0,
      confidence_percent REAL NOT NULL DEFAULT 0,
      evaluation_status TEXT NOT NULL,
      critical_risk INTEGER NOT NULL DEFAULT 0,
      criteria_json TEXT NOT NULL DEFAULT '{}',
      evidence_json TEXT NOT NULL DEFAULT '{}',
      missing_data_json TEXT NOT NULL DEFAULT '[]',
      risk_flags_json TEXT NOT NULL DEFAULT '[]',
      methodology_version TEXT NOT NULL,
      evaluated_at TEXT NOT NULL,
      evaluator TEXT NOT NULL DEFAULT 'api'
    )`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_investment_evaluations_asset ON ci_investment_evaluations(discovery_key, evaluated_at DESC)`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_investment_evaluations_status ON ci_investment_evaluations(evaluation_status, overall_score DESC, evaluated_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_investment_decisions (
      decision_id TEXT PRIMARY KEY,
      discovery_key TEXT NOT NULL,
      evaluation_id TEXT NOT NULL,
      decision TEXT NOT NULL,
      from_stage TEXT NOT NULL,
      to_stage TEXT NOT NULL,
      reason TEXT NOT NULL,
      evidence_json TEXT NOT NULL DEFAULT '{}',
      decided_at TEXT NOT NULL,
      actor TEXT NOT NULL DEFAULT 'api'
    )`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_investment_decisions_asset ON ci_investment_decisions(discovery_key, decided_at DESC)`)


    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_investigation_reports (
      report_id TEXT PRIMARY KEY,
      discovery_key TEXT NOT NULL,
      report_version INTEGER NOT NULL DEFAULT 1,
      report_status TEXT NOT NULL DEFAULT 'incomplete',
      coverage_percent REAL NOT NULL DEFAULT 0,
      confidence_percent REAL NOT NULL DEFAULT 0,
      sections_json TEXT NOT NULL DEFAULT '{}',
      missing_data_json TEXT NOT NULL DEFAULT '[]',
      risk_register_json TEXT NOT NULL DEFAULT '[]',
      sources_json TEXT NOT NULL DEFAULT '[]',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      analyst TEXT NOT NULL DEFAULT 'api'
    )`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_investigation_reports_asset ON ci_investigation_reports(discovery_key, report_version DESC, updated_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_investigation_evidence (
      evidence_id TEXT PRIMARY KEY,
      report_id TEXT NOT NULL,
      discovery_key TEXT NOT NULL,
      section_key TEXT NOT NULL,
      field_key TEXT NOT NULL,
      value_json TEXT NOT NULL,
      source TEXT NOT NULL,
      observed_at TEXT,
      confidence_percent REAL,
      evidence_status TEXT NOT NULL DEFAULT 'observed',
      recorded_at TEXT NOT NULL
    )`)
    ,db.prepare(`CREATE INDEX IF NOT EXISTS idx_ci_investigation_evidence_report ON ci_investigation_evidence(report_id, section_key, field_key, recorded_at DESC)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_collective_opportunity_runs (run_id TEXT PRIMARY KEY, status TEXT NOT NULL, assets_examined INTEGER NOT NULL DEFAULT 0, signals_created INTEGER NOT NULL DEFAULT 0, candidates_count INTEGER NOT NULL DEFAULT 0, correlations_count INTEGER NOT NULL DEFAULT 0, methodology_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_collective_opportunity_signals (signal_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, discovery_key TEXT NOT NULL, signal_type TEXT NOT NULL, severity TEXT NOT NULL, confidence_percent REAL, metrics_json TEXT NOT NULL DEFAULT '{}', evidence_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL)`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_collective_signals_asset ON ci_collective_opportunity_signals(discovery_key, created_at DESC)")
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_collective_signals_run ON ci_collective_opportunity_signals(run_id, created_at DESC)")
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_collective_opportunity_history (history_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, discovery_key TEXT NOT NULL, classification TEXT NOT NULL, opportunity_score REAL NOT NULL DEFAULT 0, confidence_percent REAL NOT NULL DEFAULT 0, price_change_24h REAL, activity_ratio REAL, buy_pressure REAL, liquidity_usd REAL, pool_depth_usd REAL, market_cap_usd REAL, fdv_usd REAL, circulating_supply REAL, total_supply REAL, sellability_status TEXT NOT NULL DEFAULT 'unknown', critical_risk INTEGER NOT NULL DEFAULT 0, evidence_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL)`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_collective_history_asset ON ci_collective_opportunity_history(discovery_key, created_at DESC)")
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_collective_history_run ON ci_collective_opportunity_history(run_id, created_at DESC)")

    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_wallet_watchlist (
      wallet_key TEXT PRIMARY KEY,
      chain_id TEXT NOT NULL,
      wallet_address TEXT NOT NULL,
      label TEXT,
      wallet_type TEXT NOT NULL DEFAULT 'unknown',
      profile_status TEXT NOT NULL DEFAULT 'user_supplied_unverified',
      source_reference TEXT,
      notes TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(chain_id, wallet_address)
    )`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_wallet_watchlist_address ON ci_wallet_watchlist(chain_id, wallet_address)")
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_wallet_scan_cursors (
      cursor_key TEXT PRIMARY KEY,
      chain_id TEXT NOT NULL,
      pair_address TEXT NOT NULL,
      last_scanned_block INTEGER NOT NULL DEFAULT 0,
      last_scan_at TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      error_message TEXT
    )`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_wallet_events (
      event_id TEXT PRIMARY KEY,
      chain_id TEXT NOT NULL,
      discovery_key TEXT NOT NULL,
      pair_address TEXT NOT NULL,
      wallet_address TEXT NOT NULL,
      recipient_address TEXT,
      transaction_hash TEXT NOT NULL,
      log_index INTEGER NOT NULL,
      block_number INTEGER NOT NULL,
      observed_at TEXT NOT NULL,
      trade_side TEXT NOT NULL,
      target_token_amount REAL,
      estimated_usd_value REAL,
      value_source TEXT NOT NULL DEFAULT 'unknown',
      wallet_category TEXT NOT NULL DEFAULT 'unknown',
      watchlist_status TEXT NOT NULL DEFAULT 'unknown',
      evidence_json TEXT NOT NULL DEFAULT '{}',
      UNIQUE(chain_id, transaction_hash, log_index)
    )`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_wallet_events_asset ON ci_wallet_events(discovery_key, observed_at DESC)")
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_wallet_events_wallet ON ci_wallet_events(chain_id, wallet_address, observed_at DESC)")
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_wallet_events_block ON ci_wallet_events(chain_id, pair_address, block_number DESC)")
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_wallet_behavior_signals (
      signal_id TEXT PRIMARY KEY,
      chain_id TEXT NOT NULL,
      discovery_key TEXT NOT NULL,
      wallet_address TEXT,
      signal_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      confidence_percent REAL,
      window_start TEXT,
      window_end TEXT,
      evidence_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    )`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_wallet_signals_asset ON ci_wallet_behavior_signals(discovery_key, created_at DESC)")
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_wallet_signals_wallet ON ci_wallet_behavior_signals(chain_id, wallet_address, created_at DESC)")
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_wallet_clusters (
      cluster_id TEXT PRIMARY KEY,
      chain_id TEXT NOT NULL,
      discovery_key TEXT NOT NULL,
      cluster_type TEXT NOT NULL,
      verification_status TEXT NOT NULL DEFAULT 'unverified_candidate',
      member_wallets_json TEXT NOT NULL DEFAULT '[]',
      evidence_json TEXT NOT NULL DEFAULT '{}',
      first_observed_at TEXT NOT NULL,
      last_observed_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_wallet_clusters_asset ON ci_wallet_clusters(discovery_key, last_observed_at DESC)")

    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_prediction_cycles (cycle_id TEXT PRIMARY KEY,status TEXT NOT NULL,cycle_start_date TEXT NOT NULL,current_day INTEGER NOT NULL DEFAULT 1,selection_mode TEXT NOT NULL,learning_stage TEXT NOT NULL DEFAULT 'child',methodology_version TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,completed_at TEXT)`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_cycles_status ON ci_conan_prediction_cycles(status,cycle_start_date DESC)")
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_prediction_assets (asset_row_id TEXT PRIMARY KEY,cycle_id TEXT NOT NULL,asset_order INTEGER NOT NULL,discovery_key TEXT NOT NULL,chain_id TEXT NOT NULL,contract_address TEXT NOT NULL,token_name TEXT,token_symbol TEXT,pair_address TEXT NOT NULL,selected_at TEXT NOT NULL,selection_reason TEXT NOT NULL,UNIQUE(cycle_id,discovery_key))`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_cycle_assets ON ci_conan_prediction_assets(cycle_id,asset_order)")
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_prediction_observations (observation_id TEXT PRIMARY KEY,cycle_id TEXT NOT NULL,discovery_key TEXT NOT NULL,cycle_day INTEGER NOT NULL,price_usd REAL,liquidity_usd REAL,volume_24h_usd REAL,buys_24h INTEGER,sells_24h INTEGER,source TEXT NOT NULL,source_observed_at TEXT,observed_at TEXT NOT NULL,evidence_json TEXT NOT NULL DEFAULT '{}')`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_observations_asset ON ci_conan_prediction_observations(cycle_id,discovery_key,observed_at DESC)")
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_observations_day ON ci_conan_prediction_observations(cycle_id,cycle_day)")
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_predictions (prediction_id TEXT PRIMARY KEY,cycle_id TEXT NOT NULL,discovery_key TEXT NOT NULL,chain_id TEXT NOT NULL,contract_address TEXT NOT NULL,token_symbol TEXT,pair_address TEXT NOT NULL,locked_at TEXT NOT NULL,reference_price_usd REAL NOT NULL,reference_source TEXT NOT NULL,reference_observed_at TEXT NOT NULL,direction TEXT NOT NULL,targets_json TEXT NOT NULL,probabilities_json TEXT NOT NULL,confidence_percent REAL,invalidation_price_usd REAL,risks_json TEXT NOT NULL DEFAULT '[]',reasoning TEXT,council_summary_json TEXT NOT NULL DEFAULT '{}',methodology_version TEXT NOT NULL,UNIQUE(cycle_id,discovery_key))`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_predictions_cycle ON ci_conan_predictions(cycle_id,locked_at)")
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_predictions_asset ON ci_conan_predictions(discovery_key,locked_at DESC)")
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_prediction_opinions (opinion_id TEXT PRIMARY KEY,cycle_id TEXT NOT NULL,prediction_id TEXT NOT NULL,discovery_key TEXT NOT NULL,role TEXT NOT NULL,provider TEXT,status TEXT NOT NULL,opinion_json TEXT NOT NULL DEFAULT '{}',error_message TEXT,created_at TEXT NOT NULL)`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_prediction_opinions_prediction ON ci_conan_prediction_opinions(prediction_id,created_at)")
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_prediction_opinions_provider ON ci_conan_prediction_opinions(provider,created_at)")
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_prediction_progress (prediction_id TEXT PRIMARY KEY,latest_price_usd REAL,latest_observed_at TEXT,targets_progress_json TEXT NOT NULL DEFAULT '[]',last_updated_at TEXT NOT NULL)`)
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_prediction_results (result_id TEXT PRIMARY KEY,prediction_id TEXT NOT NULL UNIQUE,cycle_id TEXT NOT NULL,discovery_key TEXT NOT NULL,outcome_status TEXT NOT NULL,direction_correct INTEGER,reference_price_usd REAL,final_price_usd REAL,direction_change_percent REAL,targets_touched_json TEXT NOT NULL DEFAULT '[]',targets_held_1h_json TEXT NOT NULL DEFAULT '[]',learning_notes_json TEXT NOT NULL DEFAULT '{}',evaluated_at TEXT NOT NULL)`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_results_cycle ON ci_conan_prediction_results(cycle_id,evaluated_at)")
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_results_asset ON ci_conan_prediction_results(discovery_key,evaluated_at DESC)")
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_learning_history (learning_id TEXT PRIMARY KEY,cycle_id TEXT NOT NULL,learning_type TEXT NOT NULL,summary TEXT NOT NULL,evidence_json TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL)`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_learning_cycle ON ci_conan_learning_history(cycle_id,created_at DESC)")
    ,db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_score_history (score_id TEXT PRIMARY KEY,cycle_id TEXT NOT NULL UNIQUE,score_total REAL,direction_score REAL,targets_technical_score REAL,probability_calibration_score REAL,project_quality_score REAL,market_activity_score REAL,risk_management_score REAL,evaluated_predictions INTEGER NOT NULL DEFAULT 0,unverifiable_predictions INTEGER NOT NULL DEFAULT 0,methodology_version TEXT NOT NULL,components_json TEXT NOT NULL DEFAULT "{}",created_at TEXT NOT NULL)`)
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_score_history_created ON ci_conan_score_history(created_at DESC)")
    ,db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_score_history_score ON ci_conan_score_history(score_total DESC,created_at DESC)")




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

function validateRadarLifecycleEvidenceSubstance(evidence) {
  const priceOnlyTerms = /^(price|price increase|price rise|pump|dump|variation|price change|price change 24h|percentage change|roi)$/i;
  const priceKey = /(price|pump|dump|variation|percent|percentage|roi)/i;
  const inspect = (value, key = "") => {
    if (priceKey.test(key)) return false;
    if (value === null || value === undefined) return false;
    if (typeof value === "string") {
      const normalized = value.trim();
      return normalized.length > 0 && !priceOnlyTerms.test(normalized);
    }
    if (typeof value === "number") return Number.isFinite(value);
    if (typeof value === "boolean") return true;
    if (Array.isArray(value)) return value.some(item => inspect(item, key));
    if (typeof value === "object") {
      return Object.entries(value).some(([childKey, childValue]) => inspect(childValue, childKey));
    }
    return false;
  };
  const observationKeys = ["observation", "observations", "finding", "findings", "checks", "metrics", "identity", "contract", "liquidity", "security", "onchain", "holders", "volume", "market_data"];
  const observation = Object.entries(evidence || {}).find(([key]) => observationKeys.includes(key.toLowerCase()));
  if (!observation || !inspect(observation[1], observation[0])) {
    return "Les preuves doivent contenir un constat concret autre qu'une simple hausse ou variation de prix.";
  }
  return null;
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
  const substanceError = validateRadarLifecycleEvidenceSubstance(evidence);
  if (substanceError) return { error: substanceError };
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
    return json({ success: true, stages: RADAR_LIFECYCLE_STAGES, counts: counts.results || [], count: result.results?.length || 0, assets: result.results || [], synchronization });
  }

  if (method === "GET" && path === "/api/radar/lifecycle-detail") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    if (!discoveryKey) return errorResponse("Le paramètre discovery_key est obligatoire.");
    await syncRadarAssetLifecycle(db, 5000);
    await syncRadarAssetLifecycleMissing(db, 1000);
    const asset = await db.prepare(
      "SELECT discovery_key, chain_id, contract_address, token_name, token_symbol, first_seen_at, status, review_reason FROM ci_radar_discoveries WHERE discovery_key = ?"
    ).bind(discoveryKey).first();
    if (!asset) return errorResponse("Actif radar introuvable.", 404);
    const lifecycle = await db.prepare(
      "SELECT * FROM ci_radar_asset_lifecycle WHERE discovery_key = ?"
    ).bind(discoveryKey).first();
    const history = await db.prepare(
      "SELECT * FROM ci_radar_asset_lifecycle_history WHERE discovery_key = ? ORDER BY transitioned_at ASC, event_id ASC LIMIT 1000"
    ).bind(discoveryKey).all();
    const events = history.results || [];
    const lastEvent = events.length ? events[events.length - 1] : null;
    const historyConsistent = !!lifecycle && !!lastEvent && lastEvent.to_stage === lifecycle.current_stage;
    return json({
      success: true,
      asset,
      lifecycle: lifecycle || null,
      history: events,
      history_count: events.length,
      history_consistency: {
        structurally_consistent: historyConsistent,
        current_stage: lifecycle?.current_stage || null,
        last_recorded_stage: lastEvent?.to_stage || null,
        note: historyConsistent
          ? "La dernière étape de l'historique correspond à l'étape courante."
          : "Historique absent ou désaccord avec l'étape courante; contrôle approfondi requis."
      }
    });
  }

  if (method === "GET" && path === "/api/radar/lifecycle-duration") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    if (!discoveryKey) return errorResponse("Le paramètre discovery_key est obligatoire.");
    const lifecycle = await db.prepare(
      "SELECT * FROM ci_radar_asset_lifecycle WHERE discovery_key = ?"
    ).bind(discoveryKey).first();
    if (!lifecycle) return errorResponse("Cycle de vie introuvable pour cet actif.", 404);
    const historyResult = await db.prepare(
      "SELECT from_stage, to_stage, transitioned_at, reason FROM ci_radar_asset_lifecycle_history WHERE discovery_key = ? ORDER BY transitioned_at ASC, event_id ASC LIMIT 1000"
    ).bind(discoveryKey).all();
    const history = historyResult.results || [];
    const timeline = [];
    let activeStage = null;
    let enteredAt = null;
    let chronologyValid = true;
    for (const event of history) {
      const eventTime = Date.parse(event.transitioned_at || "");
      if (!Number.isFinite(eventTime)) { chronologyValid = false; continue; }
      if (activeStage === null) {
        activeStage = event.from_stage;
        enteredAt = eventTime;
      }
      if (eventTime < enteredAt) chronologyValid = false;
      timeline.push({
        stage: activeStage,
        entered_at: new Date(enteredAt).toISOString(),
        exited_at: new Date(eventTime).toISOString(),
        duration_seconds: Math.max(0, Math.floor((eventTime - enteredAt) / 1000)),
        transition_reason: event.reason || null
      });
      activeStage = event.to_stage;
      enteredAt = eventTime;
    }
    const now = Date.now();
    const currentEntry = Date.parse(lifecycle.entered_stage_at || "");
    const currentEnteredAt = Number.isFinite(currentEntry) ? currentEntry : enteredAt;
    if (activeStage !== null && currentEnteredAt !== null && Number.isFinite(currentEnteredAt)) {
      if (now < currentEnteredAt) chronologyValid = false;
      timeline.push({
        stage: lifecycle.current_stage,
        entered_at: new Date(currentEnteredAt).toISOString(),
        exited_at: null,
        duration_seconds: Math.max(0, Math.floor((now - currentEnteredAt) / 1000)),
        is_current: true
      });
    }
    return json({
      success: true,
      discovery_key: discoveryKey,
      current_stage: lifecycle.current_stage,
      timeline,
      chronology_valid: chronologyValid,
      note: "Durées calculées à partir des horodatages enregistrés; elles ne constituent pas une preuve de qualité de l'actif."
    });
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


  /* ---------------- CHAPITRE 3 — CERCLE DES INVESTISSEMENTS ---------------- */

  if (method === "POST" && path === "/api/radar/investment/evaluate") {
    const body = await readBody(request);
    const discoveryKey = safeString(body.discovery_key || "", 200);
    if (!discoveryKey) return errorResponse("discovery_key requis.");
    const asset = await db.prepare("SELECT discovery_key FROM ci_radar_discoveries WHERE discovery_key = ?").bind(discoveryKey).first();
    if (!asset) return errorResponse("Actif radar introuvable.", 404);
    const lifecycle = await db.prepare("SELECT current_stage FROM ci_radar_asset_lifecycle WHERE discovery_key = ?").bind(discoveryKey).first();
    if (!lifecycle) return errorResponse("Cycle de vie de l'actif indisponible.", 409);
    const evaluation = calculateRadarInvestmentEvaluation({ ...body, lifecycle_stage: lifecycle.current_stage });
    const saved = await persistRadarInvestmentEvaluation(db, discoveryKey, evaluation, body.evaluator || "api");
    await audit(db, "investment_evaluation_created", discoveryKey + " — score " + saved.overall_score + "/100 — " + saved.evaluation_status);
    return json({ success: true, evaluation: saved }, 201);
  }

  if (method === "GET" && path === "/api/radar/investment/evaluations") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    const result = discoveryKey
      ? await db.prepare("SELECT * FROM ci_investment_evaluations WHERE discovery_key = ? ORDER BY evaluated_at DESC LIMIT ?").bind(discoveryKey, limit).all()
      : await db.prepare("SELECT * FROM ci_investment_evaluations ORDER BY evaluated_at DESC LIMIT ?").bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, evaluations: result.results || [], methodology: { version: RADAR_INVESTMENT_METHODOLOGY_VERSION, criteria: RADAR_INVESTMENT_CRITERIA } });
  }

  if (method === "GET" && path === "/api/radar/investment-circle") {
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    const members = await getRadarInvestmentCircle(db, limit);
    return json({ success: true, count: members.length, members, methodology: { version: RADAR_INVESTMENT_METHODOLOGY_VERSION, criteria: RADAR_INVESTMENT_CRITERIA, entry_thresholds: { score: 70, coverage_percent: 80, confidence_percent: 60 }, critical_risk_blocks_entry: true } });
  }

  if (method === "POST" && path === "/api/radar/investment/decision") {
    const body = await readBody(request);
    const result = await recordRadarInvestmentDecision(db, body);
    if (result.error) return errorResponse(result.error, 409);
    return json({ success: true, decision: result }, 201);
  }

  if (method === "GET" && path === "/api/radar/investment/decisions") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const limit = Math.max(1, Math.min(1000, Number(url.searchParams.get("limit")) || 200));
    const result = discoveryKey
      ? await db.prepare("SELECT * FROM ci_investment_decisions WHERE discovery_key = ? ORDER BY decided_at DESC LIMIT ?").bind(discoveryKey, limit).all()
      : await db.prepare("SELECT * FROM ci_investment_decisions ORDER BY decided_at DESC LIMIT ?").bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, decisions: result.results || [] });
  }


  /* ---------------- CHAPITRE 4 — LABORATOIRE D'INVESTIGATION -------------- */


  if (method === "GET" && path === "/api/radar/investigation/prepare") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    if (!discoveryKey) return errorResponse("discovery_key requis.");
    const dossier = await prepareRadarInvestigationDossier(db, discoveryKey);
    if (!dossier) return errorResponse("Actif radar introuvable.", 404);
    return json({ success: true, dossier });
  }

  if (method === "POST" && path === "/api/radar/investigation/report") {
    const body = await readBody(request);
    const discoveryKey = safeString(body.discovery_key || "", 200);
    if (!discoveryKey) return errorResponse("discovery_key requis.");
    const asset = await db.prepare("SELECT discovery_key FROM ci_radar_discoveries WHERE discovery_key = ?").bind(discoveryKey).first();
    if (!asset) return errorResponse("Actif radar introuvable.", 404);
    const lifecycle = await db.prepare("SELECT current_stage FROM ci_radar_asset_lifecycle WHERE discovery_key = ?").bind(discoveryKey).first();
    if (!lifecycle || !["precursors", "investigation_lab", "potential_investment_circle"].includes(lifecycle.current_stage)) {
      return errorResponse("Le dossier d'investigation est réservé aux actifs ayant atteint les précurseurs ou une étape ultérieure.", 409);
    }
    const report = buildRadarInvestigationReport(body.sections || {}, body.risks || []);
    const saved = await persistRadarInvestigationReport(db, discoveryKey, report, body.analyst || "api");
    await audit(db, "investigation_report_created", discoveryKey + " — version " + saved.report_version + " — couverture " + saved.coverage_percent + "%");
    return json({ success: true, report: saved }, 201);
  }

  if (method === "GET" && path === "/api/radar/investigation/report") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    if (!discoveryKey) return errorResponse("discovery_key requis.");
    const report = await getLatestRadarInvestigationReport(db, discoveryKey);
    if (!report) return json({ success: true, report: null, message: "Aucun dossier d'investigation enregistré." });
    return json({ success: true, report, methodology: RADAR_INVESTIGATION_SECTIONS });
  }

  if (method === "GET" && path === "/api/radar/investigation/history") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    if (!discoveryKey) return errorResponse("discovery_key requis.");
    const limit = Math.max(1, Math.min(200, Number(url.searchParams.get("limit")) || 50));
    const result = await db.prepare("SELECT report_id, discovery_key, report_version, report_status, coverage_percent, confidence_percent, missing_data_json, sources_json, created_at, updated_at, analyst FROM ci_investigation_reports WHERE discovery_key = ? ORDER BY report_version DESC LIMIT ?").bind(discoveryKey, limit).all();
    return json({ success: true, count: result.results?.length || 0, history: result.results || [] });
  }

  if (method === "GET" && path === "/api/radar/investigation/evidence") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    if (!discoveryKey) return errorResponse("discovery_key requis.");
    const reportId = safeString(url.searchParams.get("report_id") || "", 120);
    const limit = Math.max(1, Math.min(1000, Number(url.searchParams.get("limit")) || 300));
    const result = reportId
      ? await db.prepare("SELECT * FROM ci_investigation_evidence WHERE discovery_key = ? AND report_id = ? ORDER BY recorded_at DESC LIMIT ?").bind(discoveryKey, reportId, limit).all()
      : await db.prepare("SELECT * FROM ci_investigation_evidence WHERE discovery_key = ? ORDER BY recorded_at DESC LIMIT ?").bind(discoveryKey, limit).all();
    return json({ success: true, count: result.results?.length || 0, evidence: result.results || [] });
  }


  /* ---------------- CHAPITRE 5 — CONSEIL DES CINQ IA ----------------------- */


  /* ---------------- CHAPITRE 6 — INTELLIGENCE COLLECTIVE ------------------ */


  /* ---------------- CHAPITRE 7 — BALEINES ET PORTEFEUILLES --------------- */

  if (method === "POST" && path === "/api/wallets/scan") {
    const body = await readBody(request);
    const result = await runRadarWalletScan(db, {
      discovery_key: safeString(body.discovery_key || "", 200),
      chain_id: safeString(body.chain_id || "", 80),
      pair_limit: body.pair_limit
    });
    return json({ success: true, scan: result }, result.status === "partial" ? 207 : 201);
  }

  if (method === "POST" && path === "/api/wallets/watchlist") {
    const body = await readBody(request);
    const result = await upsertRadarWalletWatchlist(db, body);
    if (result.error) return errorResponse(result.error, 400);
    return json({ success: true, wallet: result }, 201);
  }

  if (method === "GET" && path === "/api/wallets/watchlist") {
    const chain = safeString(url.searchParams.get("chain_id") || "", 80);
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    const result = chain
      ? await db.prepare("SELECT * FROM ci_wallet_watchlist WHERE chain_id = ? ORDER BY updated_at DESC LIMIT ?").bind(chain, limit).all()
      : await db.prepare("SELECT * FROM ci_wallet_watchlist ORDER BY updated_at DESC LIMIT ?").bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, wallets: result.results || [] });
  }

  if (method === "GET" && path === "/api/wallets/events") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const wallet = safeString(url.searchParams.get("wallet_address") || "", 100).toLowerCase();
    const limit = Math.max(1, Math.min(1000, Number(url.searchParams.get("limit")) || 100));
    if (!discoveryKey && !wallet) return errorResponse("discovery_key ou wallet_address requis.");
    const result = discoveryKey
      ? await db.prepare("SELECT * FROM ci_wallet_events WHERE discovery_key = ? ORDER BY observed_at DESC LIMIT ?").bind(discoveryKey, limit).all()
      : await db.prepare("SELECT * FROM ci_wallet_events WHERE wallet_address = ? ORDER BY observed_at DESC LIMIT ?").bind(wallet, limit).all();
    return json({ success: true, count: result.results?.length || 0, events: result.results || [] });
  }

  if (method === "GET" && path === "/api/wallets/signals") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const wallet = safeString(url.searchParams.get("wallet_address") || "", 100).toLowerCase();
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    if (!discoveryKey && !wallet) return errorResponse("discovery_key ou wallet_address requis.");
    const result = discoveryKey
      ? await db.prepare("SELECT * FROM ci_wallet_behavior_signals WHERE discovery_key = ? ORDER BY created_at DESC LIMIT ?").bind(discoveryKey, limit).all()
      : await db.prepare("SELECT * FROM ci_wallet_behavior_signals WHERE wallet_address = ? ORDER BY created_at DESC LIMIT ?").bind(wallet, limit).all();
    return json({ success: true, count: result.results?.length || 0, signals: result.results || [] });
  }

  if (method === "GET" && path === "/api/wallets/clusters") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const limit = Math.max(1, Math.min(300, Number(url.searchParams.get("limit")) || 100));
    const result = discoveryKey
      ? await db.prepare("SELECT * FROM ci_wallet_clusters WHERE discovery_key = ? ORDER BY last_observed_at DESC LIMIT ?").bind(discoveryKey, limit).all()
      : await db.prepare("SELECT * FROM ci_wallet_clusters ORDER BY last_observed_at DESC LIMIT ?").bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, clusters: result.results || [] });
  }


  /* ---------------- CHAPITRE 8 — CYCLE DE PRÉDICTION CONAN 15 JOURS ---------------- */
  if (method === "POST" && path === "/api/conan/prediction-cycle/run") {
    const result = await runConanPredictionCycle(db, env);
    return json({ success: true, cycle: result }, result.status === "error" ? 500 : 200);
  }
  if (method === "GET" && path === "/api/conan/prediction-cycles") {
    const limit=Math.max(1,Math.min(100,Number(url.searchParams.get("limit"))||30));
    const result=await db.prepare("SELECT * FROM ci_conan_prediction_cycles ORDER BY cycle_start_date DESC LIMIT ?").bind(limit).all();
    return json({success:true,count:result.results?.length||0,cycles:result.results||[]});
  }
  if (method === "GET" && path === "/api/conan/predictions") {
    const cycleId=safeString(url.searchParams.get("cycle_id")||"",120),discoveryKey=safeString(url.searchParams.get("discovery_key")||"",200),limit=Math.max(1,Math.min(200,Number(url.searchParams.get("limit"))||50));
    if(!cycleId&&!discoveryKey)return errorResponse("cycle_id ou discovery_key requis.");
    const result=cycleId?await db.prepare("SELECT * FROM ci_conan_predictions WHERE cycle_id=? ORDER BY locked_at ASC LIMIT ?").bind(cycleId,limit).all():await db.prepare("SELECT * FROM ci_conan_predictions WHERE discovery_key=? ORDER BY locked_at DESC LIMIT ?").bind(discoveryKey,limit).all();
    return json({success:true,count:result.results?.length||0,predictions:result.results||[]});
  }
  if (method === "GET" && path === "/api/conan/prediction-observations") {
    const cycleId=safeString(url.searchParams.get("cycle_id")||"",120),discoveryKey=safeString(url.searchParams.get("discovery_key")||"",200),limit=Math.max(1,Math.min(2000,Number(url.searchParams.get("limit"))||500));
    if(!cycleId&&!discoveryKey)return errorResponse("cycle_id ou discovery_key requis.");
    const result=cycleId?await db.prepare("SELECT * FROM ci_conan_prediction_observations WHERE cycle_id=? ORDER BY observed_at ASC LIMIT ?").bind(cycleId,limit).all():await db.prepare("SELECT * FROM ci_conan_prediction_observations WHERE discovery_key=? ORDER BY observed_at DESC LIMIT ?").bind(discoveryKey,limit).all();
    return json({success:true,count:result.results?.length||0,observations:result.results||[]});
  }
  if (method === "GET" && path === "/api/conan/prediction-opinions") {
    const id=safeString(url.searchParams.get("prediction_id")||"",120);if(!id)return errorResponse("prediction_id requis.");
    const result=await db.prepare("SELECT * FROM ci_conan_prediction_opinions WHERE prediction_id=? ORDER BY created_at ASC").bind(id).all();
    return json({success:true,count:result.results?.length||0,opinions:result.results||[]});
  }
  if (method === "GET" && path === "/api/conan/prediction-results") {
    const cycleId=safeString(url.searchParams.get("cycle_id")||"",120),discoveryKey=safeString(url.searchParams.get("discovery_key")||"",200),limit=Math.max(1,Math.min(500,Number(url.searchParams.get("limit"))||100));
    if(!cycleId&&!discoveryKey)return errorResponse("cycle_id ou discovery_key requis.");
    const result=cycleId?await db.prepare("SELECT * FROM ci_conan_prediction_results WHERE cycle_id=? ORDER BY evaluated_at ASC LIMIT ?").bind(cycleId,limit).all():await db.prepare("SELECT * FROM ci_conan_prediction_results WHERE discovery_key=? ORDER BY evaluated_at DESC LIMIT ?").bind(discoveryKey,limit).all();
    return json({success:true,count:result.results?.length||0,results:result.results||[]});
  }


  if (method === "GET" && path === "/api/conan/growth") {
    await ensureConanPredictionTables(db);
    const state=await db.prepare("SELECT * FROM ci_conan_growth_state WHERE state_id='primary'").first();
    const history=await db.prepare("SELECT * FROM ci_conan_growth_history ORDER BY created_at DESC LIMIT 50").all();
    return json({success:true,methodology:CONAN_GROWTH_METHODOLOGY,state,transitions:history.results||[],thresholds:{child_to_adolescent:"Au moins 7 directions correctes parmi les 10 premières prédictions évaluées et vérifiables.",adolescent_to_adult:"Au moins 70 directions correctes parmi les 100 premières prédictions évaluées et vérifiables."},unverifiable_policy:"Les prédictions non vérifiables sont exclues des deux seuils."});
  }
  if (method === "GET" && path === "/api/conan/surveillance-windows") {
    await ensureConanPredictionTables(db);
    const result=await db.prepare("SELECT * FROM ci_conan_surveillance_windows ORDER BY window_number ASC").all();
    return json({success:true,count:result.results?.length||0,windows:result.results||[],note:"La fenêtre débloquée à l'adolescence est créée vide; elle n'est pas présentée comme surveillée avant attribution d'un actif."});
  }
  if (method === "POST" && path === "/api/conan/surveillance-windows/assign") {
    await ensureConanPredictionTables(db);
    const body=await readBody(request);
    const windowId=safeString(body.window_id||"",120),discoveryKey=safeString(body.discovery_key||"",200);
    if(!windowId||!discoveryKey)return errorResponse("window_id et discovery_key sont requis.");
    const windowRow=await db.prepare("SELECT * FROM ci_conan_surveillance_windows WHERE window_id=?").bind(windowId).first();
    if(!windowRow)return errorResponse("Fenêtre de surveillance inconnue.",404);
    if(windowRow.status!=="unassigned")return errorResponse("Cette fenêtre est déjà attribuée; aucune substitution automatique n'est autorisée.",409);
    const asset=await db.prepare("SELECT discovery_key,chain_id,contract_address,token_symbol FROM ci_radar_discoveries WHERE discovery_key=?").bind(discoveryKey).first();
    if(!asset)return errorResponse("Actif absent de l'univers crypto.",404);
    const market=await getConanLatestMarket(db,discoveryKey);
    if(!market)return errorResponse("Aucun prix source récent exploitable pour cet actif.",409);
    const timestamp=nowISO();
    await db.prepare("UPDATE ci_conan_surveillance_windows SET status='assigned',discovery_key=?,chain_id=?,contract_address=?,token_symbol=?,assigned_at=?,assignment_evidence_json=? WHERE window_id=? AND status='unassigned'").bind(
      asset.discovery_key,asset.chain_id,asset.contract_address,asset.token_symbol,timestamp,JSON.stringify({price_usd:market.price_usd,source:market.source,observed_at:market.observed_at}),windowId
    ).run();
    await audit(db,"conan_extra_surveillance_window_assigned","Fenêtre "+windowId+" attribuée à "+discoveryKey+".");
    return json({success:true,window_id:windowId,status:"assigned",asset:{discovery_key:asset.discovery_key,chain_id:asset.chain_id,contract_address:asset.contract_address,token_symbol:asset.token_symbol},reference:{price_usd:market.price_usd,source:market.source,observed_at:market.observed_at}});
  }
  if (method === "GET" && path === "/api/conan/scores") {
    const cycleId=safeString(url.searchParams.get("cycle_id")||"",120),limit=Math.max(1,Math.min(500,Number(url.searchParams.get("limit"))||100));
    const result=cycleId?await db.prepare("SELECT * FROM ci_conan_score_history WHERE cycle_id=? ORDER BY created_at DESC").bind(cycleId).all():await db.prepare("SELECT * FROM ci_conan_score_history ORDER BY created_at DESC LIMIT ?").bind(limit).all();
    return json({success:true,count:result.results?.length||0,scores:result.results||[]});
  }
  if (method === "GET" && path === "/api/conan/score") {
    const cycleId=safeString(url.searchParams.get("cycle_id")||"",120);
    if(cycleId){
      const result=await db.prepare("SELECT * FROM ci_conan_score_history WHERE cycle_id=? LIMIT 1").bind(cycleId).first();
      if(!result)return errorResponse("Aucun score calculé pour ce cycle.",404);
      return json({success:true,score:result});
    }
    const overall=await db.prepare("SELECT COUNT(*) AS cycles_count,SUM(evaluated_predictions) AS evaluated_predictions,SUM(unverifiable_predictions) AS unverifiable_predictions,SUM(evaluated_predictions*score_total)/NULLIF(SUM(evaluated_predictions),0) AS score_total,SUM(evaluated_predictions*direction_score)/NULLIF(SUM(evaluated_predictions),0) AS direction_score,SUM(evaluated_predictions*targets_technical_score)/NULLIF(SUM(evaluated_predictions),0) AS targets_technical_score,SUM(evaluated_predictions*probability_calibration_score)/NULLIF(SUM(evaluated_predictions),0) AS probability_calibration_score,SUM(evaluated_predictions*project_quality_score)/NULLIF(SUM(evaluated_predictions),0) AS project_quality_score,SUM(evaluated_predictions*market_activity_score)/NULLIF(SUM(evaluated_predictions),0) AS market_activity_score,SUM(evaluated_predictions*risk_management_score)/NULLIF(SUM(evaluated_predictions),0) AS risk_management_score FROM ci_conan_score_history WHERE score_total IS NOT NULL AND evaluated_predictions>0").first();
    return json({success:true,scope:"all_evaluated_cycles_weighted_by_verified_prediction_count",score:overall?.score_total??null,cycles_count:Number(overall?.cycles_count||0),evaluated_predictions:Number(overall?.evaluated_predictions||0),unverifiable_predictions:Number(overall?.unverifiable_predictions||0),components:overall?{prediction_quality:Number(overall.direction_score||0)+Number(overall.targets_technical_score||0)+Number(overall.probability_calibration_score||0),direction:overall.direction_score,targets_technical:overall.targets_technical_score,probability_calibration:overall.probability_calibration_score,project_quality:overall.project_quality_score,market_activity:overall.market_activity_score,risk_management:overall.risk_management_score}:null,methodology_version:CONAN_SCORE_METHODOLOGY,weights:CONAN_SCORE_WEIGHTS});
  }
  if (method === "GET" && path === "/api/conan/learning-history") {
    const cycleId=safeString(url.searchParams.get("cycle_id")||"",120),limit=Math.max(1,Math.min(500,Number(url.searchParams.get("limit"))||100));
    const result=cycleId?await db.prepare("SELECT * FROM ci_conan_learning_history WHERE cycle_id=? ORDER BY created_at DESC LIMIT ?").bind(cycleId,limit).all():await db.prepare("SELECT * FROM ci_conan_learning_history ORDER BY created_at DESC LIMIT ?").bind(limit).all();
    return json({success:true,count:result.results?.length||0,learning:result.results||[]});
  }

  if (method === "POST" && path === "/api/collective-intelligence/scan") {
    const body = await readBody(request);
    const result = await runCollectiveOpportunityScan(db, body.limit);
    return json({ success: true, scan: result }, 201);
  }

  if (method === "POST" && path === "/api/collective-intelligence/council-compare") {
    const body = await readBody(request);
    const discoveryKey = safeString(body.discovery_key || "", 200);
    if (!discoveryKey) return errorResponse("discovery_key requis.");
    const comparison = await recordCollectiveCouncilComparison(db, discoveryKey);
    if (comparison.error) return errorResponse(comparison.error, comparison.status || 404);
    return json({ success: true, comparison }, 201);
  }

  if (method === "GET" && path === "/api/collective-intelligence/opportunities") {
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    const stage = safeString(url.searchParams.get("stage") || "", 80);
    const result = stage
      ? await db.prepare("SELECT * FROM ci_collective_opportunity_history WHERE classification = ? ORDER BY created_at DESC LIMIT ?").bind(stage, limit).all()
      : await db.prepare("SELECT * FROM ci_collective_opportunity_history ORDER BY created_at DESC LIMIT ?").bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, opportunities: result.results || [] });
  }

  if (method === "GET" && path === "/api/collective-intelligence/signals") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const runId = safeString(url.searchParams.get("run_id") || "", 120);
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    if (!discoveryKey && !runId) return errorResponse("discovery_key ou run_id requis.");
    const result = discoveryKey
      ? await db.prepare("SELECT * FROM ci_collective_opportunity_signals WHERE discovery_key = ? ORDER BY created_at DESC LIMIT ?").bind(discoveryKey, limit).all()
      : await db.prepare("SELECT * FROM ci_collective_opportunity_signals WHERE run_id = ? ORDER BY created_at DESC LIMIT ?").bind(runId, limit).all();
    return json({ success: true, count: result.results?.length || 0, signals: result.results || [] });
  }

  if (method === "GET" && path === "/api/collective-intelligence/runs") {
    const limit = Math.max(1, Math.min(200, Number(url.searchParams.get("limit")) || 50));
    const result = await db.prepare("SELECT * FROM ci_collective_opportunity_runs ORDER BY created_at DESC LIMIT ?").bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, runs: result.results || [] });
  }

  if (method === "POST" && path === "/api/ai/council/analyze") {
    const body = await readBody(request);
    const discoveryKey = safeString(body.discovery_key || "", 200);
    if (!discoveryKey) return errorResponse("discovery_key requis.");
    const result = await runRadarAICouncil(env, db, discoveryKey);
    if (result.error) return errorResponse(result.error, result.status || 409);
    return json({ success: true, council: result }, 201);
  }

  if (method === "GET" && path === "/api/ai/council/sessions") {
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const limit = Math.max(1, Math.min(200, Number(url.searchParams.get("limit")) || 50));
    const result = discoveryKey
      ? await db.prepare("SELECT * FROM ci_ai_council_sessions WHERE discovery_key = ? ORDER BY created_at DESC LIMIT ?").bind(discoveryKey, limit).all()
      : await db.prepare("SELECT * FROM ci_ai_council_sessions ORDER BY created_at DESC LIMIT ?").bind(limit).all();
    return json({ success: true, count: result.results?.length || 0, sessions: result.results || [] });
  }

  if (method === "GET" && path === "/api/ai/council/opinions") {
    const sessionId = safeString(url.searchParams.get("session_id") || "", 120);
    const discoveryKey = safeString(url.searchParams.get("discovery_key") || "", 200);
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 100));
    if (!sessionId && !discoveryKey) return errorResponse("session_id ou discovery_key requis.");
    const result = sessionId
      ? await db.prepare("SELECT * FROM ci_ai_council_opinions WHERE session_id = ? ORDER BY created_at ASC LIMIT ?").bind(sessionId, limit).all()
      : await db.prepare("SELECT * FROM ci_ai_council_opinions WHERE discovery_key = ? ORDER BY created_at DESC LIMIT ?").bind(discoveryKey, limit).all();
    return json({ success: true, count: result.results?.length || 0, opinions: result.results || [] });
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


/* -------------------------------------------------------------------------- */
/* CHAPITRE 3 — CERCLE DES INVESTISSEMENTS POTENTIELS                         */
/* -------------------------------------------------------------------------- */

const RADAR_INVESTMENT_METHODOLOGY_VERSION = "1.0.0";
const RADAR_INVESTMENT_CRITERIA = [
  { key: "security", label: "Sécurité du contrat et des transactions", weight: 25 },
  { key: "liquidity", label: "Liquidité, profondeur et facilité de sortie", weight: 20 },
  { key: "market_activity", label: "Activité de marché et qualité des échanges", weight: 15 },
  { key: "fundamentals", label: "Projet, utilité, développement et adoption", weight: 20 },
  { key: "tokenomics", label: "Tokenomics, distribution et dilution", weight: 10 },
  { key: "transparency", label: "Transparence, identité et qualité des sources", weight: 10 }
];

function normalizeRadarInvestmentEvidence(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const sources = Array.isArray(value.sources) ? value.sources : (value.source ? [value.source] : []);
  const observations = Array.isArray(value.observations) ? value.observations : (value.observation ? [value.observation] : []);
  const cleanSources = sources.map(item => safeString(item, 500)).filter(Boolean);
  const cleanObservations = observations.map(item => safeString(item, 1500)).filter(Boolean);
  if (!cleanSources.length || !cleanObservations.length) return null;
  return {
    sources: [...new Set(cleanSources)],
    observations: cleanObservations,
    observed_at: safeString(value.observed_at || "", 80) || null,
    source_quality: safeString(value.source_quality || "unrated", 40),
    notes: safeString(value.notes || "", 1000) || null
  };
}

function calculateRadarInvestmentEvaluation(body) {
  const supplied = body.criteria && typeof body.criteria === "object" && !Array.isArray(body.criteria) ? body.criteria : {};
  const riskFlags = Array.isArray(body.risk_flags) ? body.risk_flags.map(item => safeString(item, 300)).filter(Boolean).slice(0, 50) : [];
  const criticalRiskFlags = new Set(["is_honeypot", "honeypot_confirmed", "cannot_sell", "cannot_sell_all", "confirmed_scam", "confirmed_rug_pull", "malicious_contract"]);
  const criticalRiskFromFlags = riskFlags.some(flag => criticalRiskFlags.has(flag.toLowerCase().replace(/[\\s-]+/g, "_")));
  const criticalRisk = body.critical_risk === true || safeString(body.risk_level || "", 40).toLowerCase() === "critical" || criticalRiskFromFlags;
  const criteria = {};
  const evidence = {};
  const missing = [];
  let weightedScore = 0;
  let coveredWeight = 0;
  let confidenceWeighted = 0;

  for (const definition of RADAR_INVESTMENT_CRITERIA) {
    const item = supplied[definition.key];
    const score = item && item.score !== undefined ? Number(item.score) : NaN;
    const confidence = item && item.confidence !== undefined ? Number(item.confidence) : NaN;
    const normalizedEvidence = normalizeRadarInvestmentEvidence(item?.evidence);
    if (!Number.isFinite(score) || score < 0 || score > 100 || !Number.isFinite(confidence) || confidence < 0 || confidence > 100 || !normalizedEvidence) {
      missing.push({ criterion: definition.key, label: definition.label, weight: definition.weight, reason: "Note (0–100), confiance (0–100), source et observation vérifiables requis." });
      criteria[definition.key] = { label: definition.label, weight: definition.weight, score: null, confidence: null, status: "missing" };
      continue;
    }
    criteria[definition.key] = { label: definition.label, weight: definition.weight, score, confidence, status: "assessed" };
    evidence[definition.key] = normalizedEvidence;
    weightedScore += score * definition.weight / 100;
    confidenceWeighted += confidence * definition.weight;
    coveredWeight += definition.weight;
  }

  const overallScore = Math.round(weightedScore * 100) / 100;
  const coverage = coveredWeight;
  const confidence = coveredWeight ? Math.round((confidenceWeighted / coveredWeight) * (coverage / 100) * 100) / 100 : 0;
  const lifecycleStage = safeString(body.lifecycle_stage || "", 80);
  let status = "insufficient_data";
  if (criticalRisk) status = "blocked_critical_risk";
  else if (overallScore < 50 && coverage >= 50) status = "not_recommended";
  else if (overallScore >= 70 && coverage >= 80 && confidence >= 60 &&
    criteria.security.status === "assessed" && criteria.liquidity.status === "assessed" &&
    (lifecycleStage === "investigation_lab" || lifecycleStage === "potential_investment_circle")) status = "eligible";
  else if (coverage >= 50) status = "watchlist_review";
  return {
    overall_score: overallScore,
    coverage_percent: coverage,
    confidence_percent: confidence,
    evaluation_status: status,
    critical_risk: criticalRisk,
    criteria,
    evidence,
    missing_data: missing,
    risk_flags: riskFlags,
    methodology_version: RADAR_INVESTMENT_METHODOLOGY_VERSION,
    thresholds: {
      eligible_score_minimum: 70,
      eligible_coverage_minimum_percent: 80,
      eligible_confidence_minimum_percent: 60,
      mandatory_criteria: ["security", "liquidity"],
      critical_risk_blocks_entry: true,
      auto_blocked_risk_flags: [...criticalRiskFlags]
    },
    interpretation: "Le score est la somme des contributions pondérées sur 100; un critère absent contribue zéro. La couverture indique le poids des critères réellement documentés. La confiance est pondérée puis réduite par la couverture. Une donnée manquante n'est jamais assimilée à une preuve positive."
  };
}

async function persistRadarInvestmentEvaluation(db, discoveryKey, evaluation, evaluator = "api") {
  const evaluationId = cryptoRandomId();
  const evaluatedAt = nowISO();
  await db.prepare(`INSERT INTO ci_investment_evaluations
    (evaluation_id, discovery_key, overall_score, coverage_percent, confidence_percent,
     evaluation_status, critical_risk, criteria_json, evidence_json, missing_data_json,
     risk_flags_json, methodology_version, evaluated_at, evaluator)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      evaluationId, discoveryKey, evaluation.overall_score, evaluation.coverage_percent,
      evaluation.confidence_percent, evaluation.evaluation_status, evaluation.critical_risk ? 1 : 0,
      JSON.stringify(evaluation.criteria), JSON.stringify(evaluation.evidence),
      JSON.stringify(evaluation.missing_data), JSON.stringify(evaluation.risk_flags),
      evaluation.methodology_version, evaluatedAt, safeString(evaluator, 80) || "api"
    ).run();
  return { evaluation_id: evaluationId, evaluated_at: evaluatedAt, ...evaluation };
}

async function getLatestRadarInvestmentEvaluation(db, discoveryKey) {
  return db.prepare("SELECT * FROM ci_investment_evaluations WHERE discovery_key = ? ORDER BY evaluated_at DESC LIMIT 1")
    .bind(discoveryKey).first();
}

async function recordRadarInvestmentDecision(db, body) {
  const discoveryKey = safeString(body.discovery_key || "", 200);
  const decision = safeString(body.decision || "", 30).toLowerCase();
  const reason = safeString(body.reason || "", 2000);
  if (!discoveryKey || !["enter", "retain", "exit"].includes(decision) || !reason) {
    return { error: "discovery_key, decision (enter/retain/exit) et reason documentée sont requis." };
  }
  const asset = await db.prepare("SELECT discovery_key FROM ci_radar_discoveries WHERE discovery_key = ?").bind(discoveryKey).first();
  if (!asset) return { error: "Actif radar introuvable." };
  const lifecycle = await db.prepare("SELECT current_stage FROM ci_radar_asset_lifecycle WHERE discovery_key = ?").bind(discoveryKey).first();
  if (!lifecycle) return { error: "Cycle de vie de l'actif indisponible; initialisez d'abord son cycle." };
  const latest = await getLatestRadarInvestmentEvaluation(db, discoveryKey);
  if (!latest) return { error: "Une évaluation documentée est obligatoire avant toute décision." };
  if (decision !== "exit" && (latest.evaluation_status !== "eligible" || Number(latest.critical_risk) === 1)) {
    return { error: "Entrée ou maintien refusé : dernière évaluation non éligible ou risque critique." };
  }
  if (decision === "enter" && lifecycle.current_stage !== "investigation_lab") {
    return { error: "L'entrée dans le cercle exige que l'actif soit actuellement au laboratoire d'investigation." };
  }
  if (decision === "retain" && lifecycle.current_stage !== "potential_investment_circle") {
    return { error: "Le maintien exige que l'actif soit déjà dans le cercle d'investissement." };
  }
  if (decision === "exit" && lifecycle.current_stage !== "potential_investment_circle") {
    return { error: "La sortie exige que l'actif soit actuellement dans le cercle d'investissement." };
  }

  const fromStage = lifecycle.current_stage;
  const toStage = decision === "enter" ? "potential_investment_circle" :
    decision === "exit" ? "investigation_lab" : fromStage;
  const evidence = {
    source: "ci_investment_evaluations",
    observation: {
      evaluation_id: latest.evaluation_id,
      overall_score: latest.overall_score,
      coverage_percent: latest.coverage_percent,
      confidence_percent: latest.confidence_percent,
      evaluation_status: latest.evaluation_status,
      methodology_version: latest.methodology_version
    },
    decision_evidence: {
      criteria: JSON.parse(latest.criteria_json || "{}"),
      evidence: JSON.parse(latest.evidence_json || "{}"),
      missing_data: JSON.parse(latest.missing_data_json || "[]"),
      risk_flags: JSON.parse(latest.risk_flags_json || "[]")
    }
  };
  if (decision !== "retain") {
    const transition = await transitionRadarAssetLifecycle(db, {
      discovery_key: discoveryKey,
      to_stage: toStage,
      reason,
      evidence,
      actor: safeString(body.actor || "investment_circle", 80)
    });
    if (transition.error) return { error: transition.error };
  }

  const decisionId = cryptoRandomId();
  const decidedAt = nowISO();
  await db.prepare(`INSERT INTO ci_investment_decisions
    (decision_id, discovery_key, evaluation_id, decision, from_stage, to_stage, reason, evidence_json, decided_at, actor)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      decisionId, discoveryKey, latest.evaluation_id, decision, fromStage, toStage,
      reason, JSON.stringify(evidence), decidedAt, safeString(body.actor || "api", 80) || "api"
    ).run();
  await audit(db, "investment_circle_" + decision, discoveryKey + " — " + reason);
  return { decision_id: decisionId, discovery_key: discoveryKey, evaluation_id: latest.evaluation_id, decision, from_stage: fromStage, to_stage: toStage, reason, decided_at: decidedAt, evidence };
}

async function getRadarInvestmentCircle(db, limit = 100) {
  const result = await db.prepare(`SELECT d.discovery_key, d.chain_id, d.contract_address,
    d.token_name, d.token_symbol, d.first_seen_at, d.last_seen_at,
    l.current_stage, l.entered_stage_at, e.evaluation_id, e.overall_score,
    e.coverage_percent, e.confidence_percent, e.evaluation_status,
    e.critical_risk, e.evaluated_at
    FROM ci_radar_asset_lifecycle l
    JOIN ci_radar_discoveries d ON d.discovery_key = l.discovery_key
    LEFT JOIN ci_investment_evaluations e ON e.evaluation_id = (
      SELECT e2.evaluation_id FROM ci_investment_evaluations e2
      WHERE e2.discovery_key = d.discovery_key ORDER BY e2.evaluated_at DESC LIMIT 1
    )
    WHERE l.current_stage = 'potential_investment_circle'
    ORDER BY e.overall_score DESC, l.entered_stage_at DESC LIMIT ?`).bind(Math.max(1, Math.min(500, Number(limit) || 100))).all();
  return result.results || [];
}


/* -------------------------------------------------------------------------- */
/* CHAPITRE 4 — LABORATOIRE D'INVESTIGATION                                   */
/* -------------------------------------------------------------------------- */

const RADAR_INVESTIGATION_SECTIONS = [
  { key: "origin_history", label: "Origine et historique", fields: ["launch_date", "origin_story", "chain", "contract", "migration_history"] },
  { key: "team", label: "Équipe et contributeurs", fields: ["founders", "team_members", "public_profiles", "track_record"] },
  { key: "technology_utility", label: "Technologie et utilité", fields: ["technology", "use_case", "utility", "roadmap", "technical_documentation"] },
  { key: "tokenomics", label: "Tokenomics et distribution", fields: ["total_supply", "max_supply", "circulating_supply", "distribution", "vesting", "unlock_schedule", "emissions"] },
  { key: "valuation", label: "Valorisation", fields: ["market_cap", "fully_diluted_valuation", "valuation_method", "valuation_timestamp"] },
  { key: "liquidity_market", label: "Liquidité et marché", fields: ["liquidity_usd", "pool_depth", "volume_24h", "spread", "sellability", "slippage"] },
  { key: "reputation_community", label: "Réputation et communauté", fields: ["community_channels", "community_quality", "reputation_signals", "sentiment_context"] },
  { key: "partnerships", label: "Partenariats", fields: ["partners", "announcements", "verification_status"] },
  { key: "development_adoption", label: "Développement et adoption", fields: ["repository_activity", "release_activity", "developers", "users", "transactions", "integrations", "adoption_metrics"] },
  { key: "risks", label: "Risques", fields: ["security_risks", "centralization_risks", "regulatory_risks", "market_risks", "operational_risks", "conflicts_of_interest"] }
];

function normalizeRadarInvestigationSection(sectionKey, value) {
  const definition = RADAR_INVESTIGATION_SECTIONS.find(section => section.key === sectionKey);
  if (!definition || !value || typeof value !== "object" || Array.isArray(value)) return null;
  const normalized = {};
  const missing = [];
  const sources = new Set();
  let confidenceTotal = 0;
  let confidenceCount = 0;
  for (const field of definition.fields) {
    const item = value[field];
    if (item === undefined || item === null || item === "") {
      missing.push(field);
      normalized[field] = { status: "unknown", value: null, source: null, confidence_percent: null };
      continue;
    }
    const record = item && typeof item === "object" && !Array.isArray(item) && Object.prototype.hasOwnProperty.call(item, "value")
      ? item : { value: item };
    const source = safeString(record.source || "", 500);
    const confidence = Number(record.confidence_percent);
    const status = ["verified", "observed", "estimated", "unverified", "disputed"].includes(record.status)
      ? record.status : (source ? "observed" : "unverified");
    if (source) sources.add(source);
    const validConfidence = Number.isFinite(confidence) && confidence >= 0 && confidence <= 100 ? confidence : null;
    if (validConfidence !== null) { confidenceTotal += validConfidence; confidenceCount++; }
    normalized[field] = {
      status,
      value: record.value,
      source: source || null,
      observed_at: safeString(record.observed_at || "", 80) || null,
      confidence_percent: validConfidence,
      notes: safeString(record.notes || "", 1000) || null
    };
  }
  return {
    section_key: sectionKey,
    label: definition.label,
    fields: normalized,
    missing_fields: missing,
    coverage_percent: Math.round(((definition.fields.length - missing.length) / definition.fields.length) * 100),
    confidence_percent: confidenceCount ? Math.round(confidenceTotal / confidenceCount) : null,
    sources: [...sources]
  };
}

function buildRadarInvestigationReport(sectionsInput, riskInput) {
  const sections = {};
  const missing = [];
  const allSources = new Set();
  let totalFields = 0;
  let suppliedFields = 0;
  let confidenceTotal = 0;
  let confidenceCount = 0;
  for (const definition of RADAR_INVESTIGATION_SECTIONS) {
    const section = normalizeRadarInvestigationSection(definition.key, sectionsInput?.[definition.key]);
    if (!section) {
      missing.push({ section: definition.key, fields: definition.fields, reason: "Section absente ou invalide." });
      totalFields += definition.fields.length;
      continue;
    }
    sections[definition.key] = section;
    totalFields += definition.fields.length;
    suppliedFields += definition.fields.length - section.missing_fields.length;
    for (const source of section.sources) allSources.add(source);
    if (section.confidence_percent !== null) { confidenceTotal += section.confidence_percent; confidenceCount++; }
    if (section.missing_fields.length) missing.push({ section: definition.key, fields: section.missing_fields, reason: "Données non fournies; elles restent inconnues." });
  }
  const risks = Array.isArray(riskInput) ? riskInput.slice(0, 100).map(item => ({
    risk: safeString(item?.risk || item?.description || "", 1000),
    severity: ["critical", "high", "medium", "low", "unknown"].includes(safeString(item?.severity || "unknown", 20).toLowerCase()) ? safeString(item?.severity || "unknown", 20).toLowerCase() : "unknown",
    status: ["confirmed", "suspected", "mitigated", "unverified"].includes(safeString(item?.status || "unverified", 20).toLowerCase()) ? safeString(item?.status || "unverified", 20).toLowerCase() : "unverified",
    source: safeString(item?.source || "", 500) || null,
    notes: safeString(item?.notes || "", 1000) || null
  })).filter(item => item.risk) : [];
  const coverage = totalFields ? Math.round(suppliedFields / totalFields * 100) : 0;
  return {
    sections,
    missing_data: missing,
    risk_register: risks,
    sources: [...allSources],
    coverage_percent: coverage,
    confidence_percent: confidenceCount ? Math.round(confidenceTotal / confidenceCount) : 0,
    report_status: coverage === 100 ? "complete" : suppliedFields > 0 ? "incomplete" : "empty",
    methodology: "Chaque champ est conservé avec son statut, sa source et sa confiance. Une absence est affichée comme inconnue, jamais comme zéro ou comme fait. Les estimations et éléments non vérifiés restent explicitement distingués."
  };
}

async function persistRadarInvestigationReport(db, discoveryKey, report, analyst = "api") {
  const previous = await db.prepare("SELECT MAX(report_version) AS version FROM ci_investigation_reports WHERE discovery_key = ?").bind(discoveryKey).first();
  const version = Number(previous?.version || 0) + 1;
  const reportId = cryptoRandomId();
  const timestamp = nowISO();
  await db.prepare(`INSERT INTO ci_investigation_reports
    (report_id, discovery_key, report_version, report_status, coverage_percent, confidence_percent,
     sections_json, missing_data_json, risk_register_json, sources_json, created_at, updated_at, analyst)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      reportId, discoveryKey, version, report.report_status, report.coverage_percent,
      report.confidence_percent, JSON.stringify(report.sections), JSON.stringify(report.missing_data),
      JSON.stringify(report.risk_register), JSON.stringify(report.sources), timestamp, timestamp,
      safeString(analyst, 80) || "api"
    ).run();
  const evidenceStatements = [];
  for (const [sectionKey, section] of Object.entries(report.sections)) {
    for (const [fieldKey, field] of Object.entries(section.fields || {})) {
      if (field.value === null || field.value === undefined) continue;
      evidenceStatements.push(db.prepare(`INSERT INTO ci_investigation_evidence
        (evidence_id, report_id, discovery_key, section_key, field_key, value_json, source, observed_at, confidence_percent, evidence_status, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
          cryptoRandomId(), reportId, discoveryKey, sectionKey, fieldKey, JSON.stringify(field.value),
          field.source || "source_not_provided", field.observed_at, field.confidence_percent,
          field.status, timestamp
        ));
    }
  }
  for (let offset = 0; offset < evidenceStatements.length; offset += 50) {
    await db.batch(evidenceStatements.slice(offset, offset + 50));
  }
  return { report_id: reportId, report_version: version, created_at: timestamp, ...report };
}

async function getLatestRadarInvestigationReport(db, discoveryKey) {
  return db.prepare("SELECT * FROM ci_investigation_reports WHERE discovery_key = ? ORDER BY report_version DESC LIMIT 1")
    .bind(discoveryKey).first();
}


async function prepareRadarInvestigationDossier(db, discoveryKey) {
  const discovery = await db.prepare("SELECT * FROM ci_radar_discoveries WHERE discovery_key = ?").bind(discoveryKey).first();
  if (!discovery) return null;
  const [identity, market, liquidity, lp, contract, lifecycle] = await Promise.all([
    db.prepare("SELECT * FROM ci_radar_identity_checks WHERE discovery_key = ? ORDER BY checked_at DESC LIMIT 1").bind(discoveryKey).first(),
    db.prepare("SELECT * FROM ci_radar_market_checks WHERE discovery_key = ? ORDER BY checked_at DESC LIMIT 1").bind(discoveryKey).first(),
    db.prepare("SELECT * FROM ci_radar_onchain_liquidity_assessments WHERE discovery_key = ? ORDER BY checked_at DESC LIMIT 1").bind(discoveryKey).first(),
    db.prepare("SELECT * FROM ci_radar_lp_history WHERE discovery_key = ? ORDER BY checked_at DESC LIMIT 1").bind(discoveryKey).first(),
    db.prepare("SELECT * FROM ci_radar_contract_checks WHERE discovery_key = ? ORDER BY checked_at DESC LIMIT 1").bind(discoveryKey).first(),
    db.prepare("SELECT * FROM ci_radar_asset_lifecycle WHERE discovery_key = ?").bind(discoveryKey).first()
  ]);
  const parse = value => { try { return JSON.parse(value || "{}"); } catch { return {}; } };
  const known = {
    origin_history: { chain: discovery.chain_id, contract: discovery.contract_address, launch_date: discovery.pair_created_at, first_seen_at: discovery.first_seen_at, discovery_sources: parse(discovery.sources_json) },
    identity: identity ? { provider: identity.provider, outcome: identity.outcome, checked_at: identity.checked_at, metadata: parse(identity.metadata_json) } : null,
    market: market ? { provider: market.provider, outcome: market.outcome, liquidity_usd: market.liquidity_usd, volume_24h_usd: market.volume_24h_usd, pair_count: market.pair_count, checked_at: market.checked_at } : null,
    onchain_liquidity: liquidity ? { outcome: liquidity.outcome, estimated_pool_depth_usd: liquidity.estimated_pool_depth_usd, buy_impact: parse(liquidity.estimated_buy_impact_json), sell_impact: parse(liquidity.estimated_sell_impact_json), checked_at: liquidity.checked_at, caveat: "Estimation non exécutable; frais, taxes, MEV et routage peuvent modifier le résultat." } : null,
    lp_distribution: lp ? { assessment_status: lp.assessment_status, top10_locked_share_percent: lp.top10_locked_share_percent, top10_unlocked_share_percent: lp.top10_unlocked_share_percent, largest_lp_holder_percent: lp.largest_lp_holder_percent, unlock_events: parse(lp.unlock_events_json), checked_at: lp.checked_at } : null,
    contract: contract ? { provider: contract.provider, outcome: contract.outcome, contract_code_present: contract.contract_code_present, evidence: parse(contract.evidence_json), checked_at: contract.checked_at } : null
  };
  const unavailable = ["team_verification", "technology_and_utility", "tokenomics_and_vesting", "circulating_supply_and_dilution", "market_cap_and_fdv", "community_reputation", "partnership_verification", "development_activity", "adoption_metrics", "complete_security_audit"];
  return {
    discovery: { discovery_key: discovery.discovery_key, chain_id: discovery.chain_id, contract_address: discovery.contract_address, token_name: discovery.token_name, token_symbol: discovery.token_symbol, first_seen_at: discovery.first_seen_at, pair_created_at: discovery.pair_created_at, sources: parse(discovery.sources_json) },
    lifecycle: lifecycle || null,
    available_evidence: known,
    missing_investigation_areas: unavailable,
    note: "Pré-dossier assemblé à partir des dernières observations déjà enregistrées. Les domaines absents restent inconnus et nécessitent des sources vérifiables; aucune équipe, adoption, association ou donnée financière n'est inventée."
  };
}


/* -------------------------------------------------------------------------- */
/* CHAPITRE 5 — CONSEIL IA : ORCHESTRATION, PREUVES ET ARBITRAGE              */
/* -------------------------------------------------------------------------- */

const RADAR_AI_COUNCIL_ROLES = [
  { id: "fundamentals", name: "IA Fondamentale", instruction: "Évalue origine, équipe uniquement si vérifiable, technologie, utilité, tokenomics, distribution, dilution et crédibilité du projet." },
  { id: "financial", name: "IA Financière", instruction: "Évalue prix, volumes, valorisation, liquidité réelle, profondeur, volatilité, concentration, flux et risques financiers. Distingue données observées et interprétations." },
  { id: "security", name: "IA Sécurité", instruction: "Examine contrat, honeypot, possibilité de vente, taxes, privilèges administrateur, liquidité, concentration, LP et manipulation. Ne déclare jamais un contrat sûr sans preuves." },
  { id: "growth", name: "IA Croissance", instruction: "Évalue adoption, activité de développement, utilisateurs, transactions, intégrations, communauté, actualités et partenariats vérifiables." },
  { id: "arbiter", name: "IA Arbitre", instruction: "Compare les quatre avis indépendants, leurs preuves, leurs désaccords et leurs données manquantes. Ne fait pas une moyenne mécanique et n'efface jamais un signal critique." }
];

const RADAR_AI_COUNCIL_PROMPT_VERSION = "council-v1";

async function initializeAICouncilTables(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_ai_council_sessions (
      session_id TEXT PRIMARY KEY,
      discovery_key TEXT NOT NULL,
      status TEXT NOT NULL,
      decision_gate TEXT NOT NULL,
      critical_risk_signal INTEGER NOT NULL DEFAULT 0,
      summary TEXT,
      disagreements_json TEXT NOT NULL DEFAULT '[]',
      evidence_json TEXT NOT NULL DEFAULT '{}',
      provider_errors_json TEXT NOT NULL DEFAULT '[]',
      created_at TEXT NOT NULL
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_ai_council_sessions_asset ON ci_ai_council_sessions(discovery_key, created_at DESC)"),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_ai_council_opinions (
      opinion_id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      discovery_key TEXT NOT NULL,
      role TEXT NOT NULL,
      provider TEXT,
      status TEXT NOT NULL,
      opinion_json TEXT NOT NULL DEFAULT '{}',
      prompt_version TEXT NOT NULL,
      error_message TEXT,
      created_at TEXT NOT NULL
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_ai_council_opinions_session ON ci_ai_council_opinions(session_id, created_at ASC)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_ai_council_opinions_provider ON ci_ai_council_opinions(provider, status, created_at)")
  ]);
}

function normalizeRadarAICouncilOpinion(raw, roleId) {
  const parsed = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const list = value => Array.isArray(value) ? value.slice(0, 40).map(item => {
    if (item && typeof item === "object") return {
      statement: safeString(item.statement || item.claim || item.description || "", 1200),
      source: safeString(item.source || "", 500) || null,
      evidence_status: ["verified", "observed", "estimated", "unverified", "disputed"].includes(item.evidence_status) ? item.evidence_status : "unverified",
      observed_at: safeString(item.observed_at || "", 80) || null
    };
    return { statement: safeString(item, 1200), source: null, evidence_status: "unverified", observed_at: null };
  }).filter(item => item.statement) : [];
  const confidence = Number(parsed.confidence);
  const stance = ["support", "neutral", "oppose", "insufficient_data"].includes(parsed.stance) ? parsed.stance : "insufficient_data";
  return {
    role: roleId,
    summary: safeString(parsed.summary || parsed.conclusion || "", 3000),
    stance,
    facts: list(parsed.facts),
    hypotheses: list(parsed.hypotheses),
    risks: list(parsed.risks),
    missing_data: Array.isArray(parsed.missing_data) ? parsed.missing_data.slice(0, 80).map(item => safeString(item, 500)).filter(Boolean) : [],
    confidence_percent: Number.isFinite(confidence) ? Math.max(0, Math.min(100, confidence)) : null,
    critical_risk_signal: parsed.critical_risk === true || list(parsed.risks).some(item => /critical|critique/i.test(item.statement)),
    conclusion: safeString(parsed.conclusion || "", 2000),
    raw_unstructured_response: parsed.unstructured_response ? safeString(parsed.unstructured_response, 12000) : null,
    parsing_warning: safeString(parsed.parsing_warning || "", 500) || null
  };
}

async function runRadarAICouncil(env, db, discoveryKey) {
  await initializeAICouncilTables(db);
  const discovery = await db.prepare("SELECT * FROM ci_radar_discoveries WHERE discovery_key = ?").bind(discoveryKey).first();
  if (!discovery) return { error: "Actif radar introuvable.", status: 404 };

  const providers = availableAIProviders(env);
  if (!providers.length) return { error: "Aucun fournisseur IA configuré. Aucun avis simulé n'a été créé.", status: 503 };

  const dossier = await prepareRadarInvestigationDossier(db, discoveryKey);
  const latestReport = await getLatestRadarInvestigationReport(db, discoveryKey);
  const evidence = {
    asset: { discovery_key: discovery.discovery_key, chain_id: discovery.chain_id, contract_address: discovery.contract_address, name: discovery.token_name, symbol: discovery.token_symbol },
    dossier,
    latest_investigation_report: latestReport ? {
      report_id: latestReport.report_id,
      report_version: latestReport.report_version,
      coverage_percent: latestReport.coverage_percent,
      confidence_percent: latestReport.confidence_percent,
      sections: (() => { try { return JSON.parse(latestReport.sections_json || "{}"); } catch { return {}; } })(),
      missing_data: (() => { try { return JSON.parse(latestReport.missing_data_json || "[]"); } catch { return []; } })(),
      risk_register: (() => { try { return JSON.parse(latestReport.risk_register_json || "[]"); } catch { return []; } })()
    } : null,
    collected_at: nowISO(),
    data_policy: "Aucune donnée absente ne doit être inventée. Les sources citées par un modèle ne sont pas considérées vérifiées sans preuve indépendante."
  };

  const limitValue = Number(env.AI_COUNCIL_DAILY_PROVIDER_CALL_LIMIT);
  const dailyLimit = Number.isFinite(limitValue) ? Math.max(1, Math.min(50, Math.floor(limitValue))) : 5;
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const usageResult = await db.prepare("SELECT provider, COUNT(*) AS calls FROM ci_ai_council_opinions WHERE status IN ('completed', 'failed') AND created_at >= ? GROUP BY provider").bind(since).all();
  const usage = new Map((usageResult.results || []).map(row => [row.provider, Number(row.calls) || 0]));
  const available = () => providers.filter(provider => (usage.get(provider) || 0) < dailyLimit);
  const chooseProvider = () => {
    const candidates = available().sort((a, b) => (usage.get(a) || 0) - (usage.get(b) || 0));
    return candidates[0] || null;
  };

  const sessionId = cryptoRandomId();
  const opinions = [];
  const providerErrors = [];
  const expertRoles = RADAR_AI_COUNCIL_ROLES.filter(role => role.id !== "arbiter");

  const executeRole = async (role, context) => {
    const provider = chooseProvider();
    if (!provider) {
      const message = "Plafond journalier local du conseil atteint pour les fournisseurs disponibles; appel non effectué.";
      providerErrors.push({ role: role.id, provider: null, error: message });
      await db.prepare(`INSERT INTO ci_ai_council_opinions
        (opinion_id, session_id, discovery_key, role, provider, status, opinion_json, prompt_version, error_message, created_at)
        VALUES (?, ?, ?, ?, NULL, 'skipped_quota', '{}', ?, ?, ?)`).bind(
          cryptoRandomId(), sessionId, discoveryKey, role.id, RADAR_AI_COUNCIL_PROMPT_VERSION, message, nowISO()
        ).run();
      return null;
    }
    const prompt = [
      "CRYPTO INTELLIGENCE — CONSEIL IA INDÉPENDANT",
      "RÔLE : " + role.name + " (" + role.id + ")",
      "MISSION : " + role.instruction,
      "RÈGLES OBLIGATOIRES :",
      "- Sépare les faits observés, les hypothèses, les risques et les inconnues.",
      "- Pour chaque fait, indique une source et un statut de preuve; si absent, indique inconnu.",
      "- Ne fabrique aucun prix, volume, partenariat, identité, audit ou résultat.",
      "- Une source simplement citée par un modèle n'est pas une preuve vérifiée.",
      "- Un risque critique signalé doit être conservé et ne peut pas être annulé par des avis positifs.",
      "- Ne promets aucun rendement et ne donne aucune garantie de sécurité.",
      "CONTEXTE FOURNI :",
      JSON.stringify(context),
      "Réponds en JSON : { role, summary, stance: support|neutral|oppose|insufficient_data, facts:[], hypotheses:[], risks:[], missing_data:[], confidence:0-100, critical_risk:false, conclusion }."
    ].join("\n");

    try {
      const raw = await callAIProvider(provider, env, prompt);
      const normalized = normalizeRadarAICouncilOpinion(parseAIResponse(raw), role.id);
      const createdAt = nowISO();
      await db.prepare(`INSERT INTO ci_ai_council_opinions
        (opinion_id, session_id, discovery_key, role, provider, status, opinion_json, prompt_version, error_message, created_at)
        VALUES (?, ?, ?, ?, ?, 'completed', ?, ?, NULL, ?)`).bind(
          cryptoRandomId(), sessionId, discoveryKey, role.id, provider,
          JSON.stringify(normalized), RADAR_AI_COUNCIL_PROMPT_VERSION, createdAt
        ).run();
      usage.set(provider, (usage.get(provider) || 0) + 1);
      await recordProviderUsage(db, provider, true, 200);
      opinions.push({ ...normalized, provider, created_at: createdAt });
      return opinions[opinions.length - 1];
    } catch (error) {
      const message = safeString(error.message || "Erreur fournisseur IA.", 700);
      providerErrors.push({ role: role.id, provider, error: message });
      await db.prepare(`INSERT INTO ci_ai_council_opinions
        (opinion_id, session_id, discovery_key, role, provider, status, opinion_json, prompt_version, error_message, created_at)
        VALUES (?, ?, ?, ?, ?, 'failed', '{}', ?, ?, ?)`).bind(
          cryptoRandomId(), sessionId, discoveryKey, role.id, provider,
          RADAR_AI_COUNCIL_PROMPT_VERSION, message, nowISO()
        ).run();
      usage.set(provider, (usage.get(provider) || 0) + 1);
      await recordProviderUsage(db, provider, false, error.status || 500);
      return null;
    }
  };

  for (const role of expertRoles) await executeRole(role, evidence);

  const securityOpinion = opinions.find(item => item.role === "security");
  const criticalRiskSignal = opinions.some(item => item.critical_risk_signal === true);
  let arbiter = null;
  if (opinions.length) {
    const arbiterRole = RADAR_AI_COUNCIL_ROLES.find(role => role.id === "arbiter");
    arbiter = await executeRole(arbiterRole, {
      evidence,
      independent_opinions: opinions.map(item => ({ role: item.role, stance: item.stance, summary: item.summary, facts: item.facts, hypotheses: item.hypotheses, risks: item.risks, missing_data: item.missing_data, confidence_percent: item.confidence_percent })),
      mandatory_rule: "Ne supprime et ne compense jamais un signal de risque critique. Si un tel signal existe, la conclusion ne peut pas autoriser une entrée; indique une vérification humaine et indépendante requise."
    });
  }

  const stances = [...new Set(opinions.filter(item => item.role !== "arbiter").map(item => item.stance).filter(value => value !== "insufficient_data"))];
  const disagreements = stances.length > 1 ? [{
    type: "stance_divergence",
    stances,
    roles: opinions.filter(item => item.role !== "arbiter").map(item => ({ role: item.role, stance: item.stance })),
    note: "Divergence conservée; aucune moyenne ne l'efface."
  }] : [];
  const decisionGate = criticalRiskSignal ? "blocked_pending_independent_verification" :
    (opinions.length < 4 || !arbiter ? "incomplete_no_decision" : "advisory_only");
  const status = opinions.length === 5 ? "completed" : opinions.length ? "partial" : "failed";
  const summary = criticalRiskSignal
    ? "Signal de risque critique rapporté par au moins une IA : toute conclusion positive est bloquée en attente d'une vérification indépendante."
    : safeString(arbiter?.summary || arbiter?.conclusion || "Conseil incomplet; aucune conclusion consolidée fiable.", 2000);
  const session = {
    session_id: sessionId,
    discovery_key: discoveryKey,
    status,
    decision_gate: decisionGate,
    critical_risk_signal: criticalRiskSignal,
    summary,
    opinions,
    arbiter,
    disagreements,
    provider_errors: providerErrors,
    evidence,
    created_at: nowISO(),
    safeguards: {
      independent_expert_calls_before_arbiter: true,
      critical_risk_cannot_be_overridden: true,
      model_claims_are_not_independent_verification: true,
      daily_local_provider_call_limit: dailyLimit,
      no_automatic_investment_decision: true
    }
  };
  await db.prepare(`INSERT INTO ci_ai_council_sessions
    (session_id, discovery_key, status, decision_gate, critical_risk_signal, summary, disagreements_json, evidence_json, provider_errors_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      sessionId, discoveryKey, status, decisionGate, criticalRiskSignal ? 1 : 0, summary,
      JSON.stringify(disagreements), JSON.stringify(evidence), JSON.stringify(providerErrors), session.created_at
    ).run();
  await audit(db, "ai_council_session_" + status, discoveryKey + " — " + decisionGate);
  return session;
}



/* -------------------------------------------------------------------------- */
/* CHAPITRE 6 — INTELLIGENCE COLLECTIVE ET DÉTECTION D'OPPORTUNITÉS           */
/* -------------------------------------------------------------------------- */

const RADAR_COLLECTIVE_METHODOLOGY = {
  version: "collective-v1",
  weights: { liquidity_and_depth: 25, market_activity: 20, buy_sell_balance: 15, independent_evaluation: 20, evidence_coverage: 20 },
  safeguards: [
    "Un prix bas ou une hausse ne prouvent pas une sous-évaluation.",
    "Capitalisation, FDV et offre restent inconnues si aucune donnée sourcée n'existe.",
    "Liquidité déclarée et profondeur on-chain estimée sont deux mesures distinctes.",
    "Une possibilité de vente inconnue n'est jamais considérée comme confirmée.",
    "Un risque critique bloque toute qualification favorable.",
    "Une corrélation statistique ne prouve ni causalité ni coordination."
  ]
};

function collectiveParseJSON(value, fallback = {}) {
  try { return typeof value === "string" ? JSON.parse(value) : value ?? fallback; }
  catch { return fallback; }
}

function collectiveSectionValue(section, field) {
  const item = section && section[field];
  if (item === null || item === undefined) return null;
  if (typeof item === "object" && !Array.isArray(item)) return item.value ?? item.normalized_value ?? null;
  return item;
}

function collectivePearson(xs, ys) {
  if (xs.length < 5 || xs.length !== ys.length) return null;
  const mx = xs.reduce((a,b)=>a+b,0)/xs.length, my = ys.reduce((a,b)=>a+b,0)/ys.length;
  let n=0, dx=0, dy=0;
  for(let i=0;i<xs.length;i++){const x=xs[i]-mx,y=ys[i]-my;n+=x*y;dx+=x*x;dy+=y*y;}
  const d=Math.sqrt(dx*dy);
  return d>0?n/d:null;
}

async function runCollectiveOpportunityScan(db, requestedLimit = 100) {
  const limit=Math.max(1,Math.min(250,Number(requestedLimit)||100));
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_collective_opportunity_runs (run_id TEXT PRIMARY KEY,status TEXT NOT NULL,assets_examined INTEGER NOT NULL DEFAULT 0,signals_created INTEGER NOT NULL DEFAULT 0,candidates_count INTEGER NOT NULL DEFAULT 0,correlations_count INTEGER NOT NULL DEFAULT 0,methodology_json TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_collective_opportunity_signals (signal_id TEXT PRIMARY KEY,run_id TEXT NOT NULL,discovery_key TEXT NOT NULL,signal_type TEXT NOT NULL,severity TEXT NOT NULL,confidence_percent REAL,metrics_json TEXT NOT NULL DEFAULT '{}',evidence_json TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL)`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_collective_signals_asset ON ci_collective_opportunity_signals(discovery_key,created_at DESC)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_collective_signals_run ON ci_collective_opportunity_signals(run_id,created_at DESC)"),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_collective_opportunity_history (history_id TEXT PRIMARY KEY,run_id TEXT NOT NULL,discovery_key TEXT NOT NULL,classification TEXT NOT NULL,opportunity_score REAL NOT NULL DEFAULT 0,confidence_percent REAL NOT NULL DEFAULT 0,price_change_24h REAL,activity_ratio REAL,buy_pressure REAL,liquidity_usd REAL,pool_depth_usd REAL,market_cap_usd REAL,fdv_usd REAL,circulating_supply REAL,total_supply REAL,sellability_status TEXT NOT NULL DEFAULT 'unknown',critical_risk INTEGER NOT NULL DEFAULT 0,evidence_json TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL)`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_collective_history_asset ON ci_collective_opportunity_history(discovery_key,created_at DESC)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_collective_history_run ON ci_collective_opportunity_history(run_id,created_at DESC)")
  ]);

  const runId=cryptoRandomId(), createdAt=nowISO();
  const discovered=await db.prepare("SELECT discovery_key,chain_id,contract_address,token_name,token_symbol,status FROM ci_radar_discoveries ORDER BY last_seen_at DESC LIMIT ?").bind(limit).all();
  let signalsCreated=0,candidatesCount=0;
  const snapshotKeys=[];

  for(const asset of discovered.results||[]){
    const poolResult=await db.prepare("SELECT * FROM ci_radar_pool_metrics WHERE discovery_key = ? ORDER BY observed_at DESC LIMIT 20").bind(asset.discovery_key).all();
    const byPair=new Map();
    for(const row of poolResult.results||[]) if(!byPair.has(row.pair_address)) byPair.set(row.pair_address,row);
    const pairs=[...byPair.values()], metricRows=pairs.map(row=>collectiveParseJSON(row.evidence_json,{}));
    const sum=field=>pairs.length?pairs.reduce((n,row)=>n+(radarFiniteMetric(row[field])||0),0):null;
    const liquidity=sum("liquidity_usd"),volume=sum("volume_24h_usd"),buys=sum("buys_24h"),sells=sum("sells_24h");
    const activityRatio=liquidity>0&&volume!==null?volume/liquidity:null;
    const buyPressure=buys!==null&&sells!==null&&buys+sells>0?buys/(buys+sells):null;
    const changes=metricRows.map(x=>radarFiniteMetric(x.price_change_24h_percent)).filter(x=>x!==null);
    const priceChange=changes.length?changes.reduce((a,b)=>a+b,0)/changes.length:null;
    const caps=metricRows.map(x=>radarFiniteMetric(x.market_cap_usd)).filter(x=>x!==null);
    const fdvs=metricRows.map(x=>radarFiniteMetric(x.fdv_usd)).filter(x=>x!==null);
    const marketCap=caps.length?Math.max(...caps):null,fdv=fdvs.length?Math.max(...fdvs):null;

    const depth=await db.prepare("SELECT estimated_pool_depth_usd,checked_at FROM ci_radar_onchain_liquidity_assessments WHERE discovery_key = ? ORDER BY checked_at DESC LIMIT 1").bind(asset.discovery_key).first();
    const poolDepth=radarFiniteMetric(depth?.estimated_pool_depth_usd);
    const evaluation=await db.prepare("SELECT overall_score,coverage_percent,confidence_percent,evaluation_status,critical_risk,risk_flags_json,evaluated_at FROM ci_investment_evaluations WHERE discovery_key = ? ORDER BY evaluated_at DESC LIMIT 1").bind(asset.discovery_key).first();
    const report=await db.prepare("SELECT sections_json,coverage_percent,confidence_percent,report_version,updated_at FROM ci_investigation_reports WHERE discovery_key = ? ORDER BY report_version DESC,updated_at DESC LIMIT 1").bind(asset.discovery_key).first();
    const sections=collectiveParseJSON(report?.sections_json,{});
    const tokenomics=sections.tokenomics||{},liquiditySection=sections.liquidity_market||{};
    const circulating=radarFiniteMetric(collectiveSectionValue(tokenomics,"circulating_supply"));
    const totalSupply=radarFiniteMetric(collectiveSectionValue(tokenomics,"total_supply")??collectiveSectionValue(tokenomics,"max_supply"));
    const sellabilityRaw=collectiveSectionValue(liquiditySection,"sellability");
    const sellability=typeof sellabilityRaw==="boolean"?(sellabilityRaw?"reported_sellable_unverified":"reported_unsellable_unverified"):safeString(sellabilityRaw||"unknown",80);
    const riskFlags=collectiveParseJSON(evaluation?.risk_flags_json,[]);
    const critical=Number(evaluation?.critical_risk)===1||(Array.isArray(riskFlags)&&riskFlags.some(x=>/honeypot|cannot.?sell|rug.?pull|scam|malicious|critical/i.test(typeof x==="string"?x:JSON.stringify(x))));
    
    const liquidityScore=poolDepth!==null&&liquidity!==null?Math.min(25,Math.max(0,Math.log10(Math.max(1,poolDepth))*2.5+Math.log10(Math.max(1,liquidity))*1.5)):liquidity!==null?Math.min(12,Math.log10(Math.max(1,liquidity))*2):0;
    const activityScore=activityRatio!==null?Math.min(20,Math.max(0,activityRatio*4)):0;
    const balanceScore=buyPressure!==null?Math.min(15,Math.max(0,(1-Math.abs(buyPressure-.55)/.55)*15)):0;
    const evaluationScore=evaluation?Math.min(20,Math.max(0,Number(evaluation.overall_score||0)*.2)):0;
    const coverage=radarFiniteMetric(evaluation?.coverage_percent??report?.coverage_percent)||0;
    const evidenceScore=Math.min(20,Math.max(0,coverage*.2));
    const score=Math.round((liquidityScore+activityScore+balanceScore+evaluationScore+evidenceScore)*100)/100;
    const observed=[liquidity,volume,buys,sells,poolDepth,marketCap,fdv,circulating,totalSupply].filter(x=>x!==null).length;
    const confidence=Math.round(Math.min(100,observed/9*65+(evaluation?Number(evaluation.confidence_percent||0)*.35:0)));
    const classification=critical?"blocked_critical_risk":(score>=60&&evaluation?.evaluation_status==="eligible"&&poolDepth!==null&&sellability==="reported_sellable_unverified"?"watchlist_candidate_requires_verification":"research_needed");
    if(classification==="watchlist_candidate_requires_verification")candidatesCount++;
    const metrics={liquidity_usd_provider_reported:liquidity,pool_depth_usd_onchain_estimate:poolDepth,volume_24h_usd_provider_reported:volume,buys_24h:buys,sells_24h:sells,buy_pressure_ratio:buyPressure,volume_to_liquidity_ratio:activityRatio,price_change_24h_percent_context_only:priceChange,market_cap_usd:marketCap,fdv_usd:fdv,circulating_supply:circulating,total_or_max_supply:totalSupply,sellability_status:sellability,investment_evaluation:evaluation||null};
    const evidence={asset:{discovery_key:asset.discovery_key,chain_id:asset.chain_id,contract_address:asset.contract_address,name:asset.token_name,symbol:asset.token_symbol,stage:asset.status},sources:[...new Set(pairs.map(x=>x.source).filter(Boolean))],metrics,report_version:report?.report_version||null,report_updated_at:report?.updated_at||null,methodology:RADAR_COLLECTIVE_METHODOLOGY.version,limitations:["Liquidité déclarée par fournisseur; profondeur estimée séparément.","Vente non vérifiée par ce moteur.","Score de tri, pas valeur intrinsèque ni conseil d'achat."]};
    const addSignal=async(type,severity,conf,detail)=>{await db.prepare("INSERT INTO ci_collective_opportunity_signals (signal_id,run_id,discovery_key,signal_type,severity,confidence_percent,metrics_json,evidence_json,created_at) VALUES (?,?,?,?,?,?,?,?,?)").bind(cryptoRandomId(),runId,asset.discovery_key,type,severity,conf,JSON.stringify(metrics),JSON.stringify(detail),createdAt).run();signalsCreated++;};
    if(buys!==null&&sells!==null&&buys+sells>=10&&buyPressure>=.75)await addSignal("buy_pressure_anomaly","watch",Math.min(85,Math.round(50+(buyPressure-.75)*100)),{buys_24h:buys,sells_24h:sells,note:"Déséquilibre de transactions, pas preuve d'accumulation nette."});
    if(activityRatio!==null&&activityRatio>=3&&liquidity>0)await addSignal("volume_liquidity_dislocation","watch",60,{volume_to_liquidity_ratio:activityRatio,note:"Peut signaler activité réelle, liquidité faible ou wash trading; vérification requise."});
    if(priceChange!==null&&Math.abs(priceChange)>=25)await addSignal("large_price_move_context","context",55,{price_change_24h_percent:priceChange,note:"Contexte de marché uniquement; ne prouve pas une sous-évaluation."});
    if(critical)await addSignal("critical_risk_veto","critical",95,{risk_flags:riskFlags,note:"Risque critique: bloque toute qualification favorable."});
    await db.prepare(`INSERT INTO ci_collective_opportunity_history (history_id,run_id,discovery_key,classification,opportunity_score,confidence_percent,price_change_24h,activity_ratio,buy_pressure,liquidity_usd,pool_depth_usd,market_cap_usd,fdv_usd,circulating_supply,total_supply,sellability_status,critical_risk,evidence_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
      cryptoRandomId(),runId,asset.discovery_key,classification,score,confidence,priceChange,activityRatio,buyPressure,liquidity,poolDepth,marketCap,fdv,circulating,totalSupply,sellability,critical?1:0,JSON.stringify(evidence),createdAt
    ).run();
    snapshotKeys.push(asset.discovery_key);
  }

  // Corrélations de rendements: minimum cinq scans communs et seuil absolu 0,80.
  let correlations=0;
  const keys=snapshotKeys.slice(0,40);
  if(keys.length>=2){
    const marks=keys.map(()=>"?").join(",");
    const rows=await db.prepare("SELECT run_id,discovery_key,price_change_24h FROM ci_collective_opportunity_history WHERE discovery_key IN ("+marks+") AND price_change_24h IS NOT NULL ORDER BY created_at DESC LIMIT 2000").bind(...keys).all();
    const series=new Map();
    for(const row of rows.results||[]){if(!series.has(row.discovery_key))series.set(row.discovery_key,new Map());if(!series.get(row.discovery_key).has(row.run_id))series.get(row.discovery_key).set(row.run_id,Number(row.price_change_24h));}
    const ids=[...series.keys()];
    for(let i=0;i<ids.length;i++)for(let j=i+1;j<ids.length;j++){
      const left=series.get(ids[i]),right=series.get(ids[j]),common=[...left.keys()].filter(k=>right.has(k)).slice(0,20);
      if(common.length<5)continue;
      const coefficient=collectivePearson(common.map(k=>left.get(k)),common.map(k=>right.get(k)));
      if(coefficient===null||Math.abs(coefficient)<.8)continue;
      const detail={correlation_type:"pearson_price_change_24h",coefficient:Math.round(coefficient*1000)/1000,common_observations:common.length,discovery_keys:[ids[i],ids[j]],note:"Association historique descriptive, sans preuve de causalité ni de coordination."};
      await db.prepare("INSERT INTO ci_collective_opportunity_signals (signal_id,run_id,discovery_key,signal_type,severity,confidence_percent,metrics_json,evidence_json,created_at) VALUES (?,?,?,'cross_asset_price_correlation','research',?,'{}',?,?)").bind(cryptoRandomId(),runId,ids[i],Math.round(Math.abs(coefficient)*100),JSON.stringify(detail),createdAt).run();
      correlations++;signalsCreated++;
    }
  }
  await db.prepare("INSERT INTO ci_collective_opportunity_runs (run_id,status,assets_examined,signals_created,candidates_count,correlations_count,methodology_json,created_at) VALUES (?, 'completed', ?, ?, ?, ?, ?, ?)").bind(runId,snapshotKeys.length,signalsCreated,candidatesCount,correlations,JSON.stringify(RADAR_COLLECTIVE_METHODOLOGY),createdAt).run();
  await audit(db,"collective_opportunity_scan_completed",runId+" — "+snapshotKeys.length+" actifs examinés; "+signalsCreated+" signaux.");
  return {run_id:runId,status:"completed",assets_examined:snapshotKeys.length,signals_created:signalsCreated,watchlist_candidates:candidatesCount,historical_correlations:correlations,created_at:createdAt,methodology:RADAR_COLLECTIVE_METHODOLOGY,note:"Pistes de recherche documentées, jamais recommandations d'achat ni preuves de sous-évaluation."};
}



async function recordCollectiveCouncilComparison(db, discoveryKey) {
  const session = await db.prepare("SELECT * FROM ci_ai_council_sessions WHERE discovery_key = ? ORDER BY created_at DESC LIMIT 1").bind(discoveryKey).first();
  if (!session) return { error: "Aucune session du conseil IA disponible pour cet actif.", status: 404 };
  const rows = await db.prepare("SELECT role, provider, status, opinion_json, error_message, created_at FROM ci_ai_council_opinions WHERE session_id = ? ORDER BY created_at ASC").bind(session.session_id).all();
  const opinions = (rows.results || []).map(row => ({ ...row, parsed: collectiveParseJSON(row.opinion_json, {}) }));
  const experts = opinions.filter(item => item.role !== "arbiter" && item.status === "completed");
  const arbiter = opinions.find(item => item.role === "arbiter" && item.status === "completed") || null;
  const stances = [...new Set(experts.map(item => item.parsed.stance).filter(Boolean))];
  const riskStatements = experts.flatMap(item => Array.isArray(item.parsed.risks) ? item.parsed.risks.map(risk => ({ role: item.role, risk })) : []);
  const hypotheses = experts.flatMap(item => Array.isArray(item.parsed.hypotheses) ? item.parsed.hypotheses.map(hypothesis => ({ role: item.role, hypothesis })) : []);
  const facts = experts.flatMap(item => Array.isArray(item.parsed.facts) ? item.parsed.facts.map(fact => ({ role: item.role, fact })) : []);
  const critical = Number(session.critical_risk_signal) === 1 || experts.some(item => item.parsed.critical_risk_signal === true);
  const disagreement = stances.length > 1 || riskStatements.length > 0;
  const runId = cryptoRandomId(), createdAt = nowISO();
  const evidence = {
    session_id: session.session_id,
    completed_roles: experts.map(item => item.role),
    missing_or_failed_roles: opinions.filter(item => item.status !== "completed").map(item => ({ role: item.role, status: item.status, error: item.error_message || null })),
    stances_by_role: experts.map(item => ({ role: item.role, stance: item.parsed.stance || "unknown", confidence_percent: item.parsed.confidence_percent ?? item.parsed.confidence ?? null })),
    arbiter_opinion: arbiter?.parsed || null,
    risks_by_role: riskStatements,
    facts_by_role: facts,
    hypotheses_by_role: hypotheses,
    disagreements: stances.length > 1 ? { stances, note: "Les avis divergents sont conservés et ne sont pas moyennés." } : null,
    critical_risk_veto: critical,
    interpretation: "Les affirmations des IA sont des opinions de modèles et ne deviennent pas des faits vérifiés sans preuve externe."
  };
  await db.prepare("INSERT INTO ci_collective_opportunity_runs (run_id,status,assets_examined,signals_created,candidates_count,correlations_count,methodology_json,created_at) VALUES (?, 'council_comparison', 1, 1, 0, 0, ?, ?)").bind(runId, JSON.stringify({ version: "collective-council-compare-v1" }), createdAt).run();
  await db.prepare("INSERT INTO ci_collective_opportunity_signals (signal_id,run_id,discovery_key,signal_type,severity,confidence_percent,metrics_json,evidence_json,created_at) VALUES (?,?,?,?,?,?,?,?,?)").bind(
    cryptoRandomId(), runId, discoveryKey, critical ? "council_critical_risk_veto" : disagreement ? "council_divergence_and_hypotheses" : "council_cross_check",
    critical ? "critical" : disagreement ? "research" : "context",
    experts.length ? Math.round(experts.reduce((n,item)=>n+Number(item.parsed.confidence_percent ?? item.parsed.confidence ?? 0),0)/experts.length) : null,
    JSON.stringify({ expert_opinions: experts.length, distinct_stances: stances.length }),
    JSON.stringify(evidence), createdAt
  ).run();
  await audit(db, "collective_council_comparison", discoveryKey + " — " + (critical ? "risque critique" : "comparaison des avis"));
  return { run_id: runId, discovery_key: discoveryKey, session_id: session.session_id, experts_compared: experts.length, arbiter_available: !!arbiter, critical_risk_veto: critical, disagreement_detected: disagreement, risks: riskStatements, hypotheses, facts, evidence, created_at: createdAt };
}



/* -------------------------------------------------------------------------- */
/* CHAPITRE 7 — SURVEILLANCE DES BALEINES ET PETITS PORTEFEUILLES              */
/* -------------------------------------------------------------------------- */

const RADAR_WALLET_SWAP_TOPIC = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822";
const RADAR_WALLET_THRESHOLDS_USD = { small_trade_max: 500, whale_trade_min: 10000 };
const RADAR_WALLET_SCAN_MAX_BLOCK_RANGE = 2000;
const RADAR_WALLET_SCAN_DEFAULT_BLOCK_RANGE = 1000;

async function ensureRadarWalletTables(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_wallet_watchlist (wallet_key TEXT PRIMARY KEY,chain_id TEXT NOT NULL,wallet_address TEXT NOT NULL,label TEXT,wallet_type TEXT NOT NULL DEFAULT 'unknown',profile_status TEXT NOT NULL DEFAULT 'user_supplied_unverified',source_reference TEXT,notes TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(chain_id,wallet_address))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_wallet_scan_cursors (cursor_key TEXT PRIMARY KEY,chain_id TEXT NOT NULL,pair_address TEXT NOT NULL,last_scanned_block INTEGER NOT NULL DEFAULT 0,last_scan_at TEXT,status TEXT NOT NULL DEFAULT 'pending',error_message TEXT)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_wallet_events (event_id TEXT PRIMARY KEY,chain_id TEXT NOT NULL,discovery_key TEXT NOT NULL,pair_address TEXT NOT NULL,wallet_address TEXT NOT NULL,recipient_address TEXT,transaction_hash TEXT NOT NULL,log_index INTEGER NOT NULL,block_number INTEGER NOT NULL,observed_at TEXT NOT NULL,trade_side TEXT NOT NULL,target_token_amount REAL,estimated_usd_value REAL,value_source TEXT NOT NULL DEFAULT 'unknown',wallet_category TEXT NOT NULL DEFAULT 'unknown',watchlist_status TEXT NOT NULL DEFAULT 'unknown',evidence_json TEXT NOT NULL DEFAULT '{}',UNIQUE(chain_id,transaction_hash,log_index))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_wallet_behavior_signals (signal_id TEXT PRIMARY KEY,chain_id TEXT NOT NULL,discovery_key TEXT NOT NULL,wallet_address TEXT,signal_type TEXT NOT NULL,severity TEXT NOT NULL,confidence_percent REAL,window_start TEXT,window_end TEXT,evidence_json TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_wallet_clusters (cluster_id TEXT PRIMARY KEY,chain_id TEXT NOT NULL,discovery_key TEXT NOT NULL,cluster_type TEXT NOT NULL,verification_status TEXT NOT NULL DEFAULT 'unverified_candidate',member_wallets_json TEXT NOT NULL DEFAULT '[]',evidence_json TEXT NOT NULL DEFAULT '{}',first_observed_at TEXT NOT NULL,last_observed_at TEXT NOT NULL,created_at TEXT NOT NULL)`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_wallet_events_asset ON ci_wallet_events(discovery_key,observed_at DESC)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_wallet_events_wallet ON ci_wallet_events(chain_id,wallet_address,observed_at DESC)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_wallet_signals_asset ON ci_wallet_behavior_signals(discovery_key,created_at DESC)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_wallet_clusters_asset ON ci_wallet_clusters(discovery_key,last_observed_at DESC)")
  ]);
}

function radarWalletDecodeWord(data, index) {
  const value = safeString(data || "", 20000).replace(/^0x/i, "");
  const word = value.slice(index * 64, (index + 1) * 64);
  return word.length === 64 && /^[0-9a-fA-F]+$/.test(word) ? BigInt("0x" + word) : null;
}

function radarWalletTopicAddress(topic) {
  const value = safeString(topic || "", 100);
  return /^0x[0-9a-fA-F]{64}$/.test(value) ? "0x" + value.slice(-40).toLowerCase() : null;
}

async function radarWalletRpcRequest(rpcUrl, method, params) {
  const response = await externalJSON(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
  }, 12000);
  const payload = response.data || {};
  if (payload.error) {
    const error = new Error(safeString(payload.error.message || "Erreur RPC wallet.", 400));
    error.status = payload.error.code || response.status || 502;
    throw error;
  }
  return payload.result;
}

function radarWalletTradeCategory(usdValue) {
  if (usdValue === null || usdValue === undefined) return "unknown";
  if (usdValue >= RADAR_WALLET_THRESHOLDS_USD.whale_trade_min) return "large_trade_size";
  if (usdValue <= RADAR_WALLET_THRESHOLDS_USD.small_trade_max) return "small_trade_size";
  return "mid_size_trade";
}

async function upsertRadarWalletWatchlist(db, body = {}) {
  await ensureRadarWalletTables(db);
  const chain = safeString(body.chain_id || "", 80).toLowerCase();
  const address = safeString(body.wallet_address || "", 100).toLowerCase();
  if (!radarPublicRpc(chain)) return { error: "Réseau non pris en charge par la surveillance on-chain actuelle (Ethereum, BSC et Base)." };
  if (!/^0x[a-f0-9]{40}$/.test(address)) return { error: "Adresse EVM invalide." };
  const walletType = ["whale","small","known","unknown","other"].includes(body.wallet_type) ? body.wallet_type : "unknown";
  const label = safeString(body.label || "", 120) || null;
  const source = safeString(body.source_reference || "", 500) || null;
  const notes = safeString(body.notes || "", 1000) || null;
  const key = chain + ":" + address;
  const timestamp = nowISO();
  await db.prepare(`INSERT INTO ci_wallet_watchlist (wallet_key,chain_id,wallet_address,label,wallet_type,profile_status,source_reference,notes,created_at,updated_at)
    VALUES (?,?,?,?,?,'user_supplied_unverified',?,?,?,?)
    ON CONFLICT(wallet_key) DO UPDATE SET label=excluded.label,wallet_type=excluded.wallet_type,source_reference=excluded.source_reference,notes=excluded.notes,updated_at=excluded.updated_at`).bind(
      key, chain, address, label, walletType, source, notes, timestamp, timestamp
    ).run();
  await audit(db,"wallet_watchlist_updated",chain+":"+address+" — profil utilisateur non vérifié");
  return { wallet_key:key, chain_id:chain, wallet_address:address, label, wallet_type:walletType, profile_status:"user_supplied_unverified", source_reference:source, notes, updated_at:timestamp };
}

async function recordRadarWalletBehavior(db, chain, discoveryKey) {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const rows = await db.prepare("SELECT wallet_address,trade_side,estimated_usd_value,observed_at,block_number,pair_address,wallet_category FROM ci_wallet_events WHERE chain_id = ? AND discovery_key = ? AND observed_at >= ? ORDER BY observed_at DESC LIMIT 1000").bind(chain, discoveryKey, cutoff).all();
  const events = rows.results || [];
  const byWallet = new Map();
  for (const event of events) {
    if (!byWallet.has(event.wallet_address)) byWallet.set(event.wallet_address, []);
    byWallet.get(event.wallet_address).push(event);
  }
  let signals = 0;
  for (const [wallet, activity] of byWallet) {
    const buys = activity.filter(item => item.trade_side === "buy");
    const sells = activity.filter(item => item.trade_side === "sell");
    if (buys.length >= 3) {
      const total = buys.reduce((sum,item)=>sum+(radarFiniteMetric(item.estimated_usd_value)||0),0);
      const first = buys[buys.length-1].observed_at, last = buys[0].observed_at;
      await db.prepare("INSERT INTO ci_wallet_behavior_signals (signal_id,chain_id,discovery_key,wallet_address,signal_type,severity,confidence_percent,window_start,window_end,evidence_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)").bind(
        crypto.randomUUID(),chain,discoveryKey,wallet,"repeated_accumulation","watch",Math.min(90,55+buys.length*5),first,last,
        JSON.stringify({buy_count:buys.length,sell_count:sells.length,estimated_buy_value_usd:total,wallet_category:activity[0]?.wallet_category||"unknown",note:"Achats répétés observés sur des événements Swap; intention ou solde net non déduits."}),nowISO()
      ).run();
      signals++;
    }
    if (sells.length >= 3) {
      await db.prepare("INSERT INTO ci_wallet_behavior_signals (signal_id,chain_id,discovery_key,wallet_address,signal_type,severity,confidence_percent,window_start,window_end,evidence_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)").bind(
        crypto.randomUUID(),chain,discoveryKey,wallet,"repeated_distribution","watch",Math.min(90,55+sells.length*5),sells[sells.length-1].observed_at,sells[0].observed_at,
        JSON.stringify({sell_count:sells.length,buy_count:buys.length,note:"Ventes répétées observées sur des événements Swap; solde total du portefeuille non connu."}),nowISO()
      ).run();
      signals++;
    }
    if (buys.length >= 2 && sells.length >= 2) {
      const churnCutoff = new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString();
      const priorChurn = await db.prepare("SELECT signal_id FROM ci_wallet_behavior_signals WHERE chain_id = ? AND discovery_key = ? AND wallet_address = ? AND signal_type = ? AND created_at >= ? LIMIT 1").bind(chain,discoveryKey,wallet,"rapid_buy_sell_churn_candidate",churnCutoff).first();
      const blocks = activity.map(item => Number(item.block_number)).filter(Number.isFinite);
      if (!priorChurn && blocks.length && Math.max(...blocks) - Math.min(...blocks) <= 500) {
        await db.prepare("INSERT INTO ci_wallet_behavior_signals (signal_id,chain_id,discovery_key,wallet_address,signal_type,severity,confidence_percent,window_start,window_end,evidence_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)").bind(
          crypto.randomUUID(),chain,discoveryKey,wallet,"rapid_buy_sell_churn_candidate","research",40,
          activity[activity.length-1].observed_at,activity[0].observed_at,
          JSON.stringify({buy_count:buys.length,sell_count:sells.length,block_span:Math.max(...blocks)-Math.min(...blocks),note:"Achats et ventes rapprochés pouvant justifier une analyse de churn ou de manipulation; aucune manipulation n'est établie par ce seul motif."}),nowISO()
        ).run();
        signals++;
      }
    }
  }

  // Plusieurs adresses actives dans une fenêtre de blocs rapprochée: piste de comportement similaire,
  // jamais preuve d'une identité commune, d'un financement commun ou d'une coordination.
  const buckets = new Map();
  for (const event of events.filter(item => item.trade_side === "buy" && Number.isFinite(Number(item.block_number)))) {
    const bucket = Math.floor(Number(event.block_number) / 100);
    if (!buckets.has(bucket)) buckets.set(bucket, new Map());
    const wallets = buckets.get(bucket);
    if (!wallets.has(event.wallet_address)) wallets.set(event.wallet_address, []);
    wallets.get(event.wallet_address).push(event);
  }
  for (const [bucket, wallets] of buckets) {
    const small = [...wallets.entries()].filter(([,items])=>items.some(item=>item.wallet_category==="small_trade_size"));
    if (small.length < 5) continue;
    const members = small.map(([wallet])=>wallet).sort();
    const first = small.flatMap(([,items])=>items.map(item=>item.observed_at)).sort()[0];
    const last = small.flatMap(([,items])=>items.map(item=>item.observed_at)).sort().slice(-1)[0];
    const clusterKey = chain+":"+discoveryKey+":small-buys:"+bucket;
    await db.prepare("INSERT OR IGNORE INTO ci_wallet_clusters (cluster_id,chain_id,discovery_key,cluster_type,verification_status,member_wallets_json,evidence_json,first_observed_at,last_observed_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)").bind(
      clusterKey,chain,discoveryKey,"temporally_similar_small_wallet_buys","unverified_candidate",JSON.stringify(members),
      JSON.stringify({block_bucket_100:bucket,member_count:members.length,note:"Proximité temporelle seulement. Aucun lien d'identité, financement, contrôle commun ou coordination n'est prouvé."}),
      first,last,nowISO()
    ).run();
    await db.prepare("INSERT INTO ci_wallet_behavior_signals (signal_id,chain_id,discovery_key,wallet_address,signal_type,severity,confidence_percent,window_start,window_end,evidence_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)").bind(
      crypto.randomUUID(),chain,discoveryKey,null,"small_wallet_co_accumulation_candidate","research",45,first,last,
      JSON.stringify({cluster_id:clusterKey,member_wallets:members,verification_status:"unverified_candidate",note:"Regroupement temporel exploratoire, pas preuve de coordination."}),nowISO()
    ).run();
    signals++;
  }
  return {events_examined:events.length,wallets_observed:byWallet.size,signals_created:signals};
}

async function runRadarWalletScan(db, options = {}) {
  await ensureRadarWalletTables(db);
  const chainFilter = safeString(options.chain_id || "",80).toLowerCase();
  const discoveryFilter = safeString(options.discovery_key || "",200);
  const pairLimit = Math.max(1,Math.min(20,Number(options.pair_limit)||5));
  const pairs = await db.prepare(
    "SELECT p.chain_id,p.pair_address,p.token_address,p.token_symbol,p.pair_key,d.discovery_key FROM ci_radar_pairs p JOIN ci_radar_discoveries d ON lower(d.chain_id)=lower(p.chain_id) AND lower(d.contract_address)=lower(p.token_address) WHERE (?='' OR lower(p.chain_id)=?) AND (?='' OR d.discovery_key=?) ORDER BY p.last_seen_at DESC LIMIT ?"
  ).bind(chainFilter,chainFilter,discoveryFilter,discoveryFilter,pairLimit).all();
  const results = [];
  let eventsSaved=0, signalsCreated=0, errors=0;
  for (const pair of pairs.results || []) {
    const rpc = radarPublicRpc(pair.chain_id);
    if (!rpc) { results.push({pair_address:pair.pair_address,status:"unsupported_chain"}); continue; }
    const cursorKey = (pair.chain_id+":"+pair.pair_address).toLowerCase();
    try {
      const latestHex = await radarWalletRpcRequest(rpc.url,"eth_blockNumber",[]);
      const latestBlock = Number(BigInt(latestHex));
      if (!Number.isSafeInteger(latestBlock) || latestBlock < 1) throw new Error("Hauteur de bloc RPC invalide.");
      const cursor = await db.prepare("SELECT last_scanned_block FROM ci_wallet_scan_cursors WHERE cursor_key = ?").bind(cursorKey).first();
      const configuredRange = Math.max(1,Math.min(RADAR_WALLET_SCAN_MAX_BLOCK_RANGE,Number(options.block_range)||RADAR_WALLET_SCAN_DEFAULT_BLOCK_RANGE));
      const fromBlock = cursor ? Math.max(0,Number(cursor.last_scanned_block)+1) : Math.max(0,latestBlock-configuredRange+1);
      const toBlock = Math.min(latestBlock,fromBlock+configuredRange-1);
      if (fromBlock>toBlock) { results.push({pair_address:pair.pair_address,status:"up_to_date",last_scanned_block:latestBlock}); continue; }
      const logs = await radarWalletRpcRequest(rpc.url,"eth_getLogs",[{address:pair.pair_address,fromBlock:"0x"+fromBlock.toString(16),toBlock:"0x"+toBlock.toString(16),topics:[RADAR_WALLET_SWAP_TOPIC] }]);
      if (!Array.isArray(logs)) throw new Error("Réponse eth_getLogs invalide.");
      await recordProviderUsage(db,"publicnode_wallet_rpc",true,200);
      const tokenCheck = await db.prepare("SELECT token0_address,token1_address,token0_decimals,token1_decimals FROM ci_radar_onchain_pool_checks WHERE chain_id = ? AND pair_address = ? AND outcome = 'onchain_reserves_read' ORDER BY checked_at DESC LIMIT 1").bind(pair.chain_id,pair.pair_address).first();
      let token0=tokenCheck?.token0_address||null,token1=tokenCheck?.token1_address||null;
      let decimals0=radarFiniteMetric(tokenCheck?.token0_decimals),decimals1=radarFiniteMetric(tokenCheck?.token1_decimals);
      if (!token0 || !token1) {
        const values=await Promise.all([
          radarRpcCall(rpc.url,"eth_call",[{to:pair.pair_address,data:"0x0dfe1681"},"latest"]),
          radarRpcCall(rpc.url,"eth_call",[{to:pair.pair_address,data:"0xd21220a7"},"latest"])
        ]);
        token0=radarDecodeAddress(values[0]);token1=radarDecodeAddress(values[1]);
      }
      const target=String(pair.token_address||"").toLowerCase();
      const targetIndex=String(token0||"").toLowerCase()===target?0:String(token1||"").toLowerCase()===target?1:-1;
      if (targetIndex<0) throw new Error("Le token surveillé ne correspond pas aux tokens on-chain de la paire.");
      const targetDecimals=targetIndex===0?decimals0:decimals1;
      let resolvedDecimals=targetDecimals;
      if (resolvedDecimals===null || resolvedDecimals===undefined) {
        const tokenResult=await radarRpcCall(rpc.url,"eth_call",[{to:target,data:"0x313ce567"},"latest"]);
        const word=radarHexWord(tokenResult,0);
        resolvedDecimals=word?Number(BigInt("0x"+word)):null;
      }
      if (!Number.isInteger(resolvedDecimals)||resolvedDecimals<0||resolvedDecimals>36) throw new Error("Décimales du token indisponibles ou invalides.");
      const priceRow=await db.prepare("SELECT price_usd FROM ci_radar_pool_metrics WHERE discovery_key = ? AND pair_address = ? ORDER BY observed_at DESC LIMIT 1").bind(pair.discovery_key,pair.pair_address).first();
      const tokenPrice=radarFiniteMetric(priceRow?.price_usd);
      let pairEvents=0;
      for (const log of logs.slice(0,100)) {
        if (!Array.isArray(log.topics)||log.topics.length<3||!log.transactionHash) continue;
        const words=[0,1,2,3].map(index=>radarWalletDecodeWord(log.data,index));
        if (words.some(value=>value===null)) continue;
        const targetIn=words[targetIndex],targetOut=words[targetIndex+2];
        let side="unknown",rawAmount=null;
        if (targetOut>0n && targetIn===0n) { side="buy";rawAmount=targetOut; }
        else if (targetIn>0n && targetOut===0n) { side="sell";rawAmount=targetIn; }
        else continue;
        const tx=await radarWalletRpcRequest(rpc.url,"eth_getTransactionByHash",[log.transactionHash]);
        const wallet=String(tx?.from||"").toLowerCase();
        if (!/^0x[a-f0-9]{40}$/.test(wallet)) continue;
        const tokenAmount=Number(rawAmount)/Math.pow(10,resolvedDecimals);
        const usdValue=tokenPrice!==null&&tokenPrice>0&&Number.isFinite(tokenAmount)?tokenAmount*tokenPrice:null;
        const category=radarWalletTradeCategory(usdValue);
        const watch=await db.prepare("SELECT wallet_type,profile_status FROM ci_wallet_watchlist WHERE chain_id = ? AND wallet_address = ?").bind(pair.chain_id,wallet).first();
        const blockNumber=Number(BigInt(log.blockNumber));
        const recipient=radarWalletTopicAddress(log.topics[2]);
        const observedAt=nowISO();
        const evidence={
          source:"PublicNode eth_getLogs + eth_getTransactionByHash",
          event:"Uniswap-V2-compatible Swap",
          transaction_origin_wallet:wallet,
          pair_address:pair.pair_address,
          target_token_address:target,
          target_token_index:targetIndex,
          raw_amounts:{amount0_in:words[0].toString(),amount1_in:words[1].toString(),amount0_out:words[2].toString(),amount1_out:words[3].toString()},
          token_decimals:resolvedDecimals,
          token_price_usd_reference:tokenPrice,
          usd_value_is_estimate:true,
          recipient_address:recipient,
          wallet_identity_verified:false,
          trade_classification:"Swap event decoded; transaction origin used as wallet actor. Smart routers/contract wallets may represent an intermediary.",
          transfer_only_events_excluded:true
        };
        const inserted=await db.prepare("INSERT OR IGNORE INTO ci_wallet_events (event_id,chain_id,discovery_key,pair_address,wallet_address,recipient_address,transaction_hash,log_index,block_number,observed_at,trade_side,target_token_amount,estimated_usd_value,value_source,wallet_category,watchlist_status,evidence_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(
          crypto.randomUUID(),pair.chain_id,pair.discovery_key,pair.pair_address,wallet,recipient,log.transactionHash,Number(BigInt(log.logIndex)),blockNumber,observedAt,side,tokenAmount,usdValue,
          tokenPrice!==null?"provider_price_estimate":"unknown",category,watch?(watch.profile_status+":"+watch.wallet_type):"unknown",JSON.stringify(evidence)
        ).run();
        if (Number(inserted.meta?.changes||0)>0) { eventsSaved++;pairEvents++; }
      }
      await db.prepare("INSERT INTO ci_wallet_scan_cursors (cursor_key,chain_id,pair_address,last_scanned_block,last_scan_at,status,error_message) VALUES (?,?,?,?,?,'completed',NULL) ON CONFLICT(cursor_key) DO UPDATE SET last_scanned_block=excluded.last_scanned_block,last_scan_at=excluded.last_scan_at,status='completed',error_message=NULL").bind(
        cursorKey,pair.chain_id,pair.pair_address,toBlock,nowISO()
      ).run();
      results.push({pair_address:pair.pair_address,chain_id:pair.chain_id,status:"completed",from_block:fromBlock,to_block:toBlock,swap_logs_found:logs.length,events_saved:pairEvents});
      const behavior=await recordRadarWalletBehavior(db,pair.chain_id,pair.discovery_key);
      signalsCreated+=behavior.signals_created;
    } catch(error) {
      errors++;
      await db.prepare("INSERT INTO ci_wallet_scan_cursors (cursor_key,chain_id,pair_address,last_scanned_block,last_scan_at,status,error_message) VALUES (?,?,?,0,?,'error',?) ON CONFLICT(cursor_key) DO UPDATE SET last_scan_at=excluded.last_scan_at,status='error',error_message=excluded.error_message").bind(
        cursorKey,pair.chain_id,pair.pair_address,nowISO(),safeString(error.message||"Erreur scan wallet.",500)
      ).run();
      await recordProviderUsage(db,"publicnode_wallet_rpc",false,error.status||500);
      results.push({pair_address:pair.pair_address,chain_id:pair.chain_id,status:"error",error:safeString(error.message||"Erreur RPC.",300)});
    }
  }
  const status=errors?(results.length===errors?"failed":"partial"):"completed";
  await audit(db,"wallet_monitoring_scan",eventsSaved+" événements Swap ajoutés; "+signalsCreated+" signaux comportementaux; "+errors+" erreurs.");
  return {status,pairs_examined:results.length,events_saved:eventsSaved,signals_created:signalsCreated,errors,results,thresholds_usd:RADAR_WALLET_THRESHOLDS_USD,supported_chains:["Ethereum","BSC","Base"],limitations:["Lecture des événements Swap V2 compatibles uniquement; les autres AMM ne sont pas couverts par ce parseur.","L'adresse from de la transaction est l'initiateur, pas nécessairement le bénéficiaire économique.","Les valeurs USD sont estimées avec le dernier prix DexScreener connu.","Les transferts ERC-20 simples ne sont jamais comptés comme achats ou ventes.","Les clusters temporels restent non vérifiés et ne prouvent aucune relation entre portefeuilles."]};
}



/* -------------------------------------------------------------------------- */
/* CHAPITRE 8 — CONAN : CYCLE D'OBSERVATION, PRÉDICTION ET APPRENTISSAGE 15 J */
/* -------------------------------------------------------------------------- */
const CONAN_PREDICTION_METHODOLOGY = "conan-15d-v1";
const CONAN_PROVIDER_DAILY_LIMIT_DEFAULT = 5;
const CONAN_OBSERVATION_MIN_INTERVAL_MS = 15 * 60 * 1000;
const CONAN_FORECAST_ROLES = [
  {id:"fundamentals",name:"IA Fondamentale",task:"Évalue les fondamentaux, l'utilité et les événements vérifiables qui peuvent influer sur le prix."},
  {id:"financial",name:"IA Financière",task:"Analyse prix, volumes, liquidité, volatilité et scénarios chiffrés à partir des observations fournies."},
  {id:"security",name:"IA Sécurité",task:"Évalue les risques de contrat, liquidité et manipulation; identifie les conditions d'invalidation."},
  {id:"growth",name:"IA Croissance",task:"Évalue activité, adoption et catalyseurs vérifiables; sépare faits et hypothèses."},
  {id:"arbiter",name:"IA Arbitre",task:"Confronte les quatre avis indépendants et produit une prévision prudente sans effacer leurs désaccords."}
];

function conanUtcDate(value=new Date()){return new Date(value).toISOString().slice(0,10);}
function conanCycleDay(startDate,today=conanUtcDate()){
  return Math.max(1,Math.floor((Date.parse(today+"T00:00:00.000Z")-Date.parse(startDate+"T00:00:00.000Z"))/86400000)+1);
}

function normalizeConanForecast(raw,referencePrice){
  const value=raw&&typeof raw==="object"&&!Array.isArray(raw)?raw:{};
  const direction=["up","down","sideways"].includes(String(value.direction||"").toLowerCase())?String(value.direction).toLowerCase():null;
  const targets=(Array.isArray(value.targets)?value.targets.slice(0,3):[]).map((item,index)=>{
    const price=radarFiniteMetric(item?.price_usd??item?.price??item?.target_price);
    const probability=radarFiniteMetric(item?.probability_percent??item?.probability);
    if(price===null||price<=0||probability===null||probability<0||probability>100)return null;
    if(direction==="up"&&price<=referencePrice)return null;
    if(direction==="down"&&price>=referencePrice)return null;
    return {target_index:index+1,price_usd:price,probability_percent:probability,horizon:"15_day_cycle"};
  }).filter(Boolean);
  const confidence=radarFiniteMetric(value.confidence_percent??value.confidence);
  const invalidation=radarFiniteMetric(value.invalidation_price_usd??value.invalidation_price);
  if(!direction||!targets.length)return null;
  if(direction==="up"&&invalidation!==null&&invalidation>=referencePrice)return null;
  if(direction==="down"&&invalidation!==null&&invalidation<=referencePrice)return null;
  return {
    direction,targets,
    confidence_percent:confidence===null?null:Math.max(0,Math.min(100,confidence)),
    invalidation_price_usd:invalidation,
    risks:Array.isArray(value.risks)?value.risks.slice(0,20).map(item=>safeString(typeof item==="object"?(item.statement||item.description):item,800)).filter(Boolean):[],
    reasoning:safeString(value.reasoning||value.summary||value.conclusion||"",3000)
  };
}

async function ensureConanPredictionTables(db){await initializeBackendTables(db);}

async function getConanLatestMarket(db,discoveryKey){
  return await db.prepare("SELECT discovery_key,chain_id,pair_address,price_usd,liquidity_usd,volume_24h_usd,buys_24h,sells_24h,observed_at,source FROM ci_radar_pool_metrics WHERE discovery_key=? AND price_usd>0 ORDER BY observed_at DESC LIMIT 1").bind(discoveryKey).first();
}

async function selectConanCycleAssets(db){
  const result=await db.prepare("SELECT d.discovery_key,d.chain_id,d.contract_address,d.token_name,d.token_symbol,m.pair_address,m.price_usd,m.source,m.observed_at,m.liquidity_usd,m.volume_24h_usd FROM ci_radar_discoveries d JOIN ci_radar_pool_metrics m ON m.metric_key=(SELECT pm.metric_key FROM ci_radar_pool_metrics pm WHERE pm.discovery_key=d.discovery_key AND pm.price_usd>0 ORDER BY pm.observed_at DESC LIMIT 1) WHERE m.price_usd>0 ORDER BY RANDOM() LIMIT 100").all();
  const candidates=result.results||[];
  if(candidates.length<2)return {assets:[],mode:"unavailable",reason:"Moins de deux actifs distincts disposent d'un prix source exploitable."};
  const historyResult=await db.prepare("SELECT p.discovery_key,AVG(CASE WHEN r.direction_correct=1 THEN 100 WHEN r.direction_correct=0 THEN 0 ELSE NULL END) AS accuracy,COUNT(r.result_id) AS sample_count FROM ci_conan_predictions p JOIN ci_conan_prediction_results r ON r.prediction_id=p.prediction_id WHERE r.outcome_status='evaluated' GROUP BY p.discovery_key").all();
  const history=new Map((historyResult.results||[]).map(row=>[row.discovery_key,{accuracy:radarFiniteMetric(row.accuracy),count:Number(row.sample_count)||0}]));
  const experienced=history.size>0;
  if(!experienced){
    for(let i=candidates.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[candidates[i],candidates[j]]=[candidates[j],candidates[i]];}
  }else{
    candidates.sort((a,b)=>{
      const ah=history.get(a.discovery_key),bh=history.get(b.discovery_key);
      const av=ah?ah.accuracy+Math.min(ah.count,10)*0.25:50;
      const bv=bh?bh.accuracy+Math.min(bh.count,10)*0.25:50;
      return bv-av||(Math.random()-0.5);
    });
  }
  return {assets:candidates.slice(0,2),mode:experienced?"experience_weighted_with_exploration":"random_initial",reason:experienced?"Sélection pondérée par les résultats antérieurs évalués, avec exploration des actifs sans historique.":"Sélection initiale aléatoire parmi les actifs possédant un prix observé."};
}

async function createConanPredictionCycle(db){
  const today=conanUtcDate();
  const completed=await db.prepare("SELECT cycle_id FROM ci_conan_prediction_cycles WHERE status='completed' AND completed_at>=? LIMIT 1").bind(today+"T00:00:00.000Z").first();
  if(completed)return {status:"cycle_completed_today",cycle_id:completed.cycle_id};
  const selection=await selectConanCycleAssets(db);
  if(selection.assets.length!==2)return {status:"waiting_for_two_assets",reason:selection.reason};
  const id=cryptoRandomId(),timestamp=nowISO();
  await db.prepare("INSERT INTO ci_conan_prediction_cycles (cycle_id,status,cycle_start_date,current_day,selection_mode,learning_stage,methodology_version,created_at,updated_at) VALUES (?,'observing',?,1,?,'child',?,?,?)").bind(id,today,selection.mode,CONAN_PREDICTION_METHODOLOGY,timestamp,timestamp).run();
  for(let i=0;i<2;i++){
    const asset=selection.assets[i];
    await db.prepare("INSERT INTO ci_conan_prediction_assets (asset_row_id,cycle_id,asset_order,discovery_key,chain_id,contract_address,token_name,token_symbol,pair_address,selected_at,selection_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?)").bind(
      cryptoRandomId(),id,i+1,asset.discovery_key,asset.chain_id,asset.contract_address,asset.token_name,asset.token_symbol,asset.pair_address,timestamp,selection.reason
    ).run();
    await recordConanPredictionObservation(db,{cycle_id:id},asset,1);
  }
  await db.prepare("INSERT INTO ci_conan_learning_history (learning_id,cycle_id,learning_type,summary,evidence_json,created_at) VALUES (?,?,?,?,?,?)").bind(
    cryptoRandomId(),id,"cycle_started","Début du cycle de 15 jours : deux actifs distincts; observation initiale pendant les jours 1 à 7.",JSON.stringify({selection_mode:selection.mode,selection_reason:selection.reason,assets:selection.assets.map(item=>({discovery_key:item.discovery_key,chain_id:item.chain_id,contract_address:item.contract_address,pair_address:item.pair_address,price_usd:item.price_usd,source:item.source,observed_at:item.observed_at}))}),timestamp
  ).run();
  await audit(db,"conan_prediction_cycle_started","Cycle "+id+" lancé avec deux actifs distincts.");
  return {status:"started",cycle_id:id,cycle_start_date:today,selection_mode:selection.mode,assets:selection.assets.map(item=>({discovery_key:item.discovery_key,chain_id:item.chain_id,contract_address:item.contract_address,symbol:item.token_symbol,price_usd:item.price_usd,source:item.source}))};
}

async function getConanProviderUsage(db,since){
  const result=await db.prepare("SELECT provider,COUNT(*) AS calls FROM (SELECT provider,created_at FROM ci_ai_council_opinions WHERE provider IS NOT NULL AND status IN ('completed','failed') AND created_at>=? UNION ALL SELECT provider,created_at FROM ci_conan_prediction_opinions WHERE provider IS NOT NULL AND status IN ('completed','failed') AND created_at>=?) GROUP BY provider").bind(since,since).all();
  return new Map((result.results||[]).map(row=>[row.provider,Number(row.calls)||0]));
}

async function callConanForecastRole(db,env,cycle,asset,predictionId,role,context,usage,dailyLimit){
  const providers=availableAIProviders(env);
  const provider=providers.filter(item=>(usage.get(item)||0)<dailyLimit).sort((a,b)=>(usage.get(a)||0)-(usage.get(b)||0))[0];
  if(!provider){
    const message="Plafond journalier local atteint; appel non effectué, aucun avis simulé.";
    await db.prepare("INSERT INTO ci_conan_prediction_opinions (opinion_id,cycle_id,prediction_id,discovery_key,role,provider,status,opinion_json,error_message,created_at) VALUES (?,?,?,?,?,NULL,'skipped_quota','{}',?,?)").bind(cryptoRandomId(),cycle.cycle_id,predictionId,asset.discovery_key,role.id,message,nowISO()).run();
    return null;
  }
  const prompt=[
    "CRYPTO INTELLIGENCE — CONAN — PRÉVISION DU CYCLE DE 15 JOURS",
    "RÔLE : "+role.name+" ("+role.id+"). MISSION : "+role.task,
    "DONNÉES ET OBSERVATIONS : "+JSON.stringify(context),
    "Prévision pour la période de suivi du jour 8 au jour 15. Le prix de référence fourni ne doit pas être remplacé.",
    "Ne fabrique aucun prix, volume, fait ou source. Distingue faits, hypothèses, risques et inconnues. Une probabilité n'est pas une garantie.",
    "Retourne uniquement un JSON : direction ('up','down','sideways'), targets (1 à 3 objets {price_usd,probability_percent}), confidence_percent, invalidation_price_usd, risks (tableau), reasoning.",
    "Pour up, les cibles sont au-dessus du prix de référence; pour down, elles sont en dessous. Si les données sont insuffisantes, ne fabrique pas de cible.",
    role.id==="arbiter"?"Compare les quatre avis indépendants fournis, conserve leurs désaccords et arbitre prudemment.":"Avis indépendant requis; n'imite pas les autres rôles."
  ].join("\n");
  try{
    const parsed=parseAIResponse(await callAIProvider(provider,env,prompt));
    const forecast=normalizeConanForecast(parsed,context.reference_price_usd);
    const status=forecast?"completed":"invalid_response";
    await db.prepare("INSERT INTO ci_conan_prediction_opinions (opinion_id,cycle_id,prediction_id,discovery_key,role,provider,status,opinion_json,error_message,created_at) VALUES (?,?,?,?,?,?,?,?,NULL,?)").bind(
      cryptoRandomId(),cycle.cycle_id,predictionId,asset.discovery_key,role.id,provider,status,JSON.stringify({raw:parsed,normalized_forecast:forecast}),nowISO()
    ).run();
    usage.set(provider,(usage.get(provider)||0)+1);
    await recordProviderUsage(db,provider,true,200);
    return {role:role.id,provider,status,forecast,raw:parsed};
  }catch(error){
    const message=safeString(error.message||"Erreur fournisseur IA.",700);
    await db.prepare("INSERT INTO ci_conan_prediction_opinions (opinion_id,cycle_id,prediction_id,discovery_key,role,provider,status,opinion_json,error_message,created_at) VALUES (?,?,?,?,?,?,'failed','{}',?,?)").bind(
      cryptoRandomId(),cycle.cycle_id,predictionId,asset.discovery_key,role.id,provider,message,nowISO()
    ).run();
    usage.set(provider,(usage.get(provider)||0)+1);
    await recordProviderUsage(db,provider,false,error.status||500);
    return {role:role.id,provider,status:"failed",error:message};
  }
}

async function lockConanPredictionForAsset(db,env,cycle,asset,market,usage,dailyLimit){
  const existing=await db.prepare("SELECT prediction_id FROM ci_conan_predictions WHERE cycle_id=? AND discovery_key=?").bind(cycle.cycle_id,asset.discovery_key).first();
  if(existing)return {status:"already_locked",prediction_id:existing.prediction_id};
  if(!market||!Number.isFinite(Number(market.price_usd))||Number(market.price_usd)<=0)return {status:"waiting_for_reference_price"};
  const predictionId=cryptoRandomId();
  const observations=await db.prepare("SELECT cycle_day,price_usd,liquidity_usd,volume_24h_usd,buys_24h,sells_24h,source,source_observed_at,observed_at FROM ci_conan_prediction_observations WHERE cycle_id=? AND discovery_key=? ORDER BY observed_at ASC LIMIT 500").bind(cycle.cycle_id,asset.discovery_key).all();
  const context={
    asset:{discovery_key:asset.discovery_key,chain_id:asset.chain_id,contract_address:asset.contract_address,symbol:asset.token_symbol,pair_address:asset.pair_address},
    reference_price_usd:Number(market.price_usd),reference_source:market.source,reference_observed_at:market.observed_at,
    observations:observations.results||[],cycle_start_date:cycle.cycle_start_date,lock_day:8,evaluation_day:15
  };
  const experts=[];
  for(const role of CONAN_FORECAST_ROLES.filter(item=>item.id!=="arbiter"))experts.push(await callConanForecastRole(db,env,cycle,asset,predictionId,role,context,usage,dailyLimit));
  const usable=experts.filter(item=>item&&item.status==="completed"&&item.forecast);
  if(usable.length<2)return {status:"insufficient_ai_opinions",expert_opinions:usable.length,required:2};
  const arbiterRole=CONAN_FORECAST_ROLES.find(item=>item.id==="arbiter");
  const arbiter=await callConanForecastRole(db,env,cycle,asset,predictionId,arbiterRole,{...context,independent_opinions:usable.map(item=>({role:item.role,provider:item.provider,forecast:item.forecast}))},usage,dailyLimit);
  if(!arbiter||arbiter.status!=="completed"||!arbiter.forecast)return {status:"arbiter_forecast_unavailable",expert_opinions:usable.length};
  const forecast=arbiter.forecast,lockedAt=nowISO();
  const summary={expert_roles:usable.map(item=>({role:item.role,provider:item.provider,direction:item.forecast.direction,confidence_percent:item.forecast.confidence_percent})),arbiter_provider:arbiter.provider,expert_disagreement:new Set(usable.map(item=>item.forecast.direction)).size>1};
  await db.prepare("INSERT OR IGNORE INTO ci_conan_predictions (prediction_id,cycle_id,discovery_key,chain_id,contract_address,token_symbol,pair_address,locked_at,reference_price_usd,reference_source,reference_observed_at,direction,targets_json,probabilities_json,confidence_percent,invalidation_price_usd,risks_json,reasoning,council_summary_json,methodology_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(
    predictionId,cycle.cycle_id,asset.discovery_key,asset.chain_id,asset.contract_address,asset.token_symbol,asset.pair_address,lockedAt,Number(market.price_usd),safeString(market.source||"unknown",120),market.observed_at,forecast.direction,JSON.stringify(forecast.targets),JSON.stringify(forecast.targets.map(item=>item.probability_percent)),forecast.confidence_percent,forecast.invalidation_price_usd,JSON.stringify(forecast.risks),forecast.reasoning,JSON.stringify(summary),CONAN_PREDICTION_METHODOLOGY
  ).run();
  const progress=forecast.targets.map(item=>({target_index:item.target_index,price_usd:item.price_usd,probability_percent:item.probability_percent,touched_at:null,held_1h_at:null,verification_method:null}));
  await db.prepare("INSERT OR IGNORE INTO ci_conan_prediction_progress (prediction_id,latest_price_usd,latest_observed_at,targets_progress_json,last_updated_at) VALUES (?,?,?,?,?)").bind(predictionId,market.price_usd,market.observed_at,JSON.stringify(progress),lockedAt).run();
  await audit(db,"conan_prediction_locked","Prévision verrouillée pour "+asset.discovery_key+"; prix de référence "+market.price_usd+".");
  return {status:"locked",prediction_id:predictionId,direction:forecast.direction,targets:forecast.targets,reference_price_usd:Number(market.price_usd),locked_at:lockedAt,expert_opinions:usable.length};
}

function conanTargetReached(direction,price,target){
  return direction==="up"?price>=target:direction==="down"?price<=target:Math.abs((price-target)/target)*100<=1;
}

async function recordConanPredictionObservation(db,cycle,asset,cycleDay){
  const market=await getConanLatestMarket(db,asset.discovery_key);
  if(!market||!Number.isFinite(Number(market.price_usd))||Number(market.price_usd)<=0)return {status:"missing_price"};
  const last=await db.prepare("SELECT observed_at FROM ci_conan_prediction_observations WHERE cycle_id=? AND discovery_key=? ORDER BY observed_at DESC LIMIT 1").bind(cycle.cycle_id,asset.discovery_key).first();
  const previous=last?Date.parse(last.observed_at):0;
  if(previous&&Date.now()-previous<CONAN_OBSERVATION_MIN_INTERVAL_MS)return {status:"sample_interval_not_elapsed",price_usd:market.price_usd};
  const timestamp=nowISO();
  await db.prepare("INSERT INTO ci_conan_prediction_observations (observation_id,cycle_id,discovery_key,cycle_day,price_usd,liquidity_usd,volume_24h_usd,buys_24h,sells_24h,source,source_observed_at,observed_at,evidence_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(
    cryptoRandomId(),cycle.cycle_id,asset.discovery_key,cycleDay,market.price_usd,market.liquidity_usd,market.volume_24h_usd,market.buys_24h,market.sells_24h,safeString(market.source||"unknown",120),market.observed_at,timestamp,
    JSON.stringify({provider_source:market.source,market_metric_observed_at:market.observed_at,live_status:"dernier relevé fournisseur persisté; pas une cotation directe garantie"})
  ).run();
  const prediction=await db.prepare("SELECT * FROM ci_conan_predictions WHERE cycle_id=? AND discovery_key=?").bind(cycle.cycle_id,asset.discovery_key).first();
  if(prediction){
    const row=await db.prepare("SELECT targets_progress_json FROM ci_conan_prediction_progress WHERE prediction_id=?").bind(prediction.prediction_id).first();
    let targets=[];try{targets=JSON.parse(row?.targets_progress_json||"[]");}catch{targets=[];}
    for(const target of targets){
      const reached=conanTargetReached(prediction.direction,Number(market.price_usd),Number(target.price_usd));
      if(reached&&!target.touched_at)target.touched_at=timestamp;
      if(reached&&!target.streak_started_at)target.streak_started_at=timestamp;
      if(!reached)target.streak_started_at=null;
      if(reached&&target.streak_started_at&&!target.held_1h_at&&Date.now()-Date.parse(target.streak_started_at)>=3600000){
        const streakRows=await db.prepare("SELECT price_usd,observed_at FROM ci_conan_prediction_observations WHERE cycle_id=? AND discovery_key=? AND observed_at>=? AND observed_at<=? ORDER BY observed_at ASC").bind(
          cycle.cycle_id,asset.discovery_key,target.streak_started_at,timestamp
        ).all();
        const samples=streakRows.results||[];
        const gaps=samples.slice(1).map((item,index)=>Date.parse(item.observed_at)-Date.parse(samples[index].observed_at));
        const allSamplesFavorable=samples.length>=3&&samples.every(item=>conanTargetReached(prediction.direction,Number(item.price_usd),Number(target.price_usd)));
        const samplingContinuousEnough=gaps.length>0&&Math.max(...gaps)<=30*60*1000;
        if(allSamplesFavorable&&samplingContinuousEnough){
          target.held_1h_at=timestamp;
          target.verification_method="all_recorded_samples_favorable_for_one_hour_maximum_gap_30m";
        }
      }
    }
    await db.prepare("INSERT INTO ci_conan_prediction_progress (prediction_id,latest_price_usd,latest_observed_at,targets_progress_json,last_updated_at) VALUES (?,?,?,?,?) ON CONFLICT(prediction_id) DO UPDATE SET latest_price_usd=excluded.latest_price_usd,latest_observed_at=excluded.latest_observed_at,targets_progress_json=excluded.targets_progress_json,last_updated_at=excluded.last_updated_at").bind(
      prediction.prediction_id,market.price_usd,timestamp,JSON.stringify(targets),timestamp
    ).run();
  }
  return {status:"observed",price_usd:market.price_usd,source:market.source,observed_at:timestamp};
}


/* CHAPITRE 9 — BARÈME CONAN /100, PONDÉRATIONS OFFICIELLES */
const CONAN_SCORE_METHODOLOGY = "conan-score-100-v1";
const CONAN_SCORE_WEIGHTS = Object.freeze({
  direction:25,
  target_technical:15,
  probability_calibration:10,
  project_quality:20,
  market_activity:15,
  risk_management:15
});

function conanSafeParse(value,fallback){
  try{return JSON.parse(value??"");}catch{return fallback;}
}
function conanClamp(value,min=0,max=100){
  const number=Number(value);
  return Number.isFinite(number)?Math.max(min,Math.min(max,number)):min;
}
function conanHasCriticalRisk(value,depth=0){
  if(depth>6||value===null||value===undefined)return false;
  if(typeof value==="string")return /confirmed[_ -]?(scam|rug[_ -]?pull)|honeypot[_ -]?confirmed|cannot[_ -]?sell|malicious[_ -]?contract|critical[_ -]?risk/i.test(value);
  if(Array.isArray(value))return value.some(item=>conanHasCriticalRisk(item,depth+1));
  if(typeof value==="object"){
    for(const [key,item] of Object.entries(value)){
      if(/critical[_ -]?risk|risk[_ -]?veto|security[_ -]?veto|confirmed[_ -]?(scam|rug[_ -]?pull)|honeypot[_ -]?confirmed|cannot[_ -]?sell|malicious[_ -]?contract/i.test(key)&&item===true)return true;
      if((key==="risk_flags"||key==="critical_risks"||key==="veto_reasons")&&conanHasCriticalRisk(item,depth+1))return true;
      if(conanHasCriticalRisk(item,depth+1))return true;
    }
  }
  return false;
}

async function calculateAndPersistConanScore(db,cycle){
  const predictionsResult=await db.prepare("SELECT * FROM ci_conan_predictions WHERE cycle_id=? ORDER BY locked_at ASC").bind(cycle.cycle_id).all();
  const predictions=predictionsResult.results||[];
  const resultRows=await db.prepare("SELECT * FROM ci_conan_prediction_results WHERE cycle_id=?").bind(cycle.cycle_id).all();
  const resultsById=new Map((resultRows.results||[]).map(item=>[item.prediction_id,item]));
  const evaluated=predictions.filter(item=>resultsById.get(item.prediction_id)?.outcome_status==="evaluated");
  const unverifiable=(resultRows.results||[]).filter(item=>item.outcome_status==="unverifiable").length;
  if(!evaluated.length){
    const noData={reason:"Aucune prédiction vérifiable : score total non calculable, aucune note artificielle.",weights:CONAN_SCORE_WEIGHTS};
    await db.prepare("INSERT OR IGNORE INTO ci_conan_score_history (score_id,cycle_id,score_total,direction_score,targets_technical_score,probability_calibration_score,project_quality_score,market_activity_score,risk_management_score,evaluated_predictions,unverifiable_predictions,methodology_version,components_json,created_at) VALUES (?,?,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?,?,?,?,?)").bind(
      cryptoRandomId(),cycle.cycle_id,0,unverifiable,CONAN_SCORE_METHODOLOGY,JSON.stringify(noData),nowISO()
    ).run();
    return {score_total:null,score_status:"not_calculable",reason:noData.reason,weights:CONAN_SCORE_WEIGHTS};
  }

  let directionCorrect=0,targetTechnicalTotal=0,calibrationTotal=0,projectTotal=0,activityTotal=0,riskTotal=0;
  let targetCount=0,calibrationCount=0;
  const assetEvidence=[];
  for(const prediction of evaluated){
    const result=resultsById.get(prediction.prediction_id);
    if(Number(result.direction_correct)===1)directionCorrect++;
    const progressRow=await db.prepare("SELECT targets_progress_json FROM ci_conan_prediction_progress WHERE prediction_id=?").bind(prediction.prediction_id).first();
    const progress=conanSafeParse(progressRow?.targets_progress_json,[]);
    const targets=Array.isArray(progress)?progress:[];
    let targetAttainment=0,targetCalibration=0;
    for(const target of targets){
      const probability=conanClamp(target.probability_percent,0,100)/100;
      const touched=Boolean(target.touched_at);
      const held=Boolean(target.held_1h_at);
      targetAttainment+=held?1:touched?0.5:0;
      targetCalibration+=(probability-(touched?1:0))**2;
      targetCount++;calibrationCount++;
    }
    const technical=targets.length?15*targetAttainment/targets.length:0;
    const calibration=targets.length?10*(1-targetCalibration/targets.length):0;
    targetTechnicalTotal+=technical;
    calibrationTotal+=calibration;

    const [investment,report,observations,opinions]=await Promise.all([
      db.prepare("SELECT overall_score,coverage_percent,confidence_percent,critical_risk,evaluation_status FROM ci_investment_evaluations WHERE discovery_key=? AND evaluated_at<=? ORDER BY evaluated_at DESC LIMIT 1").bind(prediction.discovery_key,prediction.locked_at).first(),
      db.prepare("SELECT coverage_percent,confidence_percent,report_status FROM ci_investigation_reports WHERE discovery_key=? AND updated_at<=? ORDER BY report_version DESC LIMIT 1").bind(prediction.discovery_key,prediction.locked_at).first(),
      db.prepare("SELECT price_usd,liquidity_usd,volume_24h_usd,buys_24h,sells_24h,observed_at FROM ci_conan_prediction_observations WHERE cycle_id=? AND discovery_key=? AND observed_at>=? ORDER BY observed_at ASC").bind(cycle.cycle_id,prediction.discovery_key,prediction.locked_at).all(),
      db.prepare("SELECT role,status,opinion_json,error_message FROM ci_conan_prediction_opinions WHERE prediction_id=?").bind(prediction.prediction_id).all()
    ]);
    const evalScore=investment?conanClamp(investment.overall_score):0;
    const evalCoverage=investment?conanClamp(investment.coverage_percent):0;
    const reportCoverage=report?conanClamp(report.coverage_percent):0;
    const project=investment?20*(evalScore/100)*((0.7*evalCoverage+0.3*reportCoverage)/100):0;
    projectTotal+=project;

    const samples=observations.results||[];
    const hasLiquidity=samples.some(item=>radarFiniteMetric(item.liquidity_usd)!==null);
    const hasVolume=samples.some(item=>radarFiniteMetric(item.volume_24h_usd)!==null);
    const hasBuys=samples.some(item=>radarFiniteMetric(item.buys_24h)!==null);
    const hasSells=samples.some(item=>radarFiniteMetric(item.sells_24h)!==null);
    const activityCoverage=[hasLiquidity,hasVolume,hasBuys,hasSells].filter(Boolean).length/4;
    const latestSample=samples[samples.length-1]||{};
    const transactionCount=Math.max(0,Number(latestSample.buys_24h)||0)+Math.max(0,Number(latestSample.sells_24h)||0);
    const transactionActivity=Math.min(1,Math.log1p(transactionCount)/Math.log(101));
    const persistence=Math.min(1,samples.length/3);
    const activity=5*activityCoverage+5*transactionActivity+5*persistence;
    activityTotal+=activity;

    const opinionRows=opinions.results||[];
    const securityOpinion=opinionRows.find(item=>item.role==="security"&&item.status==="completed");
    const arbiterOpinion=opinionRows.find(item=>item.role==="arbiter"&&item.status==="completed");
    const risks=conanSafeParse(prediction.risks_json,[]);
    const opinionPayloads=opinionRows.map(item=>conanSafeParse(item.opinion_json,{}));
    const criticalRisk=Number(investment?.critical_risk)===1||conanHasCriticalRisk(risks)||opinionPayloads.some(item=>conanHasCriticalRisk(item));
    const invalidation=radarFiniteMetric(prediction.invalidation_price_usd)!==null;
    const riskRegister=Array.isArray(risks)&&risks.length>0;
    let riskManagement=criticalRisk?0:
      (invalidation?5:0)+(riskRegister?3:0)+(securityOpinion?3:0)+(arbiterOpinion?2:0)+(!criticalRisk?2:0);
    riskManagement=conanClamp(riskManagement,0,15);
    riskTotal+=riskManagement;
    assetEvidence.push({
      prediction_id:prediction.prediction_id,discovery_key:prediction.discovery_key,
      direction_correct:Number(result.direction_correct)===1,
      target_count:targets.length,target_attainment_score:technical,probability_calibration_score:calibration,
      investment_evaluation_available:Boolean(investment),investment_score:investment?evalScore:null,
      investment_coverage_percent:investment?evalCoverage:null,investigation_coverage_percent:report?reportCoverage:null,
      market_observation_count:samples.length,transaction_count:transactionCount,
      market_activity_score:activity,security_opinion_available:Boolean(securityOpinion),
      arbiter_opinion_available:Boolean(arbiterOpinion),invalidation_defined:invalidation,
      risk_register_present:riskRegister,critical_risk_detected:criticalRisk,risk_management_score:riskManagement
    });
  }
  const count=evaluated.length;
  const directionScore=25*directionCorrect/count;
  const targetsTechnicalScore=targetTechnicalTotal/count;
  const probabilityCalibrationScore=calibrationTotal/count;
  const projectQualityScore=projectTotal/count;
  const marketActivityScore=activityTotal/count;
  const riskManagementScore=riskTotal/count;
  const total=conanClamp(directionScore+targetsTechnicalScore+probabilityCalibrationScore+projectQualityScore+marketActivityScore+riskManagementScore,0,100);
  const components={
    weights:CONAN_SCORE_WEIGHTS,
    prediction_quality:{score:directionScore+targetsTechnicalScore+probabilityCalibrationScore,max:50,formula:"Sous-score prédiction = direction /25 + précision technique des cibles /15 + calibration des probabilités /10."},
    direction:{score:directionScore,max:25,correct:directionCorrect,evaluated:count,formula:"25 × directions correctes / prédictions évaluées"},
    target_technical:{score:targetsTechnicalScore,max:15,formula:"Par cible : 1 si maintenue une heure, 0.5 si seulement touchée, 0 sinon; moyenne par prédiction puis moyenne du cycle."},
    probability_calibration:{score:probabilityCalibrationScore,max:10,formula:"10 × (1 − Brier moyen); événement cible = cible touchée, probabilité exprimée entre 0 et 1."},
    project_quality:{score:projectQualityScore,max:20,formula:"20 × score investissement/100 × (70 % couverture évaluation + 30 % couverture dossier)/100; données absentes = 0 et signalées."},
    market_activity:{score:marketActivityScore,max:15,formula:"5 points couverture liquidité/volume/achats/ventes + 5 activité transactionnelle logarithmique plafonnée à 100 transactions + 5 persistance plafonnée à 3 observations."},
    risk_management:{score:riskManagementScore,max:15,formula:"5 invalidation définie + 3 registre de risques + 3 avis sécurité + 2 avis arbitre + 2 absence de veto critique; risque critique détecté = 0 pour cette prédiction."},
    evaluated_predictions:count,unverifiable_predictions:unverifiable,asset_evidence:assetEvidence,
    missing_data_policy:"Les données absentes ne sont pas inventées et ne rapportent aucun point dans leur composante.",
    target_calibration_note:"La calibration est une mesure Brier descriptive sur les cibles touchées; elle ne prouve pas la qualité statistique à faible échantillon.",
    methodology_version:CONAN_SCORE_METHODOLOGY
  };
  await db.prepare("INSERT OR IGNORE INTO ci_conan_score_history (score_id,cycle_id,score_total,direction_score,targets_technical_score,probability_calibration_score,project_quality_score,market_activity_score,risk_management_score,evaluated_predictions,unverifiable_predictions,methodology_version,components_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(
    cryptoRandomId(),cycle.cycle_id,total,directionScore,targetsTechnicalScore,probabilityCalibrationScore,projectQualityScore,marketActivityScore,riskManagementScore,count,unverifiable,CONAN_SCORE_METHODOLOGY,JSON.stringify(components),nowISO()
  ).run();
  return {score_total:total,score_status:"calculated",components:{
    direction:directionScore,targets_technical:targetsTechnicalScore,probability_calibration:probabilityCalibrationScore,
    project_quality:projectQualityScore,market_activity:marketActivityScore,risk_management:riskManagementScore
  },prediction_quality_score:directionScore+targetsTechnicalScore+probabilityCalibrationScore,evaluated_predictions:count,unverifiable_predictions:unverifiable,methodology_version:CONAN_SCORE_METHODOLOGY};
}

async function evaluateConanPredictionCycle(db,cycle){
  const predictions=await db.prepare("SELECT * FROM ci_conan_predictions WHERE cycle_id=? ORDER BY locked_at ASC").bind(cycle.cycle_id).all();
  const evaluated=[];
  for(const prediction of predictions.results||[]){
    const exists=await db.prepare("SELECT result_id FROM ci_conan_prediction_results WHERE prediction_id=?").bind(prediction.prediction_id).first();
    if(exists)continue;
    const observations=await db.prepare("SELECT price_usd,observed_at,source FROM ci_conan_prediction_observations WHERE cycle_id=? AND discovery_key=? AND observed_at>=? AND price_usd>0 ORDER BY observed_at ASC").bind(cycle.cycle_id,prediction.discovery_key,prediction.locked_at).all();
    const samples=observations.results||[],final=samples.length?samples[samples.length-1]:null;
    if(!final){
      await db.prepare("INSERT INTO ci_conan_prediction_results (result_id,prediction_id,cycle_id,discovery_key,outcome_status,direction_correct,reference_price_usd,final_price_usd,direction_change_percent,targets_touched_json,targets_held_1h_json,learning_notes_json,evaluated_at) VALUES (?,?,?,?, 'unverifiable',NULL,?,NULL,NULL,'[]','[]',?,?)").bind(
        cryptoRandomId(),prediction.prediction_id,cycle.cycle_id,prediction.discovery_key,prediction.reference_price_usd,JSON.stringify({reason:"Aucun prix source exploitable après verrouillage."}),nowISO()
      ).run();
      evaluated.push({prediction_id:prediction.prediction_id,status:"unverifiable"});continue;
    }
    const change=(Number(final.price_usd)-Number(prediction.reference_price_usd))/Number(prediction.reference_price_usd)*100;
    const directionCorrect=prediction.direction==="up"?(change>0?1:0):prediction.direction==="down"?(change<0?1:0):(Math.abs(change)<=3?1:0);
    const progress=await db.prepare("SELECT targets_progress_json FROM ci_conan_prediction_progress WHERE prediction_id=?").bind(prediction.prediction_id).first();
    let targets=[];try{targets=JSON.parse(progress?.targets_progress_json||"[]");}catch{targets=[];}
    const touched=targets.filter(item=>item.touched_at).map(item=>({target_index:item.target_index,price_usd:item.price_usd,touched_at:item.touched_at}));
    const held=targets.filter(item=>item.held_1h_at).map(item=>({target_index:item.target_index,price_usd:item.price_usd,held_1h_at:item.held_1h_at,verification_method:item.verification_method}));
    const notes={direction_rule:"Comparaison entre le prix de référence verrouillé et le dernier prix observé au jour 15.",sideways_rule:"Variation absolue de 3 % ou moins.",target_rule:"Contact distinct de la confirmation : toutes les observations enregistrées doivent rester favorables pendant au moins une heure, avec un intervalle maximal de 30 minutes; les périodes non échantillonnées ne sont pas prouvées.",observations_after_lock:samples.length,first_observation:samples[0]?.observed_at||null,final_observation:final.observed_at,final_source:final.source,direction_change_percent:change,direction_correct:directionCorrect===1};
    await db.prepare("INSERT INTO ci_conan_prediction_results (result_id,prediction_id,cycle_id,discovery_key,outcome_status,direction_correct,reference_price_usd,final_price_usd,direction_change_percent,targets_touched_json,targets_held_1h_json,learning_notes_json,evaluated_at) VALUES (?,?,?,?, 'evaluated',?,?,?,?,?,?,?,?)").bind(
      cryptoRandomId(),prediction.prediction_id,cycle.cycle_id,prediction.discovery_key,directionCorrect,prediction.reference_price_usd,final.price_usd,change,JSON.stringify(touched),JSON.stringify(held),JSON.stringify(notes),nowISO()
    ).run();
    evaluated.push({prediction_id:prediction.prediction_id,status:"evaluated",direction_correct:directionCorrect===1,change_percent:change,targets_touched:touched.length,targets_held_1h:held.length});
  }
  const rows=await db.prepare("SELECT outcome_status,direction_correct FROM ci_conan_prediction_results WHERE cycle_id=?").bind(cycle.cycle_id).all();
  const valid=(rows.results||[]).filter(item=>item.outcome_status==="evaluated"),correct=valid.filter(item=>Number(item.direction_correct)===1).length;
  const assetCount=await db.prepare("SELECT COUNT(*) AS count FROM ci_conan_prediction_assets WHERE cycle_id=?").bind(cycle.cycle_id).first();
  const predictionCount=await db.prepare("SELECT COUNT(*) AS count FROM ci_conan_predictions WHERE cycle_id=?").bind(cycle.cycle_id).first();
  const summary={selected_assets:Number(assetCount?.count||0),locked_predictions:Number(predictionCount?.count||0),assets_without_locked_prediction:Math.max(0,Number(assetCount?.count||0)-Number(predictionCount?.count||0)),evaluated_predictions:valid.length,unverifiable_predictions:(rows.results||[]).filter(item=>item.outcome_status==="unverifiable").length,direction_correct:correct,direction_accuracy_percent:valid.length?correct/valid.length*100:null,formal_conan_score:"Calculé selon la pondération officielle au chapitre 9; non anticipé ici."};
  const conanScore=await calculateAndPersistConanScore(db,cycle);
  summary.conan_score=conanScore.score_total;
  summary.conan_score_status=conanScore.score_status;
  summary.conan_score_components=conanScore.components||null;
  summary.conan_score_methodology=CONAN_SCORE_METHODOLOGY;
  const timestamp=nowISO();
  await db.prepare("INSERT INTO ci_conan_learning_history (learning_id,cycle_id,learning_type,summary,evidence_json,created_at) VALUES (?,?,?,?,?,?)").bind(
    cryptoRandomId(),cycle.cycle_id,"cycle_evaluation","Évaluation du cycle de 15 jours : résultats, erreurs, cibles touchées et cibles maintenues.",JSON.stringify(summary),timestamp
  ).run();
  await db.prepare("UPDATE ci_conan_prediction_cycles SET status='completed',current_day=15,updated_at=?,completed_at=? WHERE cycle_id=?").bind(timestamp,timestamp,cycle.cycle_id).run();
  await audit(db,"conan_prediction_cycle_completed","Cycle "+cycle.cycle_id+" évalué : "+valid.length+" prévisions vérifiables, "+correct+" directions correctes.");
  await audit(db,"conan_prediction_score_calculated","Score Conan du cycle "+cycle.cycle_id+" : "+(conanScore.score_total===null?"non calculable":conanScore.score_total+"/100")+".");
  return {status:"completed",cycle_id:cycle.cycle_id,summary,evaluated};
}


/* CHAPITRE 10 — MATURITÉ DE CONAN ET DÉBLOCAGES PROGRESSIFS */
const CONAN_GROWTH_METHODOLOGY = "conan-growth-first10-first100-v1";
const conanChapter10OriginalEnsureTables = ensureConanPredictionTables;
ensureConanPredictionTables = async function(db){
  await conanChapter10OriginalEnsureTables(db);
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_growth_state (
      state_id TEXT PRIMARY KEY,
      maturity_stage TEXT NOT NULL DEFAULT 'child',
      verified_evaluated_predictions INTEGER NOT NULL DEFAULT 0,
      verified_correct_predictions INTEGER NOT NULL DEFAULT 0,
      first_ten_evaluated INTEGER NOT NULL DEFAULT 0,
      first_ten_correct INTEGER NOT NULL DEFAULT 0,
      first_hundred_evaluated INTEGER NOT NULL DEFAULT 0,
      first_hundred_correct INTEGER NOT NULL DEFAULT 0,
      active_asset_slots INTEGER NOT NULL DEFAULT 2,
      extra_surveillance_windows INTEGER NOT NULL DEFAULT 0,
      methodology_version TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_growth_history (
      event_id TEXT PRIMARY KEY,
      from_stage TEXT,
      to_stage TEXT NOT NULL,
      evaluated_predictions INTEGER NOT NULL,
      correct_predictions INTEGER NOT NULL,
      threshold_json TEXT NOT NULL,
      evidence_json TEXT NOT NULL,
      methodology_version TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_growth_history_created ON ci_conan_growth_history(created_at DESC)"),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_surveillance_windows (
      window_id TEXT PRIMARY KEY,
      window_number INTEGER NOT NULL,
      unlock_stage TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'unassigned',
      discovery_key TEXT,
      chain_id TEXT,
      contract_address TEXT,
      token_symbol TEXT,
      unlocked_at TEXT NOT NULL,
      assigned_at TEXT,
      assignment_evidence_json TEXT NOT NULL DEFAULT '{}'
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_surveillance_windows_status ON ci_conan_surveillance_windows(status,window_number)")
  ]);
  await db.prepare("INSERT OR IGNORE INTO ci_conan_growth_state (state_id,maturity_stage,active_asset_slots,extra_surveillance_windows,methodology_version,updated_at) VALUES ('primary','child',2,0,?,?)").bind(CONAN_GROWTH_METHODOLOGY,nowISO()).run();
};

async function getConanGrowthState(db){
  await ensureConanPredictionTables(db);
  return await db.prepare("SELECT * FROM ci_conan_growth_state WHERE state_id='primary'").first();
}

async function updateConanGrowthAfterEvaluation(db,cycleId){
  const all=await db.prepare("SELECT p.prediction_id,r.direction_correct,r.evaluated_at FROM ci_conan_predictions p JOIN ci_conan_prediction_results r ON r.prediction_id=p.prediction_id WHERE r.outcome_status='evaluated' AND r.direction_correct IS NOT NULL ORDER BY r.evaluated_at ASC,p.locked_at ASC LIMIT 100").all();
  const evaluated=all.results||[];
  const firstTen=evaluated.slice(0,10),firstHundred=evaluated.slice(0,100);
  const correctTen=firstTen.filter(item=>Number(item.direction_correct)===1).length;
  const correctHundred=firstHundred.filter(item=>Number(item.direction_correct)===1).length;
  const state=await db.prepare("SELECT * FROM ci_conan_growth_state WHERE state_id='primary'").first();
  const currentStage=state?.maturity_stage||"child";
  let nextStage=currentStage,assetSlots=Number(state?.active_asset_slots)||2,extraWindows=Number(state?.extra_surveillance_windows)||0;
  if(currentStage==="child"&&firstTen.length>=10&&correctTen>=7){
    nextStage="adolescent";extraWindows=1;
  }
  if((currentStage==="adolescent"||nextStage==="adolescent")&&firstHundred.length>=100&&correctHundred>=70){
    nextStage="adult";assetSlots=4;
  }
  const timestamp=nowISO();
  await db.prepare("UPDATE ci_conan_growth_state SET maturity_stage=?,verified_evaluated_predictions=?,verified_correct_predictions=?,first_ten_evaluated=?,first_ten_correct=?,first_hundred_evaluated=?,first_hundred_correct=?,active_asset_slots=?,extra_surveillance_windows=?,methodology_version=?,updated_at=? WHERE state_id='primary'").bind(
    nextStage,evaluated.length,evaluated.filter(item=>Number(item.direction_correct)===1).length,firstTen.length,correctTen,firstHundred.length,correctHundred,assetSlots,extraWindows,CONAN_GROWTH_METHODOLOGY,timestamp
  ).run();
  if(nextStage!==currentStage){
    const thresholds={
      child_to_adolescent:{required_evaluated:10,required_correct:7,minimum_accuracy_percent:70,unlock:"one extra surveillance window initially empty"},
      adolescent_to_adult:{required_evaluated:100,required_correct:70,minimum_accuracy_percent:70,unlock:"four assets processed in deterministic sequential order per cycle"}
    };
    const transition=nextStage==="adolescent"?"child_to_adolescent":"adolescent_to_adult";
    await db.prepare("INSERT INTO ci_conan_growth_history (event_id,from_stage,to_stage,evaluated_predictions,correct_predictions,threshold_json,evidence_json,methodology_version,created_at) VALUES (?,?,?,?,?,?,?,?,?)").bind(
      cryptoRandomId(),currentStage,nextStage,nextStage==="adolescent"?firstTen.length:firstHundred.length,nextStage==="adolescent"?correctTen:correctHundred,
      JSON.stringify(thresholds[transition]),JSON.stringify({cycle_id:cycleId,first_ten:{evaluated:firstTen.length,correct:correctTen},first_hundred:{evaluated:firstHundred.length,correct:correctHundred},counting_rule:"Seules les prédictions avec outcome_status=evaluated et direction_correct non nul comptent; les résultats unverifiable sont exclus.",asset_slots:assetSlots,extra_surveillance_windows:extraWindows}),
      CONAN_GROWTH_METHODOLOGY,timestamp
    ).run();
    if(nextStage==="adolescent"){
      await db.prepare("INSERT OR IGNORE INTO ci_conan_surveillance_windows (window_id,window_number,unlock_stage,status,discovery_key,unlocked_at,assignment_evidence_json) VALUES (?,1,'adolescent','unassigned',NULL,?,'{}')").bind(cryptoRandomId(),timestamp).run();
    }
    await db.prepare("INSERT INTO ci_conan_learning_history (learning_id,cycle_id,learning_type,summary,evidence_json,created_at) VALUES (?,?,?,?,?,?)").bind(
      cryptoRandomId(),cycleId,"growth_stage_unlocked","Conan passe de "+currentStage+" à "+nextStage+" après validation de ses prédictions.",JSON.stringify({first_ten:{evaluated:firstTen.length,correct:correctTen},first_hundred:{evaluated:firstHundred.length,correct:correctHundred},active_asset_slots:assetSlots,extra_surveillance_windows:extraWindows,methodology:CONAN_GROWTH_METHODOLOGY}),timestamp
    ).run();
    await audit(db,"conan_growth_stage_unlocked","Conan passe de "+currentStage+" à "+nextStage+"; "+(nextStage==="adolescent"?"une fenêtre de surveillance supplémentaire est débloquée, vide.":"quatre actifs seront traités séquentiellement."));
  }
  return {maturity_stage:nextStage,previous_stage:currentStage,changed:nextStage!==currentStage,verified_evaluated_predictions:evaluated.length,verified_correct_predictions:evaluated.filter(item=>Number(item.direction_correct)===1).length,first_ten:{evaluated:firstTen.length,correct:correctTen,required_correct:7},first_hundred:{evaluated:firstHundred.length,correct:correctHundred,required_correct:70},active_asset_slots:assetSlots,extra_surveillance_windows:extraWindows,methodology_version:CONAN_GROWTH_METHODOLOGY};
}

const conanChapter10OriginalSelectAssets = selectConanCycleAssets;
selectConanCycleAssets = async function(db,requestedCount=2){
  const result=await db.prepare("SELECT d.discovery_key,d.chain_id,d.contract_address,d.token_name,d.token_symbol,m.pair_address,m.price_usd,m.source,m.observed_at,m.liquidity_usd,m.volume_24h_usd FROM ci_radar_discoveries d JOIN ci_radar_pool_metrics m ON m.metric_key=(SELECT pm.metric_key FROM ci_radar_pool_metrics pm WHERE pm.discovery_key=d.discovery_key AND pm.price_usd>0 ORDER BY pm.observed_at DESC LIMIT 1) WHERE m.price_usd>0 ORDER BY RANDOM() LIMIT 100").all();
  const candidates=result.results||[];
  if(candidates.length<requestedCount)return {assets:[],mode:"unavailable",reason:"Il faut "+requestedCount+" actifs distincts avec un prix source exploitable; disponibles : "+candidates.length+"."};
  const historyResult=await db.prepare("SELECT p.discovery_key,AVG(CASE WHEN r.direction_correct=1 THEN 100 WHEN r.direction_correct=0 THEN 0 ELSE NULL END) AS accuracy,COUNT(r.result_id) AS sample_count FROM ci_conan_predictions p JOIN ci_conan_prediction_results r ON r.prediction_id=p.prediction_id WHERE r.outcome_status='evaluated' GROUP BY p.discovery_key").all();
  const history=new Map((historyResult.results||[]).map(row=>[row.discovery_key,{accuracy:radarFiniteMetric(row.accuracy),count:Number(row.sample_count)||0}]));
  const experienced=history.size>0;
  if(!experienced){
    for(let i=candidates.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[candidates[i],candidates[j]]=[candidates[j],candidates[i]];}
  }else{
    candidates.sort((a,b)=>{
      const ah=history.get(a.discovery_key),bh=history.get(b.discovery_key);
      const av=ah?ah.accuracy+Math.min(ah.count,10)*0.25:50;
      const bv=bh?bh.accuracy+Math.min(bh.count,10)*0.25:50;
      return bv-av||(Math.random()-0.5);
    });
  }
  return {assets:candidates.slice(0,requestedCount),mode:experienced?"experience_weighted_with_exploration":"random_initial",reason:experienced?"Sélection pondérée par les résultats antérieurs évalués, avec exploration des actifs sans historique; ordre de surveillance séquentiel conservé.":"Sélection initiale aléatoire parmi les actifs possédant un prix observé; ordre de surveillance séquentiel conservé."};
};

createConanPredictionCycle = async function(db){
  const today=conanUtcDate();
  const completed=await db.prepare("SELECT cycle_id FROM ci_conan_prediction_cycles WHERE status='completed' AND completed_at>=? LIMIT 1").bind(today+"T00:00:00.000Z").first();
  if(completed)return {status:"cycle_completed_today",cycle_id:completed.cycle_id};
  const growth=await getConanGrowthState(db);
  const desiredCount=growth?.maturity_stage==="adult"?4:2;
  const selection=await selectConanCycleAssets(db,desiredCount);
  if(selection.assets.length!==desiredCount)return {status:"waiting_for_assets",required_assets:desiredCount,reason:selection.reason,maturity_stage:growth?.maturity_stage||"child"};
  const id=cryptoRandomId(),timestamp=nowISO(),stage=growth?.maturity_stage||"child";
  await db.prepare("INSERT INTO ci_conan_prediction_cycles (cycle_id,status,cycle_start_date,current_day,selection_mode,learning_stage,methodology_version,created_at,updated_at) VALUES (?,'observing',?,1,?,?,?,?,?)").bind(id,today,selection.mode,stage,CONAN_PREDICTION_METHODOLOGY,timestamp,timestamp).run();
  for(let i=0;i<selection.assets.length;i++){
    const asset=selection.assets[i];
    await db.prepare("INSERT INTO ci_conan_prediction_assets (asset_row_id,cycle_id,asset_order,discovery_key,chain_id,contract_address,token_name,token_symbol,pair_address,selected_at,selection_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?)").bind(
      cryptoRandomId(),id,i+1,asset.discovery_key,asset.chain_id,asset.contract_address,asset.token_name,asset.token_symbol,asset.pair_address,timestamp,selection.reason+" Ordre séquentiel "+(i+1)+"/"+selection.assets.length+"."
    ).run();
    await recordConanPredictionObservation(db,{cycle_id:id},asset,1);
  }
  await db.prepare("INSERT INTO ci_conan_learning_history (learning_id,cycle_id,learning_type,summary,evidence_json,created_at) VALUES (?,?,?,?,?,?)").bind(
    cryptoRandomId(),id,"cycle_started","Début du cycle de 15 jours : "+selection.assets.length+" actifs distincts; observation et traitement dans l'ordre séquentiel.",JSON.stringify({selection_mode:selection.mode,selection_reason:selection.reason,maturity_stage:stage,asset_count:selection.assets.length,monitoring_order:"sequential_by_asset_order",assets:selection.assets.map(item=>({discovery_key:item.discovery_key,chain_id:item.chain_id,contract_address:item.contract_address,pair_address:item.pair_address,price_usd:item.price_usd,source:item.source,observed_at:item.observed_at}))}),timestamp
  ).run();
  await audit(db,"conan_prediction_cycle_started","Cycle "+id+" lancé au stade "+stage+" avec "+selection.assets.length+" actifs traités dans l'ordre séquentiel.");
  return {status:"started",cycle_id:id,cycle_start_date:today,maturity_stage:stage,selection_mode:selection.mode,monitoring_order:"sequential_by_asset_order",assets:selection.assets.map((item,index)=>({order:index+1,discovery_key:item.discovery_key,chain_id:item.chain_id,contract_address:item.contract_address,symbol:item.token_symbol,price_usd:item.price_usd,source:item.source}))};
};

const conanChapter10OriginalEvaluateCycle = evaluateConanPredictionCycle;
evaluateConanPredictionCycle = async function(db,cycle){
  const result=await conanChapter10OriginalEvaluateCycle(db,cycle);
  if(result?.status==="completed"){
    const growth=await updateConanGrowthAfterEvaluation(db,cycle.cycle_id);
    result.growth=growth;
  }
  return result;
};

async function runConanPredictionCycle(db,env){
  try{
    await ensureConanPredictionTables(db);
    let cycle=await db.prepare("SELECT * FROM ci_conan_prediction_cycles WHERE status IN ('observing','tracking') ORDER BY cycle_start_date ASC LIMIT 1").first();
    if(!cycle)return await createConanPredictionCycle(db);
    const today=conanUtcDate(),day=conanCycleDay(cycle.cycle_start_date,today);
    if(day>15)return await evaluateConanPredictionCycle(db,cycle);
    const result=await db.prepare("SELECT * FROM ci_conan_prediction_assets WHERE cycle_id=? ORDER BY asset_order ASC").bind(cycle.cycle_id).all();
    const assets=result.results||[],observations=[];
    for(const asset of assets)observations.push({discovery_key:asset.discovery_key,...await recordConanPredictionObservation(db,cycle,asset,day)});
    if(day<8){
      await db.prepare("UPDATE ci_conan_prediction_cycles SET current_day=?,updated_at=? WHERE cycle_id=?").bind(day,nowISO(),cycle.cycle_id).run();
      return {status:"observing",cycle_id:cycle.cycle_id,day,phase:"observation_days_1_to_7",observations,predictions_locked:0};
    }
    await db.prepare("UPDATE ci_conan_prediction_cycles SET status='tracking',current_day=?,updated_at=? WHERE cycle_id=?").bind(day,nowISO(),cycle.cycle_id).run();
    const configured=Number(env.AI_COUNCIL_DAILY_PROVIDER_CALL_LIMIT),dailyLimit=Number.isFinite(configured)?Math.max(1,Math.min(50,Math.floor(configured))):CONAN_PROVIDER_DAILY_LIMIT_DEFAULT;
    const usage=await getConanProviderUsage(db,new Date(Date.now()-86400000).toISOString()),locks=[];
    for(const asset of assets){
      const existing=await db.prepare("SELECT prediction_id FROM ci_conan_predictions WHERE cycle_id=? AND discovery_key=?").bind(cycle.cycle_id,asset.discovery_key).first();
      if(existing){locks.push({discovery_key:asset.discovery_key,status:"already_locked",prediction_id:existing.prediction_id});continue;}
      if(day!==8){locks.push({discovery_key:asset.discovery_key,status:"not_locked_on_day_8"});continue;}
      const attempt=await db.prepare("SELECT COUNT(*) AS count FROM ci_conan_prediction_opinions WHERE cycle_id=? AND discovery_key=? AND created_at>=?").bind(cycle.cycle_id,asset.discovery_key,today+"T00:00:00.000Z").first();
      if(Number(attempt?.count||0)>0){locks.push({discovery_key:asset.discovery_key,status:"attempted_today_no_duplicate_ai_calls"});continue;}
      const market=await getConanLatestMarket(db,asset.discovery_key);
      locks.push({discovery_key:asset.discovery_key,...await lockConanPredictionForAsset(db,env,cycle,asset,market,usage,dailyLimit)});
    }
    if(day>=15)return {...await evaluateConanPredictionCycle(db,{...cycle,current_day:day,status:"tracking"}),observations,locks};
    return {status:"tracking",cycle_id:cycle.cycle_id,day,phase:"prediction_lock_and_tracking_days_8_to_15",observations,locks};
  }catch(error){
    await audit(db,"conan_prediction_cycle_error",safeString(error.message||"Erreur du cycle Conan.",1000));
    return {status:"error",error:safeString(error.message||"Erreur du cycle Conan.",700)};
  }
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
    const conanTask = task.then(
      () => runConanPredictionCycle(db, env),
      () => runConanPredictionCycle(db, env)
    );
    if (ctx?.waitUntil) ctx.waitUntil(task);
    else await task;
    if (ctx?.waitUntil) ctx.waitUntil(conanTask);
    else await conanTask;
  }
};


/* -------------------------------------------------------------------------- */
/* CHAPITRE 11 — OBSERVATION ADAPTATIVE ET APPRENTISSAGE PROGRESSIF DE CONAN  */
/* -------------------------------------------------------------------------- */
const CONAN_ADAPTIVE_OBSERVATION_METHODOLOGY = "conan-adaptive-observation-7-to-1-v1";
const CONAN_ADAPTIVE_INITIAL_DAYS = 7;
const CONAN_ADAPTIVE_MIN_DAYS = 1;
const CONAN_ADAPTIVE_MAX_DAYS = 7;
const CONAN_ADAPTIVE_FIRST_STEP_WINS = 3;
const CONAN_ADAPTIVE_NEXT_STEP_WINS = 5;
const CONAN_ADAPTIVE_HOLD_ACCURACY_PERCENT = 70;
const CONAN_ADAPTIVE_DECLINE_ACCURACY_PERCENT = 60;
const CONAN_ADAPTIVE_MIN_DECLINE_SAMPLE = 5;

async function ensureConanAdaptiveObservationTables(db){
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_adaptive_observation_state (
      state_id TEXT PRIMARY KEY,
      observation_days INTEGER NOT NULL DEFAULT 7,
      stage_index INTEGER NOT NULL DEFAULT 0,
      consecutive_new_wins INTEGER NOT NULL DEFAULT 0,
      verified_evaluations INTEGER NOT NULL DEFAULT 0,
      verified_wins INTEGER NOT NULL DEFAULT 0,
      last_accuracy_percent REAL,
      last_sample_size INTEGER NOT NULL DEFAULT 0,
      last_processed_at TEXT,
      last_adjustment_reason TEXT,
      methodology_version TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_adaptive_observation_history (
      event_id TEXT PRIMARY KEY,
      previous_days INTEGER NOT NULL,
      new_days INTEGER NOT NULL,
      adjustment_type TEXT NOT NULL,
      trigger_result_id TEXT,
      rolling_accuracy_percent REAL,
      rolling_sample_size INTEGER NOT NULL DEFAULT 0,
      consecutive_new_wins INTEGER NOT NULL DEFAULT 0,
      reason TEXT NOT NULL,
      evidence_json TEXT NOT NULL,
      methodology_version TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_adaptive_history_created ON ci_conan_adaptive_observation_history(created_at DESC)"),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_adaptive_processed_results (
      result_id TEXT PRIMARY KEY,
      processed_at TEXT NOT NULL
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_adaptive_processed_at ON ci_conan_adaptive_processed_results(processed_at DESC)")
  ]);
  const timestamp=nowISO();
  await db.prepare("INSERT OR IGNORE INTO ci_conan_adaptive_observation_state (state_id,observation_days,stage_index,consecutive_new_wins,verified_evaluations,verified_wins,methodology_version,updated_at) VALUES ('primary',7,0,0,0,0,?,?)").bind(CONAN_ADAPTIVE_OBSERVATION_METHODOLOGY,timestamp).run();
  /* Les résultats antérieurs au chapitre 11 constituent l'historique de départ,
     pas de nouvelles victoires acquises sous cette politique adaptative. */
  await db.prepare("INSERT OR IGNORE INTO ci_conan_adaptive_processed_results (result_id,processed_at) SELECT result_id,? FROM ci_conan_prediction_results").bind(timestamp).run();
  if(Array.isArray(ARCHIVE_TABLES)){
    for(const table of ["ci_conan_adaptive_observation_state","ci_conan_adaptive_observation_history","ci_conan_adaptive_processed_results"]){
      if(!ARCHIVE_TABLES.includes(table))ARCHIVE_TABLES.push(table);
    }
  }
}

async function getConanAdaptiveObservationState(db){
  await ensureConanAdaptiveObservationTables(db);
  const state=await db.prepare("SELECT * FROM ci_conan_adaptive_observation_state WHERE state_id='primary'").first();
  return {
    ...state,
    policy:"7 jours au départ; 3 nouvelles victoires vérifiées pour passer à 6 jours; puis 5 nouvelles victoires vérifiées par palier jusqu'à 1 jour.",
    hold_accuracy_percent:CONAN_ADAPTIVE_HOLD_ACCURACY_PERCENT,
    decline_accuracy_percent:CONAN_ADAPTIVE_DECLINE_ACCURACY_PERCENT,
    decline_minimum_sample:CONAN_ADAPTIVE_MIN_DECLINE_SAMPLE,
    observation_days:Number(state?.observation_days)||CONAN_ADAPTIVE_INITIAL_DAYS,
    next_step_required_wins:Number(state?.stage_index)===0?CONAN_ADAPTIVE_FIRST_STEP_WINS:CONAN_ADAPTIVE_NEXT_STEP_WINS
  };
}

async function processConanAdaptiveObservationResults(db){
  await ensureConanAdaptiveObservationTables(db);
  let state=await db.prepare("SELECT * FROM ci_conan_adaptive_observation_state WHERE state_id='primary'").first();
  const pending=await db.prepare("SELECT r.result_id,r.direction_correct,r.evaluated_at,r.cycle_id,r.prediction_id FROM ci_conan_prediction_results r LEFT JOIN ci_conan_adaptive_processed_results p ON p.result_id=r.result_id WHERE p.result_id IS NULL AND r.outcome_status='evaluated' AND r.direction_correct IS NOT NULL ORDER BY r.evaluated_at ASC,r.result_id ASC LIMIT 500").all();
  const rows=pending.results||[];
  const changes=[];
  for(const item of rows){
    const timestamp=nowISO();
    await db.prepare("INSERT OR IGNORE INTO ci_conan_adaptive_processed_results (result_id,processed_at) VALUES (?,?)").bind(item.result_id,timestamp).run();
    const rolling=await db.prepare("SELECT r.direction_correct FROM ci_conan_prediction_results r WHERE r.outcome_status='evaluated' AND r.direction_correct IS NOT NULL ORDER BY r.evaluated_at DESC,r.result_id DESC LIMIT 10").all();
    const sample=rolling.results||[];
    const wins=sample.filter(row=>Number(row.direction_correct)===1).length;
    const accuracy=sample.length?wins/sample.length*100:null;
    let days=Number(state.observation_days)||7;
    let stage=Number(state.stage_index)||0;
    let consecutive=Number(state.consecutive_new_wins)||0;
    let adjustment=null,reason=null;
    if(sample.length>=CONAN_ADAPTIVE_MIN_DECLINE_SAMPLE&&accuracy<CONAN_ADAPTIVE_DECLINE_ACCURACY_PERCENT&&days<CONAN_ADAPTIVE_MAX_DAYS){
      const previous=days;
      days=Math.min(CONAN_ADAPTIVE_MAX_DAYS,days+1);
      stage=Math.max(0,7-days);
      consecutive=0;
      adjustment="extended_after_accuracy_decline";
      reason="La précision glissante est passée sous 60% sur au moins cinq prédictions vérifiables; la période est rallongée d'un jour et la progression est réinitialisée.";
      await db.prepare("INSERT INTO ci_conan_adaptive_observation_history (event_id,previous_days,new_days,adjustment_type,trigger_result_id,rolling_accuracy_percent,rolling_sample_size,consecutive_new_wins,reason,evidence_json,methodology_version,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)").bind(
        cryptoRandomId(),previous,days,adjustment,item.result_id,accuracy,sample.length,consecutive,reason,
        JSON.stringify({cycle_id:item.cycle_id,prediction_id:item.prediction_id,verified_result_id:item.result_id,rolling_wins:wins,rolling_evaluations:sample.length,threshold_percent:CONAN_ADAPTIVE_DECLINE_ACCURACY_PERCENT}),
        CONAN_ADAPTIVE_OBSERVATION_METHODOLOGY,timestamp
      ).run();
      changes.push({result_id:item.result_id,previous_days:previous,observation_days:days,adjustment,accuracy_percent:accuracy});
    }else if(Number(item.direction_correct)===1){
      consecutive+=1;
      const required=stage===0?CONAN_ADAPTIVE_FIRST_STEP_WINS:CONAN_ADAPTIVE_NEXT_STEP_WINS;
      const minimumSample=stage===0?3:5;
      if(consecutive>=required&&sample.length>=minimumSample&&accuracy!==null&&accuracy>=CONAN_ADAPTIVE_HOLD_ACCURACY_PERCENT&&days>CONAN_ADAPTIVE_MIN_DAYS){
        const previous=days;
        days=Math.max(CONAN_ADAPTIVE_MIN_DAYS,days-1);
        stage=Math.max(0,7-days);
        consecutive=0;
        adjustment="shortened_after_verified_wins";
        reason="Seuil de nouvelles victoires vérifiées atteint et précision glissante maintenue à au moins 70%; réduction d'un jour.";
        await db.prepare("INSERT INTO ci_conan_adaptive_observation_history (event_id,previous_days,new_days,adjustment_type,trigger_result_id,rolling_accuracy_percent,rolling_sample_size,consecutive_new_wins,reason,evidence_json,methodology_version,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)").bind(
          cryptoRandomId(),previous,days,adjustment,item.result_id,accuracy,sample.length,consecutive,reason,
          JSON.stringify({cycle_id:item.cycle_id,prediction_id:item.prediction_id,verified_result_id:item.result_id,rolling_wins:wins,rolling_evaluations:sample.length,required_new_wins:required,minimum_sample:minimumSample,hold_accuracy_percent:CONAN_ADAPTIVE_HOLD_ACCURACY_PERCENT}),
          CONAN_ADAPTIVE_OBSERVATION_METHODOLOGY,timestamp
        ).run();
        changes.push({result_id:item.result_id,previous_days:previous,observation_days:days,adjustment,accuracy_percent:accuracy});
      }
    }
    const totals=await db.prepare("SELECT COUNT(*) AS evaluated,SUM(CASE WHEN direction_correct=1 THEN 1 ELSE 0 END) AS wins FROM ci_conan_prediction_results WHERE outcome_status='evaluated' AND direction_correct IS NOT NULL").first();
    await db.prepare("UPDATE ci_conan_adaptive_observation_state SET observation_days=?,stage_index=?,consecutive_new_wins=?,verified_evaluations=?,verified_wins=?,last_accuracy_percent=?,last_sample_size=?,last_processed_at=?,last_adjustment_reason=?,methodology_version=?,updated_at=? WHERE state_id='primary'").bind(
      days,stage,consecutive,Number(totals?.evaluated)||0,Number(totals?.wins)||0,accuracy,sample.length,timestamp,reason||state.last_adjustment_reason||null,CONAN_ADAPTIVE_OBSERVATION_METHODOLOGY,timestamp
    ).run();
    state={...state,observation_days:days,stage_index:stage,consecutive_new_wins:consecutive,verified_evaluations:Number(totals?.evaluated)||0,verified_wins:Number(totals?.wins)||0,last_accuracy_percent:accuracy,last_sample_size:sample.length,last_processed_at:timestamp,last_adjustment_reason:reason||state.last_adjustment_reason||null};
  }
  return {state:await getConanAdaptiveObservationState(db),processed_results:rows.length,changes};
}

async function getConanAdaptiveObservationHistory(db,limit=100){
  await ensureConanAdaptiveObservationTables(db);
  const result=await db.prepare("SELECT * FROM ci_conan_adaptive_observation_history ORDER BY created_at DESC LIMIT ?").bind(Math.max(1,Math.min(500,Number(limit)||100))).all();
  return result.results||[];
}

const conanChapter11OriginalRunCycle = runConanPredictionCycle;
runConanPredictionCycle = async function(db,env){
  const result=await conanChapter11OriginalRunCycle(db,env);
  try{
    const adaptive=await processConanAdaptiveObservationResults(db);
    return {...(result&&typeof result==="object"?result:{result}),adaptive_observation:{observation_days:adaptive.state.observation_days,consecutive_new_wins:adaptive.state.consecutive_new_wins,last_accuracy_percent:adaptive.state.last_accuracy_percent,processed_results:adaptive.processed_results,changes:adaptive.changes}};
  }catch(error){
    await audit(db,"conan_adaptive_observation_error",safeString(error.message||"Erreur du moteur d'observation adaptative.",700));
    return {...(result&&typeof result==="object"?result:{result}),adaptive_observation:{status:"error",message:safeString(error.message||"Erreur adaptative.",500)}};
  }
};

const conanChapter11OriginalProtectedRoutes = handleProtectedRoutes;
handleProtectedRoutes = async function(request,env,ctx,route){
  const {path,method,url}=route;
  if(method==="GET"&&path==="/api/conan/adaptive-observation"){
    const db=getDB(env);
    await initializeBackendTables(db);
    const state=await getConanAdaptiveObservationState(db);
    return json({success:true,methodology:CONAN_ADAPTIVE_OBSERVATION_METHODOLOGY,state,policy:{initial_days:7,minimum_days:1,maximum_days:7,first_reduction_after_new_verified_wins:3,subsequent_reductions_after_new_verified_wins:5,hold_accuracy_percent:70,accuracy_decline_percent:60,accuracy_decline_minimum_sample:5,unverifiable_results_count:false},note:"Cette politique adaptative conserve le cycle de prédiction de 15 jours du chapitre 8; elle expose et historise le palier d'observation distinct sans modifier rétroactivement les cycles déjà créés."});
  }
  if(method==="GET"&&path==="/api/conan/adaptive-observation/history"){
    const db=getDB(env);
    await initializeBackendTables(db);
    const history=await getConanAdaptiveObservationHistory(db,url.searchParams.get("limit"));
    return json({success:true,count:history.length,history});
  }
  return await conanChapter11OriginalProtectedRoutes(request,env,ctx,route);
};


/* -------------------------------------------------------------------------- */
/* CHAPITRE 12 — INCUBATEUR D'APPRENTISSAGE ET D'EVOLUTION TECHNIQUE CONAN    */
/* -------------------------------------------------------------------------- */
const CONAN_INCUBATOR_METHODOLOGY = "conan-autonomous-research-incubator-v1";
const CONAN_INCUBATOR_ALLOWED_TOOL_STATUSES = ["proposed","prototype","tested","suspended","rejected"];
const CONAN_INCUBATOR_ALLOWED_EXPERIMENT_STATUSES = ["proposed","running","completed","failed","suspended"];

async function ensureConanIncubatorTables(db){
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_incubator_state (
      state_id TEXT PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'active',
      generation INTEGER NOT NULL DEFAULT 1,
      last_backup_id TEXT,
      suspended_at TEXT,
      updated_at TEXT NOT NULL,
      state_json TEXT NOT NULL DEFAULT '{}'
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_incubator_tools (
      tool_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      purpose TEXT NOT NULL,
      design_json TEXT NOT NULL,
      status TEXT NOT NULL,
      evidence_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_incubator_experiments (
      experiment_id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      hypothesis TEXT NOT NULL,
      strategy_key TEXT NOT NULL,
      status TEXT NOT NULL,
      dataset_fingerprint TEXT,
      dataset_size INTEGER NOT NULL DEFAULT 0,
      results_json TEXT NOT NULL DEFAULT '{}',
      limitations_json TEXT NOT NULL DEFAULT '[]',
      created_at TEXT NOT NULL,
      completed_at TEXT
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_incubator_observations (
      observation_id TEXT PRIMARY KEY,
      experiment_id TEXT NOT NULL,
      observation_index INTEGER NOT NULL,
      observed_at TEXT,
      value_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_improvement_proposals (
      proposal_id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      problem TEXT NOT NULL,
      proposed_change TEXT NOT NULL,
      expected_benefit TEXT,
      risks_json TEXT NOT NULL DEFAULT '[]',
      evidence_json TEXT NOT NULL DEFAULT '{}',
      status TEXT NOT NULL DEFAULT 'pending_review',
      reviewed_at TEXT,
      reviewer_note TEXT,
      created_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_incubator_events (
      event_id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      entity_id TEXT,
      details_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_incubator_backups (
      backup_id TEXT PRIMARY KEY,
      generation INTEGER NOT NULL,
      snapshot_json TEXT NOT NULL,
      checksum TEXT NOT NULL,
      verified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_incubator_tools_status ON ci_conan_incubator_tools(status,updated_at DESC)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_incubator_experiments_status ON ci_conan_incubator_experiments(status,created_at DESC)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_incubator_proposals_status ON ci_conan_improvement_proposals(status,created_at DESC)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_incubator_events_created ON ci_conan_incubator_events(created_at DESC)")
  ]);
  const timestamp=nowISO();
  await db.prepare("INSERT OR IGNORE INTO ci_conan_incubator_state (state_id,status,generation,updated_at,state_json) VALUES ('primary','active',1,?,'{}')").bind(timestamp).run();
  for(const table of ["ci_conan_incubator_state","ci_conan_incubator_tools","ci_conan_incubator_experiments","ci_conan_incubator_observations","ci_conan_improvement_proposals","ci_conan_incubator_events","ci_conan_incubator_backups"]){
    if(!ARCHIVE_TABLES.includes(table))ARCHIVE_TABLES.push(table);
  }
}

async function recordConanIncubatorEvent(db,eventType,entityId,details){
  await db.prepare("INSERT INTO ci_conan_incubator_events (event_id,event_type,entity_id,details_json,created_at) VALUES (?,?,?,?,?)").bind(
    cryptoRandomId(),safeString(eventType,100),entityId?safeString(entityId,160):null,JSON.stringify(details||{}),nowISO()
  ).run();
}

async function getConanIncubatorState(db){
  await ensureConanIncubatorTables(db);
  const state=await db.prepare("SELECT * FROM ci_conan_incubator_state WHERE state_id='primary'").first();
  const counts=await db.prepare("SELECT (SELECT COUNT(*) FROM ci_conan_incubator_tools) AS tools,(SELECT COUNT(*) FROM ci_conan_incubator_experiments) AS experiments,(SELECT COUNT(*) FROM ci_conan_improvement_proposals WHERE status='pending_review') AS pending_proposals").first();
  return { ...state,counts,permissions:{may_design_tools:true,may_run_isolated_experiments:true,may_read_available_historical_data:true,may_propose_code_changes:true,may_modify_main_code:false,may_delete_protections:false,may_change_permissions:false,may_delete_backups:false,may_purchase_paid_services:false} };
}

async function createConanIncubatorBackup(db){
  await ensureConanIncubatorTables(db);
  const names=["ci_conan_incubator_state","ci_conan_incubator_tools","ci_conan_incubator_experiments","ci_conan_incubator_observations","ci_conan_improvement_proposals","ci_conan_incubator_events"];
  const snapshot={schema:CONAN_INCUBATOR_METHODOLOGY,tables:{}};
  for(const name of names){
    const result=await db.prepare("SELECT * FROM "+name).all();
    snapshot.tables[name]=result.results||[];
  }
  const serialized=JSON.stringify(snapshot);
  let checksum=0;
  for(let i=0;i<serialized.length;i++)checksum=(Math.imul(checksum,31)+serialized.charCodeAt(i))|0;
  const backupId=cryptoRandomId(),timestamp=nowISO();
  await db.prepare("INSERT INTO ci_conan_incubator_backups (backup_id,generation,snapshot_json,checksum,verified,created_at) SELECT ?,generation,?,?,0,? FROM ci_conan_incubator_state WHERE state_id='primary'").bind(backupId,serialized,String(checksum),timestamp).run();
  const stored=await db.prepare("SELECT snapshot_json,checksum FROM ci_conan_incubator_backups WHERE backup_id=?").bind(backupId).first();
  const verified=Boolean(stored&&stored.snapshot_json===serialized&&stored.checksum===String(checksum));
  if(!verified)throw new Error("La vérification de la sauvegarde de l'incubateur a échoué; aucune opération de réinitialisation ne peut continuer.");
  await db.prepare("UPDATE ci_conan_incubator_backups SET verified=1 WHERE backup_id=?").bind(backupId).run();
  await db.prepare("UPDATE ci_conan_incubator_state SET last_backup_id=?,updated_at=? WHERE state_id='primary'").bind(backupId,timestamp).run();
  await recordConanIncubatorEvent(db,"backup_created_and_verified",backupId,{checksum:String(checksum),tables:names});
  return {backup_id:backupId,verified:true,checksum:String(checksum),tables:names};
}

function conanIncubatorFingerprint(values){
  const textValue=JSON.stringify(values);
  let hash=2166136261;
  for(let i=0;i<textValue.length;i++){hash^=textValue.charCodeAt(i);hash=Math.imul(hash,16777619);}
  return (hash>>>0).toString(16);
}

function evaluateConanHistoricalExperiment(strategyKey,observations){
  const rows=observations.map((item,index)=>({index,price:radarFiniteMetric(item?.price_usd??item?.price),timestamp:item?.observed_at||item?.timestamp||null})).filter(x=>x.price!==null&&x.price>0);
  if(rows.length<12)throw new Error("Au moins 12 observations historiques valides sont nécessaires; aucun résultat n'est extrapolé.");
  if(strategyKey!=="sma_crossover_v1")throw new Error("Stratégie expérimentale inconnue ou non autorisée.");
  let position=false,entry=0,capital=1,peak=1,maxDrawdown=0,trades=0,wins=0;
  const fast=3,slow=7;
  for(let i=slow;i<rows.length;i++){
    const fastAvg=rows.slice(i-fast+1,i+1).reduce((a,b)=>a+b.price,0)/fast;
    const slowAvg=rows.slice(i-slow+1,i+1).reduce((a,b)=>a+b.price,0)/slow;
    const price=rows[i].price;
    if(!position&&fastAvg>slowAvg){position=true;entry=price;trades++;}
    else if(position&&fastAvg<slowAvg){const tradeReturn=price/entry-1;capital*=price/entry;if(tradeReturn>0)wins++;position=false;}
    peak=Math.max(peak,capital);maxDrawdown=Math.max(maxDrawdown,(peak-capital)/peak);
  }
  if(position){const tradeReturn=rows[rows.length-1].price/entry-1;capital*=rows[rows.length-1].price/entry;if(tradeReturn>0)wins++;}
  const buyHold=rows[rows.length-1].price/rows[0].price;
  return {strategy_key:strategyKey,observations:rows.length,closed_and_finalized_trades:trades,profitable_trades:wins,win_rate_percent:trades?wins/trades*100:null,strategy_return_percent:(capital-1)*100,buy_and_hold_return_percent:(buyHold-1)*100,max_drawdown_percent:maxDrawdown*100,fees_included:false,slippage_included:false,gas_included:false,out_of_sample:false,limitations:["Prototype de recherche uniquement; ce résultat n'est pas une recommandation financière.","Les données historiques sont fournies par l'appelant et leur provenance doit être vérifiée.","Pas de frais, glissement, gas, MEV ni contraintes d'exécution.","Un seul actif et une seule série; aucun test hors échantillon automatique.","Les performances passées ne préjugent pas des résultats futurs."]};
}

async function createConanIncubatorExperiment(db,body){
  await ensureConanIncubatorTables(db);
  const state=await db.prepare("SELECT status FROM ci_conan_incubator_state WHERE state_id='primary'").first();
  if(state?.status!=="active")throw new Error("L'incubateur est suspendu; les expériences sont bloquées.");
  const title=safeString(body.title||"Expérience Conan",180),hypothesis=safeString(body.hypothesis||"",1200);
  const strategyKey=safeString(body.strategy_key||"sma_crossover_v1",80);
  const observations=Array.isArray(body.historical_observations)?body.historical_observations.slice(0,5000):[];
  if(!hypothesis)throw new Error("Une hypothèse explicite est obligatoire.");
  if(!observations.length)throw new Error("Fournis un jeu de données historiques indépendant et documenté; aucune donnée fictive ne sera générée.");
  const result=evaluateConanHistoricalExperiment(strategyKey,observations);
  const experimentId=cryptoRandomId(),timestamp=nowISO(),fingerprint=conanIncubatorFingerprint(observations);
  await db.prepare("INSERT INTO ci_conan_incubator_experiments (experiment_id,title,hypothesis,strategy_key,status,dataset_fingerprint,dataset_size,results_json,limitations_json,created_at,completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)").bind(
    experimentId,title,hypothesis,strategyKey,"completed",fingerprint,result.observations,JSON.stringify(result),JSON.stringify(result.limitations),timestamp,timestamp
  ).run();
  const inserts=observations.slice(0,5000).map((item,index)=>db.prepare("INSERT INTO ci_conan_incubator_observations (observation_id,experiment_id,observation_index,observed_at,value_json,created_at) VALUES (?,?,?,?,?,?)").bind(
    cryptoRandomId(),experimentId,index,safeString(item?.observed_at||item?.timestamp||"",100)||null,JSON.stringify(item),timestamp
  ));
  for(let i=0;i<inserts.length;i+=50)await db.batch(inserts.slice(i,i+50));
  await recordConanIncubatorEvent(db,"historical_experiment_completed",experimentId,{strategy_key:strategyKey,dataset_fingerprint:fingerprint,observations:result.observations});
  return {experiment_id:experimentId,status:"completed",dataset_fingerprint:fingerprint,results:result};
}

async function createConanImprovementProposal(db,body){
  await ensureConanIncubatorTables(db);
  const title=safeString(body.title||"",180),problem=safeString(body.problem||"",1500),proposed=safeString(body.proposed_change||"",2500);
  if(!title||!problem||!proposed)throw new Error("title, problem et proposed_change sont obligatoires.");
  const id=cryptoRandomId(),timestamp=nowISO(),risks=Array.isArray(body.risks)?body.risks.slice(0,30):[];
  await db.prepare("INSERT INTO ci_conan_improvement_proposals (proposal_id,title,problem,proposed_change,expected_benefit,risks_json,evidence_json,status,created_at) VALUES (?,?,?,?,?,?,?,'pending_review',?)").bind(
    id,title,problem,proposed,safeString(body.expected_benefit||"",1000)||null,JSON.stringify(risks),JSON.stringify(body.evidence&&typeof body.evidence==="object"?body.evidence:{}),timestamp
  ).run();
  await recordConanIncubatorEvent(db,"improvement_proposal_created",id,{title,status:"pending_review"});
  return {proposal_id:id,status:"pending_review",main_code_modified:false,requires_human_review:true};
}

const conanChapter12OriginalProtectedRoutes = handleProtectedRoutes;
handleProtectedRoutes = async function(request,env,ctx,route){
  const {path,method,url}=route;
  const chapter12Routes=[
    "/api/conan/incubator",
    "/api/conan/incubator/tools",
    "/api/conan/incubator/experiments",
    "/api/conan/incubator/proposals",
    "/api/conan/incubator/proposals/review",
    "/api/conan/incubator/suspend",
    "/api/conan/incubator/resume",
    "/api/conan/incubator/reset",
    "/api/conan/incubator/backups",
    "/api/conan/incubator/events"
  ];
  if(chapter12Routes.includes(path)){
    const db=getDB(env);
    await initializeBackendTables(db);
    await ensureConanIncubatorTables(db);
    if(method==="GET"&&path==="/api/conan/incubator")return json({success:true,methodology:CONAN_INCUBATOR_METHODOLOGY,state:await getConanIncubatorState(db)});
    if(method==="GET"&&path==="/api/conan/incubator/tools"){
      const rows=await db.prepare("SELECT * FROM ci_conan_incubator_tools ORDER BY created_at DESC LIMIT 200").all();
      return json({success:true,count:rows.results?.length||0,tools:rows.results||[]});
    }
    if(method==="POST"&&path==="/api/conan/incubator/tools"){
      const body=await readBody(request),name=safeString(body.name||"",160),purpose=safeString(body.purpose||"",1000);
      if(!name||!purpose)return errorResponse("name et purpose sont obligatoires.");
      const id=cryptoRandomId(),timestamp=nowISO();
      await db.prepare("INSERT INTO ci_conan_incubator_tools (tool_id,name,purpose,design_json,status,evidence_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)").bind(id,name,purpose,JSON.stringify(body.design&&typeof body.design==="object"?body.design:{}),"proposed",JSON.stringify({source:"human_or_conan_proposal",code_execution:false}),timestamp,timestamp).run();
      await recordConanIncubatorEvent(db,"tool_design_proposed",id,{name,purpose});
      return json({success:true,tool_id:id,status:"proposed",code_execution:false,main_code_modified:false},201);
    }
    if(method==="GET"&&path==="/api/conan/incubator/experiments"){
      const rows=await db.prepare("SELECT * FROM ci_conan_incubator_experiments ORDER BY created_at DESC LIMIT 200").all();
      return json({success:true,count:rows.results?.length||0,experiments:rows.results||[]});
    }
    if(method==="POST"&&path==="/api/conan/incubator/experiments"){
      try{return json({success:true,...await createConanIncubatorExperiment(db,await readBody(request))},201);}
      catch(error){return errorResponse(safeString(error.message||"Expérience refusée.",1000),400);}
    }
    if(method==="GET"&&path==="/api/conan/incubator/proposals"){
      const rows=await db.prepare("SELECT * FROM ci_conan_improvement_proposals ORDER BY created_at DESC LIMIT 200").all();
      return json({success:true,count:rows.results?.length||0,proposals:rows.results||[]});
    }
    if(method==="POST"&&path==="/api/conan/incubator/proposals"){
      try{return json({success:true,...await createConanImprovementProposal(db,await readBody(request))},201);}
      catch(error){return errorResponse(safeString(error.message||"Proposition invalide.",1000),400);}
    }
    if(method==="POST"&&path==="/api/conan/incubator/proposals/review"){
      const body=await readBody(request),id=safeString(body.proposal_id||"",160),decision=safeString(body.decision||"",30);
      if(!id||!["approve","reject"].includes(decision))return errorResponse("proposal_id et decision approve/reject sont requis.");
      const proposal=await db.prepare("SELECT * FROM ci_conan_improvement_proposals WHERE proposal_id=?").bind(id).first();
      if(!proposal)return errorResponse("Proposition introuvable.",404);
      if(proposal.status!=="pending_review")return errorResponse("Cette proposition a déjà été examinée.",409);
      const status=decision==="approve"?"approved_for_separate_implementation_review":"rejected";
      await db.prepare("UPDATE ci_conan_improvement_proposals SET status=?,reviewed_at=?,reviewer_note=? WHERE proposal_id=? AND status='pending_review'").bind(status,nowISO(),safeString(body.reviewer_note||"",1500)||null,id).run();
      await recordConanIncubatorEvent(db,"improvement_proposal_reviewed",id,{decision,status,main_code_modified:false});
      return json({success:true,proposal_id:id,status,main_code_modified:false,note:"L'approbation autorise uniquement une revue d'implémentation séparée; elle ne modifie jamais automatiquement le code principal."});
    }
    if(method==="POST"&&path==="/api/conan/incubator/suspend"){
      const timestamp=nowISO();
      await db.prepare("UPDATE ci_conan_incubator_state SET status='suspended',suspended_at=?,updated_at=? WHERE state_id='primary'").bind(timestamp,timestamp).run();
      await recordConanIncubatorEvent(db,"incubator_suspended",null,{timestamp});
      return json({success:true,status:"suspended"});
    }
    if(method==="POST"&&path==="/api/conan/incubator/resume"){
      const timestamp=nowISO();
      await db.prepare("UPDATE ci_conan_incubator_state SET status='active',suspended_at=NULL,updated_at=? WHERE state_id='primary'").bind(timestamp).run();
      await recordConanIncubatorEvent(db,"incubator_resumed",null,{timestamp});
      return json({success:true,status:"active"});
    }
    if(method==="POST"&&path==="/api/conan/incubator/reset"){
      const backup=await createConanIncubatorBackup(db);
      const timestamp=nowISO();
      await db.prepare("UPDATE ci_conan_incubator_state SET status='active',generation=generation+1,suspended_at=NULL,updated_at=?,state_json='{}' WHERE state_id='primary'").bind(timestamp).run();
      await recordConanIncubatorEvent(db,"incubator_generation_reset_after_verified_backup",backup.backup_id,{backup_id:backup.backup_id,backup_verified:backup.verified,note:"Les historiques et prototypes précédents sont conservés; aucune ligne n'est supprimée."});
      return json({success:true,status:"active",backup,generation_reset:true,history_preserved:true,rows_deleted:0});
    }
    if(method==="GET"&&path==="/api/conan/incubator/backups"){
      const rows=await db.prepare("SELECT backup_id,generation,checksum,verified,created_at FROM ci_conan_incubator_backups ORDER BY created_at DESC LIMIT 100").all();
      return json({success:true,count:rows.results?.length||0,backups:rows.results||[]});
    }
    if(method==="GET"&&path==="/api/conan/incubator/events"){
      const limit=Math.max(1,Math.min(500,Number(url.searchParams.get("limit"))||100));
      const rows=await db.prepare("SELECT * FROM ci_conan_incubator_events ORDER BY created_at DESC LIMIT ?").bind(limit).all();
      return json({success:true,count:rows.results?.length||0,events:rows.results||[]});
    }
  }
  return await conanChapter12OriginalProtectedRoutes(request,env,ctx,route);
};


// CHAPTER 12 ADDENDUM — AUTONOMOUS, VERSIONED CONAN-OWNED CODE WORKSPACE.
// This workspace is separate from the application's source tree. Revisions are
// stored as data in D1; they are never eval'd, imported, or executed by this Worker.
const CONAN_OWN_CODE_WORKSPACE_VERSION = "conan-owned-code-workspace-v1";

async function ensureConanOwnedCodeWorkspace(db){
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_code_modules (
      module_id TEXT PRIMARY KEY,
      module_name TEXT NOT NULL,
      description TEXT NOT NULL,
      active_revision_id TEXT,
      status TEXT NOT NULL DEFAULT 'draft',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_code_revisions (
      revision_id TEXT PRIMARY KEY,
      module_id TEXT NOT NULL,
      version_number INTEGER NOT NULL,
      source_code TEXT NOT NULL,
      source_format TEXT NOT NULL DEFAULT 'javascript',
      checksum TEXT NOT NULL,
      validation_json TEXT NOT NULL,
      parent_revision_id TEXT,
      created_by TEXT NOT NULL DEFAULT 'conan',
      created_at TEXT NOT NULL
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_code_revisions_module ON ci_conan_code_revisions(module_id,version_number DESC)"),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_code_events (
      event_id TEXT PRIMARY KEY,
      module_id TEXT,
      revision_id TEXT,
      event_type TEXT NOT NULL,
      details_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_conan_code_backups (
      backup_id TEXT PRIMARY KEY,
      snapshot_json TEXT NOT NULL,
      checksum TEXT NOT NULL,
      verified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )`)
  ]);
  for(const table of ["ci_conan_code_modules","ci_conan_code_revisions","ci_conan_code_events","ci_conan_code_backups"]){
    if(!ARCHIVE_TABLES.includes(table))ARCHIVE_TABLES.push(table);
  }
}

function validateConanOwnedCodeSource(source){
  const code=String(source??"");
  const issues=[];
  if(!code.trim())issues.push("Le code ne peut pas être vide.");
  if(code.length>30000)issues.push("La taille maximale d'une révision est de 30 000 caractères.");
  const forbidden=[
    {pattern:/\\beval\\s*\\(/i,label:"eval"},
    {pattern:/\\bnew\\s+Function\\s*\\(/i,label:"Function constructor"},
    {pattern:/\\bimport\\s*\\(/i,label:"dynamic import"},
    {pattern:/\\bfetch\\s*\\(/i,label:"network fetch"},
    {pattern:/\\bglobalThis\\b/i,label:"globalThis"},
    {pattern:/\\bprocess\\b/i,label:"process"},
    {pattern:/\\brequire\\s*\\(/i,label:"require"},
    {pattern:/\\bDeno\\b/i,label:"Deno"},
    {pattern:/\\bWebAssembly\\b/i,label:"WebAssembly"}
  ];
  for(const item of forbidden)if(item.pattern.test(code))issues.push("API non autorisée dans l'espace de code isolé : "+item.label+".");
  return {valid:issues.length===0,issues,source_characters:code.length,execution_status:"not_executable_by_application_worker",note:"Validation statique uniquement; aucune exécution de code arbitraire n'est autorisée."};
}

async function recordConanOwnedCodeEvent(db,eventType,moduleId,revisionId,details){
  await db.prepare("INSERT INTO ci_conan_code_events (event_id,module_id,revision_id,event_type,details_json,created_at) VALUES (?,?,?,?,?,?)").bind(
    cryptoRandomId(),moduleId||null,revisionId||null,eventType,JSON.stringify(details||{}),nowISO()
  ).run();
}

async function createConanOwnedCodeBackup(db){
  await ensureConanOwnedCodeWorkspace(db);
  const names=["ci_conan_code_modules","ci_conan_code_revisions","ci_conan_code_events"];
  const snapshot={schema:CONAN_OWN_CODE_WORKSPACE_VERSION,tables:{}};
  for(const name of names){
    const rows=await db.prepare("SELECT * FROM "+name).all();
    snapshot.tables[name]=rows.results||[];
  }
  const serialized=JSON.stringify(snapshot);
  const checksum=conanIncubatorFingerprint(snapshot);
  const id=cryptoRandomId(),timestamp=nowISO();
  await db.prepare("INSERT INTO ci_conan_code_backups (backup_id,snapshot_json,checksum,verified,created_at) VALUES (?,?,?,0,?)").bind(id,serialized,checksum,timestamp).run();
  const stored=await db.prepare("SELECT snapshot_json,checksum FROM ci_conan_code_backups WHERE backup_id=?").bind(id).first();
  const verified=Boolean(stored&&stored.snapshot_json===serialized&&stored.checksum===checksum);
  if(!verified)throw new Error("Sauvegarde du code personnel Conan non vérifiée; opération bloquée.");
  await db.prepare("UPDATE ci_conan_code_backups SET verified=1 WHERE backup_id=?").bind(id).run();
  await recordConanOwnedCodeEvent(db,"code_workspace_backup_verified",null,null,{backup_id:id,checksum});
  return {backup_id:id,verified:true,checksum};
}

async function createOrReviseConanOwnedModule(db,body){
  await ensureConanOwnedCodeWorkspace(db);
  const name=safeString(body.module_name||"",120);
  const description=safeString(body.description||"",1000);
  const source=typeof body.source_code==="string"?body.source_code:"";
  if(!name||!description)return {error:"module_name et description sont obligatoires."};
  const validation=validateConanOwnedCodeSource(source);
  if(!validation.valid)return {error:"Révision refusée par les garde-fous statiques.",validation};
  let moduleId=safeString(body.module_id||"",160);
  let moduleRow=null;
  if(moduleId)moduleRow=await db.prepare("SELECT * FROM ci_conan_code_modules WHERE module_id=?").bind(moduleId).first();
  if(moduleId&&!moduleRow)return {error:"Module Conan introuvable."};
  if(!moduleId){
    moduleId=cryptoRandomId();
    const timestamp=nowISO();
    await db.prepare("INSERT INTO ci_conan_code_modules (module_id,module_name,description,status,created_at,updated_at) VALUES (?,?,?,'draft',?,?)").bind(moduleId,name,description,timestamp,timestamp).run();
  }
  const latest=await db.prepare("SELECT revision_id,version_number FROM ci_conan_code_revisions WHERE module_id=? ORDER BY version_number DESC LIMIT 1").bind(moduleId).first();
  const version=(Number(latest?.version_number)||0)+1;
  const revisionId=cryptoRandomId(),timestamp=nowISO(),checksum=conanIncubatorFingerprint(source);
  await db.prepare("INSERT INTO ci_conan_code_revisions (revision_id,module_id,version_number,source_code,source_format,checksum,validation_json,parent_revision_id,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)").bind(
    revisionId,moduleId,version,source,"javascript",checksum,JSON.stringify(validation),latest?.revision_id||null,"conan",timestamp
  ).run();
  await db.prepare("UPDATE ci_conan_code_modules SET module_name=?,description=?,updated_at=? WHERE module_id=?").bind(name,description,timestamp,moduleId).run();
  await recordConanOwnedCodeEvent(db,"conan_owned_code_revision_created",moduleId,revisionId,{version,checksum,validation});
  return {module_id:moduleId,revision_id:revisionId,version,checksum,validation,execution_status:"stored_not_executed",human_approval_required:false,application_source_modified:false};
}

const conanChapter12BeforeOwnedCodeWorkspace = handleProtectedRoutes;
handleProtectedRoutes = async function(request,env,ctx,route){
  const {path,method,url}=route;
  const codeRoutes=[
    "/api/conan/incubator/code",
    "/api/conan/incubator/code/modules",
    "/api/conan/incubator/code/revisions",
    "/api/conan/incubator/code/activate",
    "/api/conan/incubator/code/backups",
    "/api/conan/incubator/code/events"
  ];
  if(codeRoutes.includes(path)){
    const db=getDB(env);
    await initializeBackendTables(db);
    await ensureConanIncubatorTables(db);
    await ensureConanOwnedCodeWorkspace(db);
    if(method==="GET"&&path==="/api/conan/incubator/code"){
      const state=await getConanIncubatorState(db);
      return json({success:true,workspace:CONAN_OWN_CODE_WORKSPACE_VERSION,autonomous_authoring:true,human_approval_required:false,application_source_access:"read_only",application_source_modification:false,arbitrary_code_execution:false,execution_status:"not_available_in_worker",permissions:state.permissions});
    }
    if(method==="GET"&&path==="/api/conan/incubator/code/modules"){
      const rows=await db.prepare("SELECT * FROM ci_conan_code_modules ORDER BY updated_at DESC LIMIT 200").all();
      return json({success:true,count:rows.results?.length||0,modules:rows.results||[]});
    }
    if(method==="POST"&&path==="/api/conan/incubator/code/modules"){
      try{
        const result=await createOrReviseConanOwnedModule(db,await readBody(request));
        if(result.error)return errorResponse(result.error,400,{validation:result.validation});
        return json({success:true,...result},201);
      }catch(error){return errorResponse(safeString(error.message||"Création de module refusée.",1000),400);}
    }
    if(method==="GET"&&path==="/api/conan/incubator/code/revisions"){
      const moduleId=safeString(url.searchParams.get("module_id")||"",160);
      if(!moduleId)return errorResponse("module_id est obligatoire.");
      const rows=await db.prepare("SELECT revision_id,module_id,version_number,source_format,checksum,validation_json,parent_revision_id,created_by,created_at FROM ci_conan_code_revisions WHERE module_id=? ORDER BY version_number DESC LIMIT 100").bind(moduleId).all();
      return json({success:true,count:rows.results?.length||0,revisions:rows.results||[]});
    }
    if(method==="GET"&&path==="/api/conan/incubator/code/activate"){
      const moduleId=safeString(url.searchParams.get("module_id")||"",160);
      const row=await db.prepare("SELECT module_id,module_name,active_revision_id,status FROM ci_conan_code_modules WHERE module_id=?").bind(moduleId).first();
      if(!row)return errorResponse("Module introuvable.",404);
      return json({success:true,module:row,activation_means:"selected_version_only",runtime_execution:false});
    }
    if(method==="POST"&&path==="/api/conan/incubator/code/activate"){
      const body=await readBody(request),moduleId=safeString(body.module_id||"",160),revisionId=safeString(body.revision_id||"",160);
      const revision=await db.prepare("SELECT * FROM ci_conan_code_revisions WHERE revision_id=? AND module_id=?").bind(revisionId,moduleId).first();
      if(!revision)return errorResponse("Révision de ce module introuvable.",404);
      const validation=JSON.parse(revision.validation_json||"{}");
      if(!validation.valid)return errorResponse("Révision non validée.",400);
      const timestamp=nowISO();
      await db.prepare("UPDATE ci_conan_code_modules SET active_revision_id=?,status='selected_not_executed',updated_at=? WHERE module_id=?").bind(revisionId,timestamp,moduleId).run();
      await recordConanOwnedCodeEvent(db,"conan_owned_revision_selected",moduleId,revisionId,{runtime_execution:false});
      return json({success:true,module_id:moduleId,active_revision_id:revisionId,status:"selected_not_executed",runtime_execution:false,application_source_modified:false});
    }
    if(method==="POST"&&path==="/api/conan/incubator/code/backups"){
      try{return json({success:true,...await createConanOwnedCodeBackup(db)},201);}
      catch(error){return errorResponse(safeString(error.message||"Sauvegarde échouée.",1000),500);}
    }
    if(method==="GET"&&path==="/api/conan/incubator/code/backups"){
      const rows=await db.prepare("SELECT backup_id,checksum,verified,created_at FROM ci_conan_code_backups ORDER BY created_at DESC LIMIT 100").all();
      return json({success:true,count:rows.results?.length||0,backups:rows.results||[]});
    }
    if(method==="GET"&&path==="/api/conan/incubator/code/events"){
      const limit=Math.max(1,Math.min(500,Number(url.searchParams.get("limit"))||100));
      const rows=await db.prepare("SELECT * FROM ci_conan_code_events ORDER BY created_at DESC LIMIT ?").bind(limit).all();
      return json({success:true,count:rows.results?.length||0,events:rows.results||[]});
    }
  }
  return await conanChapter12BeforeOwnedCodeWorkspace(request,env,ctx,route);
};


// Final corrected validator declaration. This is appended so every previously
// committed application and incubator line remains byte-for-byte unchanged.
function validateConanOwnedCodeSource(source){
  const code=String(source??"");
  const issues=[];
  if(!code.trim())issues.push("Le code ne peut pas être vide.");
  if(code.length>30000)issues.push("La taille maximale d'une révision est de 30 000 caractères.");
  const forbidden=[
    {pattern:/\beval\s*\(/i,label:"eval"},
    {pattern:/\bnew\s+Function\s*\(/i,label:"Function constructor"},
    {pattern:/\bimport\s*\(/i,label:"dynamic import"},
    {pattern:/\bfetch\s*\(/i,label:"network fetch"},
    {pattern:/\bglobalThis\b/i,label:"globalThis"},
    {pattern:/\bprocess\b/i,label:"process"},
    {pattern:/\brequire\s*\(/i,label:"require"},
    {pattern:/\bDeno\b/i,label:"Deno"},
    {pattern:/\bWebAssembly\b/i,label:"WebAssembly"}
  ];
  for(const item of forbidden)if(item.pattern.test(code))issues.push("API non autorisée dans l'espace de code isolé : "+item.label+".");
  return {valid:issues.length===0,issues,source_characters:code.length,execution_status:"not_executable_by_application_worker",note:"Validation statique uniquement; aucune exécution de code arbitraire n'est autorisée."};
}


// CHAPTER 13 — CONAN INTELLIGENT MEMORY, SEMANTIC RECALL AND ARCHIVES.
// Memory tiers: essential, useful, experimental, archives.
// Personal memory is stored in a separate table from operational memory.
// Raw source records remain untouched; archive-tier entries are references/copies,
// never permission to delete original operational or historical records.
const CONAN_MEMORY_METHODOLOGY = "conan-four-tier-semantic-recall-v1";
const CONAN_MEMORY_TIERS = ["essential","useful","experimental","archives"];

async function ensureConanMemoryTables(db){
  await db.batch([
    db.prepare(\`CREATE TABLE IF NOT EXISTS ci_conan_memory_records (
      memory_id TEXT PRIMARY KEY,
      memory_scope TEXT NOT NULL,
      tier TEXT NOT NULL,
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      structured_data_json TEXT NOT NULL DEFAULT '{}',
      exact_values_json TEXT NOT NULL DEFAULT '{}',
      source_refs_json TEXT NOT NULL DEFAULT '[]',
      observed_at TEXT,
      confidence_percent REAL,
      uncertainty_json TEXT NOT NULL DEFAULT '[]',
      context_tags_json TEXT NOT NULL DEFAULT '[]',
      outcome_json TEXT NOT NULL DEFAULT '{}',
      content_fingerprint TEXT NOT NULL,
      original_record_ref TEXT,
      duplicate_of TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )\`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_memory_scope_tier ON ci_conan_memory_records(memory_scope,tier,status,updated_at DESC)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_memory_fingerprint ON ci_conan_memory_records(memory_scope,content_fingerprint)"),
    db.prepare(\`CREATE TABLE IF NOT EXISTS ci_conan_memory_links (
      link_id TEXT PRIMARY KEY,
      from_memory_id TEXT NOT NULL,
      to_memory_id TEXT NOT NULL,
      relation_type TEXT NOT NULL,
      details_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    )\`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_memory_links_from ON ci_conan_memory_links(from_memory_id,created_at DESC)"),
    db.prepare(\`CREATE TABLE IF NOT EXISTS ci_conan_memory_recall_log (
      recall_id TEXT PRIMARY KEY,
      memory_scope TEXT NOT NULL,
      query_text TEXT NOT NULL,
      context_json TEXT NOT NULL DEFAULT '{}',
      results_json TEXT NOT NULL DEFAULT '[]',
      methodology TEXT NOT NULL,
      created_at TEXT NOT NULL
    )\`),
    db.prepare(\`CREATE TABLE IF NOT EXISTS ci_conan_memory_tier_history (
      event_id TEXT PRIMARY KEY,
      memory_id TEXT NOT NULL,
      from_tier TEXT,
      to_tier TEXT NOT NULL,
      reason TEXT NOT NULL,
      evidence_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    )\`),
    db.prepare(\`CREATE TABLE IF NOT EXISTS ci_conan_personal_memory (
      personal_memory_id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      structured_data_json TEXT NOT NULL DEFAULT '{}',
      source_refs_json TEXT NOT NULL DEFAULT '[]',
      confidence_percent REAL,
      uncertainty_json TEXT NOT NULL DEFAULT '[]',
      content_fingerprint TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )\`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_conan_personal_memory_fingerprint ON ci_conan_personal_memory(content_fingerprint)"),
    db.prepare(\`CREATE TABLE IF NOT EXISTS ci_conan_memory_backups (
      backup_id TEXT PRIMARY KEY,
      memory_scope TEXT NOT NULL,
      snapshot_json TEXT NOT NULL,
      checksum TEXT NOT NULL,
      verified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )\`)
  ]);
  for(const table of ["ci_conan_memory_records","ci_conan_memory_links","ci_conan_memory_recall_log","ci_conan_memory_tier_history","ci_conan_personal_memory","ci_conan_memory_backups"]){
    if(!ARCHIVE_TABLES.includes(table))ARCHIVE_TABLES.push(table);
  }
}

function conanMemoryNormalize(value){
  return String(value??"").toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g,"").replace(/[^a-z0-9_$.-]+/g," ").trim();
}

function conanMemoryTokens(value){
  const stop=new Set(["avec","dans","pour","mais","donc","this","that","from","with","have","will","were","been","the","and","for","are","was","une","des","les","est","sur","par","qui","que"]);
  return [...new Set(conanMemoryNormalize(value).split(/\s+/).filter(token=>token.length>2&&!stop.has(token)))].slice(0,160);
}

function conanMemoryFingerprint(payload){
  const normalized={
    title:conanMemoryNormalize(payload.title),
    summary:conanMemoryNormalize(payload.summary),
    exact_values:payload.exact_values||{},
    source_refs:payload.source_refs||[],
    observed_at:payload.observed_at||null
  };
  return conanIncubatorFingerprint(normalized);
}

function scoreConanMemoryRelevance(record,query,context){
  const queryTokens=conanMemoryTokens(query);
  const titleTokens=conanMemoryTokens(record.title);
  const summaryTokens=conanMemoryTokens(record.summary);
  const tags=Array.isArray(record.context_tags)?record.context_tags:[];
  const recordTokens=new Set([...titleTokens,...summaryTokens,...conanMemoryTokens(tags.join(" "))]);
  if(!queryTokens.length)return {score:0,matched_terms:[]};
  const matched=queryTokens.filter(token=>recordTokens.has(token));
  const overlap=matched.length/queryTokens.length;
  const titleBoost=matched.some(token=>titleTokens.includes(token))?0.15:0;
  const contextTags=Array.isArray(context?.context_tags)?context.context_tags:[];
  const contextMatches=contextTags.filter(tag=>tags.some(existing=>conanMemoryNormalize(existing)===conanMemoryNormalize(tag))).length;
  const contextBoost=Math.min(0.2,contextMatches*0.05);
  const outcomeText=JSON.stringify(record.outcome||{});
  const outcomeBoost=context?.outcome_type&&outcomeText.toLowerCase().includes(String(context.outcome_type).toLowerCase())?0.05:0;
  return {score:Math.min(1,overlap*0.6+titleBoost+contextBoost+outcomeBoost),matched_terms:matched};
}

async function createConanMemoryRecord(db,body){
  await ensureConanMemoryTables(db);
  const scope=body.memory_scope==="personal"?"personal":"operational";
  const tier=CONAN_MEMORY_TIERS.includes(body.tier)?body.tier:"useful";
  const title=safeString(body.title||"",200);
  const summary=safeString(body.summary||"",5000);
  if(!title||!summary)throw new Error("title et summary sont obligatoires.");
  const confidence=body.confidence_percent===null||body.confidence_percent===undefined?null:radarFiniteMetric(body.confidence_percent);
  if(confidence!==null&&(confidence<0||confidence>100))throw new Error("confidence_percent doit être compris entre 0 et 100.");
  const exactValues=body.exact_values&&typeof body.exact_values==="object"?body.exact_values:{};
  const structured=body.structured_data&&typeof body.structured_data==="object"?body.structured_data:{};
  const sourceRefs=Array.isArray(body.source_refs)?body.source_refs.slice(0,100):[];
  const uncertainties=Array.isArray(body.uncertainties)?body.uncertainties.slice(0,100):[];
  const tags=Array.isArray(body.context_tags)?body.context_tags.slice(0,100):[];
  const observedAt=safeString(body.observed_at||"",100)||null;
  const fingerprint=conanMemoryFingerprint({title,summary,exact_values:exactValues,source_refs:sourceRefs,observed_at:observedAt});
  const table=scope==="personal"?"ci_conan_personal_memory":"ci_conan_memory_records";
  const existing=await db.prepare("SELECT * FROM "+table+" WHERE content_fingerprint=? ORDER BY created_at ASC LIMIT 1").bind(fingerprint).first();
  if(existing){
    const duplicateId=cryptoRandomId(),timestamp=nowISO();
    if(scope==="operational"){
      await db.prepare("INSERT INTO ci_conan_memory_links (link_id,from_memory_id,to_memory_id,relation_type,details_json,created_at) VALUES (?,?,?,?,?,?)").bind(duplicateId,existing.memory_id,existing.memory_id,"duplicate_observation",JSON.stringify({new_source_refs:sourceRefs,uncertainties,observed_at:observedAt,note:"Doublon détecté; l'original est conservé et les nouveaux éléments de provenance sont ajoutés au lien."}),timestamp).run();
      const priorSources=JSON.parse(existing.source_refs_json||"[]");
      const merged=[...priorSources,...sourceRefs].filter((item,index,array)=>array.findIndex(other=>JSON.stringify(other)===JSON.stringify(item))===index);
      await db.prepare("UPDATE ci_conan_memory_records SET source_refs_json=?,updated_at=? WHERE memory_id=?").bind(JSON.stringify(merged),timestamp,existing.memory_id).run();
    }
    return {memory_id:existing.memory_id,duplicate:true,scope,original_preserved:true,additional_provenance_recorded:scope==="operational"};
  }
  const id=cryptoRandomId(),timestamp=nowISO();
  if(scope==="personal"){
    await db.prepare("INSERT INTO ci_conan_personal_memory (personal_memory_id,title,content,structured_data_json,source_refs_json,confidence_percent,uncertainty_json,content_fingerprint,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)").bind(
      id,title,summary,JSON.stringify({...structured,exact_values:exactValues,observed_at:observedAt}),JSON.stringify(sourceRefs),confidence,JSON.stringify(uncertainties),fingerprint,timestamp,timestamp
    ).run();
  }else{
    await db.prepare("INSERT INTO ci_conan_memory_records (memory_id,memory_scope,tier,title,summary,structured_data_json,exact_values_json,source_refs_json,observed_at,confidence_percent,uncertainty_json,context_tags_json,outcome_json,content_fingerprint,original_record_ref,created_at,updated_at) VALUES (?,'operational',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(
      id,tier,title,summary,JSON.stringify(structured),JSON.stringify(exactValues),JSON.stringify(sourceRefs),observedAt,confidence,JSON.stringify(uncertainties),JSON.stringify(tags),JSON.stringify(body.outcome&&typeof body.outcome==="object"?body.outcome:{}),fingerprint,safeString(body.original_record_ref||"",300)||null,timestamp,timestamp
    ).run();
    await db.prepare("INSERT INTO ci_conan_memory_tier_history (event_id,memory_id,from_tier,to_tier,reason,evidence_json,created_at) VALUES (?,?,NULL,?,?,?,?)").bind(
      cryptoRandomId(),id,tier,"initial_memory_classification",JSON.stringify({source_refs:sourceRefs,confidence_percent:confidence}),timestamp
    ).run();
  }
  return {memory_id:id,duplicate:false,scope,tier,confidence_percent:confidence,original_record_ref:safeString(body.original_record_ref||"",300)||null};
}

async function searchConanMemory(db,query,options={}){
  await ensureConanMemoryTables(db);
  const scope=options.memory_scope==="personal"?"personal":"operational";
  const limit=Math.max(1,Math.min(100,Number(options.limit)||20));
  if(scope==="personal"){
    const rows=await db.prepare("SELECT * FROM ci_conan_personal_memory ORDER BY updated_at DESC LIMIT 1000").all();
    return (rows.results||[]).map(row=>{
      const score=scoreConanMemoryRelevance({title:row.title,summary:row.content,context_tags:[],outcome:{}},query,{});
      return {...row,score:score.score,matched_terms:score.matched_terms};
    }).filter(row=>row.score>0).sort((a,b)=>b.score-a.score).slice(0,limit);
  }
  const rows=await db.prepare("SELECT * FROM ci_conan_memory_records WHERE memory_scope='operational' AND status='active' ORDER BY updated_at DESC LIMIT 2000").all();
  return (rows.results||[]).map(row=>{
    const record={...row,context_tags:JSON.parse(row.context_tags_json||"[]"),outcome:JSON.parse(row.outcome_json||"{}")};
    const score=scoreConanMemoryRelevance(record,query,options.context||{});
    return {...row,score:score.score,matched_terms:score.matched_terms};
  }).filter(row=>row.score>0).sort((a,b)=>b.score-a.score).slice(0,limit);
}

async function recallConanMemoryForSignal(db,signal,options={}){
  const query=[signal?.title,signal?.description,signal?.symbol,signal?.chain,signal?.contract,signal?.signal_type].filter(Boolean).join(" ");
  const results=await searchConanMemory(db,query,{memory_scope:"operational",limit:options.limit||10,context:{context_tags:signal?.context_tags||[],outcome_type:signal?.outcome_type}});
  const recallId=cryptoRandomId(),timestamp=nowISO();
  const context={signal_type:signal?.signal_type||null,asset:signal?.symbol||null,chain:signal?.chain||null,contract:signal?.contract||null,similarity_is_not_proof:true};
  await db.prepare("INSERT INTO ci_conan_memory_recall_log (recall_id,memory_scope,query_text,context_json,results_json,methodology,created_at) VALUES (?,'operational',?,?,?,?,?)").bind(
    recallId,query,JSON.stringify(context),JSON.stringify(results.map(item=>({memory_id:item.memory_id,score:item.score,matched_terms:item.matched_terms}))),CONAN_MEMORY_METHODOLOGY,timestamp
  ).run();
  return {recall_id:recallId,methodology:CONAN_MEMORY_METHODOLOGY,similarity_is_not_proof:true,semantic_engine:"contextual_token_and_metadata_similarity_heuristic",vector_embeddings:false,results};
}

async function changeConanMemoryTier(db,body){
  await ensureConanMemoryTables(db);
  const id=safeString(body.memory_id||"",160),tier=safeString(body.tier||"",40),reason=safeString(body.reason||"",1000);
  if(!id||!CONAN_MEMORY_TIERS.includes(tier)||!reason)throw new Error("memory_id, tier valide et reason sont obligatoires.");
  const row=await db.prepare("SELECT tier FROM ci_conan_memory_records WHERE memory_id=? AND memory_scope='operational'").bind(id).first();
  if(!row)throw new Error("Mémoire opérationnelle introuvable.");
  if(row.tier===tier)return {memory_id:id,tier,changed:false};
  const timestamp=nowISO();
  await db.prepare("UPDATE ci_conan_memory_records SET tier=?,updated_at=? WHERE memory_id=?").bind(tier,timestamp,id).run();
  await db.prepare("INSERT INTO ci_conan_memory_tier_history (event_id,memory_id,from_tier,to_tier,reason,evidence_json,created_at) VALUES (?,?,?,?,?,?,?)").bind(
    cryptoRandomId(),id,row.tier,tier,reason,JSON.stringify(body.evidence&&typeof body.evidence==="object"?body.evidence:{}),timestamp
  ).run();
  return {memory_id:id,from_tier:row.tier,to_tier:tier,changed:true,original_record_preserved:true};
}

async function createConanMemoryBackup(db,scope="operational"){
  await ensureConanMemoryTables(db);
  const names=scope==="personal"?["ci_conan_personal_memory"]:["ci_conan_memory_records","ci_conan_memory_links","ci_conan_memory_recall_log","ci_conan_memory_tier_history"];
  const snapshot={schema:CONAN_MEMORY_METHODOLOGY,memory_scope:scope,tables:{}};
  for(const name of names){
    const rows=await db.prepare("SELECT * FROM "+name).all();
    snapshot.tables[name]=rows.results||[];
  }
  const serialized=JSON.stringify(snapshot),checksum=conanIncubatorFingerprint(snapshot),id=cryptoRandomId(),timestamp=nowISO();
  await db.prepare("INSERT INTO ci_conan_memory_backups (backup_id,memory_scope,snapshot_json,checksum,verified,created_at) VALUES (?,?,?,?,0,?)").bind(id,scope,serialized,checksum,timestamp).run();
  const stored=await db.prepare("SELECT snapshot_json,checksum FROM ci_conan_memory_backups WHERE backup_id=?").bind(id).first();
  const verified=Boolean(stored&&stored.snapshot_json===serialized&&stored.checksum===checksum);
  if(!verified)throw new Error("Sauvegarde mémoire non vérifiée; aucune opération destructive ne peut être effectuée.");
  await db.prepare("UPDATE ci_conan_memory_backups SET verified=1 WHERE backup_id=?").bind(id).run();
  return {backup_id:id,memory_scope:scope,verified:true,checksum,tables:names};
}

const conanChapter13OriginalProtectedRoutes = handleProtectedRoutes;
handleProtectedRoutes = async function(request,env,ctx,route){
  const {path,method,url}=route;
  const memoryRoutes=[
    "/api/conan/memory",
    "/api/conan/memory/records",
    "/api/conan/memory/search",
    "/api/conan/memory/recall",
    "/api/conan/memory/tier",
    "/api/conan/memory/history",
    "/api/conan/memory/backups",
    "/api/conan/memory/personal"
  ];
  if(memoryRoutes.includes(path)){
    const db=getDB(env);
    await initializeBackendTables(db);
    await ensureConanMemoryTables(db);
    if(method==="GET"&&path==="/api/conan/memory"){
      const counts=await db.prepare("SELECT COUNT(*) AS operational_count FROM ci_conan_memory_records WHERE memory_scope='operational'").first();
      const personal=await db.prepare("SELECT COUNT(*) AS personal_count FROM ci_conan_personal_memory").first();
      const tiers=await db.prepare("SELECT tier,COUNT(*) AS count FROM ci_conan_memory_records WHERE memory_scope='operational' GROUP BY tier").all();
      return json({success:true,methodology:CONAN_MEMORY_METHODOLOGY,tiers:CONAN_MEMORY_TIERS,operational_memory:counts,personal_memory:personal,counts_by_tier:tiers.results||[],raw_archives_separate:true,similarity_is_not_proof:true,semantic_engine:"contextual_token_and_metadata_similarity_heuristic",vector_embeddings:false,automatic_deletion:false});
    }
    if(method==="POST"&&path==="/api/conan/memory/records"){
      try{return json({success:true,...await createConanMemoryRecord(db,await readBody(request))},201);}
      catch(error){return errorResponse(safeString(error.message||"Enregistrement mémoire refusé.",1000),400);}
    }
    if(method==="GET"&&path==="/api/conan/memory/records"){
      const scope=url.searchParams.get("memory_scope")==="personal"?"personal":"operational";
      const tier=url.searchParams.get("tier");
      if(scope==="personal"){
        const rows=await db.prepare("SELECT * FROM ci_conan_personal_memory ORDER BY updated_at DESC LIMIT 200").all();
        return json({success:true,memory_scope:scope,records:rows.results||[]});
      }
      const rows=tier&&CONAN_MEMORY_TIERS.includes(tier)
        ?await db.prepare("SELECT * FROM ci_conan_memory_records WHERE memory_scope='operational' AND tier=? ORDER BY updated_at DESC LIMIT 200").bind(tier).all()
        :await db.prepare("SELECT * FROM ci_conan_memory_records WHERE memory_scope='operational' ORDER BY updated_at DESC LIMIT 200").all();
      return json({success:true,memory_scope:scope,records:rows.results||[]});
    }
    if(method==="GET"&&path==="/api/conan/memory/personal"){
      const rows=await db.prepare("SELECT * FROM ci_conan_personal_memory ORDER BY updated_at DESC LIMIT 200").all();
      return json({success:true,count:rows.results?.length||0,personal_memory:rows.results||[],operational_memory_accessed:false});
    }
    if(method==="GET"&&path==="/api/conan/memory/search"){
      const query=safeString(url.searchParams.get("q")||"",1000);
      if(!query)return errorResponse("Le paramètre q est obligatoire.");
      const results=await searchConanMemory(db,query,{memory_scope:url.searchParams.get("memory_scope"),limit:url.searchParams.get("limit")});
      return json({success:true,methodology:CONAN_MEMORY_METHODOLOGY,similarity_is_not_proof:true,vector_embeddings:false,results});
    }
    if(method==="POST"&&path==="/api/conan/memory/recall"){
      try{return json({success:true,...await recallConanMemoryForSignal(db,await readBody(request))});}
      catch(error){return errorResponse(safeString(error.message||"Rappel mémoire impossible.",1000),400);}
    }
    if(method==="POST"&&path==="/api/conan/memory/tier"){
      try{return json({success:true,...await changeConanMemoryTier(db,await readBody(request))});}
      catch(error){return errorResponse(safeString(error.message||"Changement de niveau refusé.",1000),400);}
    }
    if(method==="GET"&&path==="/api/conan/memory/history"){
      const id=safeString(url.searchParams.get("memory_id")||"",160);
      if(!id)return errorResponse("memory_id est obligatoire.");
      const rows=await db.prepare("SELECT * FROM ci_conan_memory_tier_history WHERE memory_id=? ORDER BY created_at ASC").bind(id).all();
      return json({success:true,history:rows.results||[]});
    }
    if(method==="POST"&&path==="/api/conan/memory/backups"){
      const body=await readBody(request);
      try{return json({success:true,...await createConanMemoryBackup(db,body.memory_scope==="personal"?"personal":"operational")},201);}
      catch(error){return errorResponse(safeString(error.message||"Sauvegarde mémoire échouée.",1000),500);}
    }
    if(method==="GET"&&path==="/api/conan/memory/backups"){
      const rows=await db.prepare("SELECT backup_id,memory_scope,checksum,verified,created_at FROM ci_conan_memory_backups ORDER BY created_at DESC LIMIT 100").all();
      return json({success:true,count:rows.results?.length||0,backups:rows.results||[]});
    }
  }
  return await conanChapter13OriginalProtectedRoutes(request,env,ctx,route);
};


/* -------------------------------------------------------------------------- */
/* CHAPITRE 14 — REGISTRE, CONNEXIONS ET GOUVERNANCE DES FOURNISSEURS          */
/* -------------------------------------------------------------------------- */

const CI_PROVIDER_CATALOGUE_VERSION = "ci-provider-catalogue-v1";
const CI_PROVIDER_CATALOGUE = [
  {id:"coingecko",name:"CoinGecko",kind:"market_data",integration:"existing",credential:"COINGECKO_API_KEY",free_tier:"plan-dependent",terms_url:"https://www.coingecko.com/en/api_terms"},
  {id:"coinmarketcap",name:"CoinMarketCap",kind:"market_data",integration:"new_isolated",credential:"COINMARKETCAP_API_KEY",free_tier:"plan-dependent",terms_url:"https://coinmarketcap.com/api/terms/"},
  {id:"dexscreener",name:"DexScreener",kind:"dex_data",integration:"existing",credential:null,free_tier:"public-endpoints; limits may apply",terms_url:"https://docs.dexscreener.com/"},
  {id:"geckoterminal",name:"GeckoTerminal",kind:"dex_data",integration:"existing",credential:null,free_tier:"public-api; limits may apply",terms_url:"https://www.geckoterminal.com/dex-api"},
  {id:"defillama",name:"DeFiLlama",kind:"defi_data",integration:"new_isolated",credential:null,free_tier:"public-endpoints; limits may apply",terms_url:"https://defillama.com/docs/api"},
  {id:"etherscan",name:"Etherscan",kind:"onchain_data",integration:"new_isolated",credential:"ETHERSCAN_API_KEY",free_tier:"plan-dependent",terms_url:"https://docs.etherscan.io/"},
  {id:"blockscout",name:"Blockscout",kind:"onchain_data",integration:"new_isolated",credential:null,free_tier:"public-instance; limits may apply",terms_url:"https://docs.blockscout.com/"},
  {id:"goplus",name:"GoPlus Security",kind:"security",integration:"existing",credential:null,free_tier:"public-api; limits may apply",terms_url:"https://docs.gopluslabs.io/"},
  {id:"honeypot",name:"Honeypot.is",kind:"security",integration:"existing",credential:null,free_tier:"public-api; limits may apply",terms_url:"https://docs.honeypot.is/"},
  {id:"gemini",name:"Google Gemini",kind:"ai",integration:"existing",credential:"GEMINI_API_KEY",free_tier:"model-and-region-dependent",terms_url:"https://ai.google.dev/gemini-api/terms"},
  {id:"groq",name:"GroqCloud",kind:"ai",integration:"existing",credential:"GROQ_API_KEY",free_tier:"model-and-account-dependent",terms_url:"https://console.groq.com/docs"},
  {id:"cloudflare",name:"Cloudflare Workers AI",kind:"ai",integration:"existing",credential:"AI binding",free_tier:"account-and-model-dependent",terms_url:"https://developers.cloudflare.com/workers-ai/"},
  {id:"sambanova",name:"SambaNova",kind:"ai",integration:"existing",credential:"SAMBANOVA_API_KEY",free_tier:"account-dependent",terms_url:"https://docs.sambanova.ai/"},
  {id:"cohere",name:"Cohere",kind:"ai",integration:"existing",credential:"COHERE_API_KEY",free_tier:"plan-and-model-dependent",terms_url:"https://docs.cohere.com/"}
];

function ciProviderCredentialAvailable(env,provider){
  if(provider==="cloudflare")return Boolean(env.AI&&typeof env.AI.run==="function");
  const item=CI_PROVIDER_CATALOGUE.find(value=>value.id===provider);
  return Boolean(item&&item.credential&&env[item.credential]);
}

function ciProviderConfigured(env,provider){
  if(["dexscreener","geckoterminal","defillama","blockscout","goplus","honeypot"].includes(provider))return true;
  return ciProviderCredentialAvailable(env,provider);
}

async function ensureCIProviderManagementTables(db){
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_provider_registry (
      provider_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0,
      authorized INTEGER NOT NULL DEFAULT 0, daily_limit INTEGER,
      monthly_limit INTEGER, quota_reset_at TEXT, terms_reviewed_at TEXT,
      last_test_at TEXT, last_test_status TEXT, last_error TEXT,
      updated_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_provider_test_history (
      test_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, test_type TEXT NOT NULL,
      status TEXT NOT NULL, http_status INTEGER, latency_ms INTEGER,
      details_json TEXT NOT NULL, tested_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_provider_usage_metrics (
      metric_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, operation TEXT,
      success INTEGER NOT NULL, status_code INTEGER, latency_ms INTEGER,
      created_at TEXT NOT NULL
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_provider_metrics_provider_date ON ci_provider_usage_metrics(provider_id,created_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_provider_tests_provider_date ON ci_provider_test_history(provider_id,tested_at)")
  ]);
  for(const item of CI_PROVIDER_CATALOGUE){
    await db.prepare("INSERT OR IGNORE INTO ci_provider_registry (provider_id,enabled,authorized,updated_at) VALUES (?,0,0,?)").bind(item.id,nowISO()).run();
  }
}

function ciProviderEnvironmentStatus(env,item){
  const configured=ciProviderConfigured(env,item.id);
  return {
    id:item.id,name:item.name,kind:item.kind,integration:item.integration,
    credential_name:item.credential,credential_configured:configured,
    status:configured?"credentials_or_public_endpoint_available":"not_configured",
    free_tier:item.free_tier,terms_url:item.terms_url,
    quota_is_provider_plan_dependent:true
  };
}

async function getCIProviderDashboard(db,env){
  await ensureCIProviderManagementTables(db);
  const registry=await db.prepare("SELECT * FROM ci_provider_registry ORDER BY provider_id").all();
  const registryMap=new Map((registry.results||[]).map(row=>[row.provider_id,row]));
  const daily=await db.prepare("SELECT provider_id,COUNT(*) AS calls,SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) AS successes,SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS failures,MAX(created_at) AS last_call FROM ci_provider_usage_metrics WHERE created_at>=? GROUP BY provider_id").bind(new Date(Date.now()-86400000).toISOString()).all();
  const dailyMap=new Map((daily.results||[]).map(row=>[row.provider_id,row]));
  const oldUsage=await db.prepare("SELECT provider,COUNT(*) AS calls,SUM(success) AS successes,MAX(created_at) AS last_call FROM ci_provider_usage WHERE created_at>=? GROUP BY provider").bind(new Date(Date.now()-86400000).toISOString()).all();
  const oldMap=new Map((oldUsage.results||[]).map(row=>[row.provider,row]));
  const providers=CI_PROVIDER_CATALOGUE.map(item=>{
    const config=registryMap.get(item.id)||{};
    const metric=dailyMap.get(item.id)||oldMap.get(item.id)||{};
    const environment=ciProviderEnvironmentStatus(env,item);
    return {
      ...environment,enabled:Boolean(config.enabled),authorized:Boolean(config.authorized),
      daily_limit:config.daily_limit??null,monthly_limit:config.monthly_limit??null,
      calls_last_24h:Number(metric.calls)||0,successes_last_24h:Number(metric.successes)||0,
      failures_last_24h:Number(metric.failures)||0,last_call:metric.last_call||null,
      last_test_at:config.last_test_at||null,last_test_status:config.last_test_status||"not_tested",
      last_error:config.last_error||null,terms_reviewed_at:config.terms_reviewed_at||null,
      reset_at:config.quota_reset_at||null,
      live_connection_verified:false
    };
  });
  return {
    catalogue_version:CI_PROVIDER_CATALOGUE_VERSION,providers,
    safeguards:{paid_subscriptions:false,automatic_paid_upgrade:false,automatic_credit_purchase:false,overage_spend:false,new_sources_require_explicit_authorization:true,credentials_in_worker_environment_only:true,quotas_without_provider_confirmation_are_unknown:true}
  };
}

async function configureCIProvider(db,env,body){
  await ensureCIProviderManagementTables(db);
  const id=safeString(body.provider_id||"",60).toLowerCase();
  const item=CI_PROVIDER_CATALOGUE.find(value=>value.id===id);
  if(!item)throw new Error("Fournisseur inconnu du catalogue.");
  if(body.authorized!==true)throw new Error("Une autorisation explicite true est requise pour activer ce fournisseur.");
  if(body.enabled!==true)throw new Error("L'activation doit être explicitement demandée avec enabled=true.");
  const daily=body.daily_limit===undefined?null:Number(body.daily_limit);
  const monthly=body.monthly_limit===undefined?null:Number(body.monthly_limit);
  if((daily!==null&&(!Number.isInteger(daily)||daily<1))||(monthly!==null&&(!Number.isInteger(monthly)||monthly<1)))throw new Error("Les plafonds configurés doivent être des entiers positifs.");
  const timestamp=nowISO();
  await db.prepare("UPDATE ci_provider_registry SET enabled=1,authorized=1,daily_limit=?,monthly_limit=?,terms_reviewed_at=?,updated_at=? WHERE provider_id=?").bind(
    daily,monthly,body.terms_reviewed===true?timestamp:null,timestamp,id
  ).run();
  await audit(db,"provider_authorized",id+" activé après autorisation explicite; aucun achat ni dépassement payant autorisé.");
  return {provider_id:id,enabled:true,authorized:true,daily_limit:daily,monthly_limit:monthly,terms_reviewed_at:body.terms_reviewed===true?timestamp:null,credentials_configured:ciProviderConfigured(env,id),paid_spend_enabled:false};
}

async function testCIProvider(db,env,providerId,body={}){
  await ensureCIProviderManagementTables(db);
  const id=safeString(providerId||"",60).toLowerCase();
  const item=CI_PROVIDER_CATALOGUE.find(value=>value.id===id);
  if(!item)throw new Error("Fournisseur inconnu.");
  const config=await db.prepare("SELECT enabled,authorized FROM ci_provider_registry WHERE provider_id=?").bind(id).first();
  if(!config||!config.enabled||!config.authorized)throw new Error("Test refusé : le fournisseur doit d'abord être autorisé et activé.");
  const started=Date.now();
  let status="failed",httpStatus=null,details={},failure=null;
  try{
    if(["gemini","groq","cloudflare","sambanova","cohere"].includes(id)){
      if(!ciProviderCredentialAvailable(env,id))throw new Error("Identifiants ou binding indisponibles dans l'environnement Worker.");
      const raw=await callAIProvider(id,env,'Réponds uniquement en JSON valide avec {"provider_test":"ok"}. Ne fournis aucune autre donnée.');
      const parsed=parseAIResponse(raw);
      details={response_received:Boolean(raw),json_parsed:!parsed.parsing_warning,provider_response_excerpt:safeString(raw,300)};
      status=raw?"completed":"empty_response";
      httpStatus=200;
    }else if(id==="coingecko"){
      const result=await externalJSON("https://api.coingecko.com/api/v3/ping",{headers:env.COINGECKO_API_KEY?{"x-cg-demo-api-key":env.COINGECKO_API_KEY}:{}});httpStatus=result.status;details={ping_received:Boolean(result.data.gecko_says)};
      status="completed";
    }else if(id==="dexscreener"){
      const result=await externalJSON("https://api.dexscreener.com/latest/dex/search?q=bitcoin");httpStatus=result.status;details={pairs_returned:Array.isArray(result.data.pairs)?result.data.pairs.length:0};status="completed";
    }else if(id==="geckoterminal"){
      const result=await externalJSON("https://api.geckoterminal.com/api/v2/networks");httpStatus=result.status;details={networks_returned:Array.isArray(result.data.data)?result.data.data.length:0};status="completed";
    }else if(id==="defillama"){
      const result=await externalJSON("https://api.llama.fi/protocols");httpStatus=result.status;details={protocols_returned:Array.isArray(result.data)?result.data.length:0};status="completed";
    }else if(id==="blockscout"){
      const result=await externalJSON("https://eth.blockscout.com/api/v2/stats");httpStatus=result.status;details={response_received:Boolean(result.data)};status="completed";
    }else if(id==="coinmarketcap"){
      if(!env.COINMARKETCAP_API_KEY)throw new Error("Secret COINMARKETCAP_API_KEY absent des secrets Worker.");
      const result=await externalJSON("https://pro-api.coinmarketcap.com/v1/cryptocurrency/map?limit=1",{headers:{"X-CMC_PRO_API_KEY":env.COINMARKETCAP_API_KEY}});httpStatus=result.status;details={assets_returned:Array.isArray(result.data.data)?result.data.data.length:0};status="completed";
    }else if(id==="etherscan"){
      if(!env.ETHERSCAN_API_KEY)throw new Error("Secret ETHERSCAN_API_KEY absent des secrets Worker.");
      const endpoint=new URL("https://api.etherscan.io/v2/api");endpoint.searchParams.set("chainid","1");endpoint.searchParams.set("module","proxy");endpoint.searchParams.set("action","eth_blockNumber");endpoint.searchParams.set("apikey",env.ETHERSCAN_API_KEY);
      const result=await externalJSON(endpoint.toString());httpStatus=result.status;details={rpc_response_received:Boolean(result.data.result)};status=result.data.result?"completed":"provider_error";
    }else if(id==="goplus"||id==="honeypot"){
      const address=safeString(body.contract_address||"",100);
      if(!/^0x[a-fA-F0-9]{40}$/.test(address))throw new Error("Ce test nécessite une adresse de contrat EVM fournie explicitement.");
      if(id==="goplus"){
        const result=await externalJSON("https://api.gopluslabs.io/api/v1/token_security/1?contract_addresses="+encodeURIComponent(address));httpStatus=result.status;details={security_result_received:Boolean(result.data.result)};status="completed";
      }else{
        const result=await externalJSON("https://api.honeypot.is/v2/IsHoneypot?chainID=1&address="+encodeURIComponent(address));httpStatus=result.status;details={analysis_received:Boolean(result.data.honeypotResult||result.data.simulationResult)};status="completed";
      }
    }else{
      throw new Error("Test isolé non défini pour ce fournisseur.");
    }
  }catch(error){
    failure=safeString(error.message||"Échec du test fournisseur.",700);
    httpStatus=error.status||httpStatus;
  }
  const latency=Date.now()-started,timestamp=nowISO(),testId=cryptoRandomId();
  await db.prepare("INSERT INTO ci_provider_test_history (test_id,provider_id,test_type,status,http_status,latency_ms,details_json,tested_at) VALUES (?,?,?,?,?,?,?,?)").bind(
    testId,id,"isolated_connection_probe",status,httpStatus,latency,JSON.stringify({...details,error:failure}),timestamp
  ).run();
  await db.prepare("UPDATE ci_provider_registry SET last_test_at=?,last_test_status=?,last_error=?,updated_at=? WHERE provider_id=?").bind(
    timestamp,status,failure,timestamp,id
  ).run();
  await db.prepare("INSERT INTO ci_provider_usage_metrics (metric_id,provider_id,operation,success,status_code,latency_ms,created_at) VALUES (?,?,?,?,?,?,?)").bind(
    cryptoRandomId(),id,"isolated_connection_probe",status==="completed"?1:0,httpStatus,latency,timestamp
  ).run();
  return {test_id:testId,provider_id:id,status,http_status:httpStatus,latency_ms:latency,details,error:failure,live_test_performed:true,asset_specific_test:id==="goplus"||id==="honeypot"};
}

async function getCIProviderUsageHistory(db,limit=100){
  await ensureCIProviderManagementTables(db);
  const rows=await db.prepare("SELECT provider_id,operation,success,status_code,latency_ms,created_at FROM ci_provider_usage_metrics ORDER BY created_at DESC LIMIT ?").bind(Math.max(1,Math.min(500,Number(limit)||100))).all();
  const tests=await db.prepare("SELECT provider_id,test_type,status,http_status,latency_ms,details_json,tested_at FROM ci_provider_test_history ORDER BY tested_at DESC LIMIT ?").bind(Math.max(1,Math.min(200,Number(limit)||100))).all();
  return {usage:rows.results||[],tests:tests.results||[]};
}

ARCHIVE_TABLES.push("ci_provider_registry","ci_provider_test_history","ci_provider_usage_metrics");

const conanChapter14OriginalProtectedRoutes = handleProtectedRoutes;
handleProtectedRoutes = async function(request,env,ctx,route){
  const {path,method,url}=route;
  const providerPaths=["/api/providers","/api/providers/usage","/api/providers/configure","/api/providers/test","/api/providers/ai"];
  if(providerPaths.includes(path)){
    const db=getDB(env);
    await initializeBackendTables(db);
    await ensureCIProviderManagementTables(db);
    if(method==="GET"&&path==="/api/providers"){
      return json({success:true,...await getCIProviderDashboard(db,env)});
    }
    if(method==="GET"&&path==="/api/providers/ai"){
      const dashboard=await getCIProviderDashboard(db,env);
      return json({success:true,providers:dashboard.providers.filter(item=>item.kind==="ai"),safeguards:dashboard.safeguards});
    }
    if(method==="GET"&&path==="/api/providers/usage"){
      return json({success:true,...await getCIProviderUsageHistory(db,url.searchParams.get("limit"))});
    }
    if(method==="POST"&&path==="/api/providers/configure"){
      try{return json({success:true,...await configureCIProvider(db,env,await readBody(request))});}
      catch(error){return errorResponse(safeString(error.message||"Configuration fournisseur refusée.",1000),400);}
    }
    if(method==="POST"&&path==="/api/providers/test"){
      const body=await readBody(request);
      try{return json({success:true,...await testCIProvider(db,env,body.provider_id,body)});}
      catch(error){return errorResponse(safeString(error.message||"Test fournisseur refusé.",1000),400);}
    }
  }
  return await conanChapter14OriginalProtectedRoutes(request,env,ctx,route);
};


/* Chapitre 14 — test isolé préalable pour les nouvelles sources. */
async function testCIProviderBeforeAuthorization(db,env,providerId){
  await ensureCIProviderManagementTables(db);
  const id=safeString(providerId||"",60).toLowerCase();
  const item=CI_PROVIDER_CATALOGUE.find(value=>value.id===id);
  if(!item||item.integration!=="new_isolated")throw new Error("Ce parcours est réservé aux nouvelles sources isolées.");
  const started=Date.now();
  let status="failed",httpStatus=null,details={},failure=null;
  try{
    if(id==="defillama"){
      const result=await externalJSON("https://api.llama.fi/protocols");
      httpStatus=result.status;details={protocols_returned:Array.isArray(result.data)?result.data.length:0};status="completed";
    }else if(id==="blockscout"){
      const result=await externalJSON("https://eth.blockscout.com/api/v2/stats");
      httpStatus=result.status;details={response_received:Boolean(result.data)};status="completed";
    }else if(id==="coinmarketcap"){
      if(!env.COINMARKETCAP_API_KEY)throw new Error("Secret COINMARKETCAP_API_KEY absent des secrets Worker.");
      const result=await externalJSON("https://pro-api.coinmarketcap.com/v1/cryptocurrency/map?limit=1",{headers:{"X-CMC_PRO_API_KEY":env.COINMARKETCAP_API_KEY}});
      httpStatus=result.status;details={assets_returned:Array.isArray(result.data.data)?result.data.data.length:0};status="completed";
    }else if(id==="etherscan"){
      if(!env.ETHERSCAN_API_KEY)throw new Error("Secret ETHERSCAN_API_KEY absent des secrets Worker.");
      const endpoint=new URL("https://api.etherscan.io/v2/api");
      endpoint.searchParams.set("chainid","1");endpoint.searchParams.set("module","proxy");endpoint.searchParams.set("action","eth_blockNumber");endpoint.searchParams.set("apikey",env.ETHERSCAN_API_KEY);
      const result=await externalJSON(endpoint.toString());httpStatus=result.status;details={rpc_response_received:Boolean(result.data.result)};
      status=result.data.result?"completed":"provider_error";
    }
  }catch(error){failure=safeString(error.message||"Échec du test isolé.",700);}
  const latency=Date.now()-started,timestamp=nowISO(),testId=cryptoRandomId();
  await db.prepare("INSERT INTO ci_provider_test_history (test_id,provider_id,test_type,status,http_status,latency_ms,details_json,tested_at) VALUES (?,?,?,?,?,?,?,?)").bind(
    testId,id,"pre_authorization_isolated_probe",status,httpStatus,latency,JSON.stringify({...details,error:failure}),timestamp
  ).run();
  await db.prepare("UPDATE ci_provider_registry SET last_test_at=?,last_test_status=?,last_error=?,updated_at=? WHERE provider_id=?").bind(timestamp,status,failure,timestamp,id).run();
  await db.prepare("INSERT INTO ci_provider_usage_metrics (metric_id,provider_id,operation,success,status_code,latency_ms,created_at) VALUES (?,?,?,?,?,?,?)").bind(
    cryptoRandomId(),id,"pre_authorization_isolated_probe",status==="completed"?1:0,httpStatus,latency,timestamp
  ).run();
  return {test_id:testId,provider_id:id,status,http_status:httpStatus,latency_ms:latency,details,error:failure,authorized:false,isolated_test_only:true};
}

const ciChapter14ConfigureAfterTest = configureCIProvider;
configureCIProvider = async function(db,env,body){
  const id=safeString(body.provider_id||"",60).toLowerCase();
  const item=CI_PROVIDER_CATALOGUE.find(value=>value.id===id);
  if(item?.integration==="new_isolated"){
    const test=await db.prepare("SELECT status FROM ci_provider_test_history WHERE provider_id=? AND test_type='pre_authorization_isolated_probe' ORDER BY tested_at DESC LIMIT 1").bind(id).first();
    if(!test||test.status!=="completed")throw new Error("Cette nouvelle source doit réussir son test isolé avant toute autorisation.");
  }
  return await ciChapter14ConfigureAfterTest(db,env,body);
};

const ciChapter14PreviousRoutes = handleProtectedRoutes;
handleProtectedRoutes = async function(request,env,ctx,route){
  if(route.path==="/api/providers/test"&&route.method==="POST"){
    const body=await readBody(request);
    const db=getDB(env);
    await initializeBackendTables(db);
    await ensureCIProviderManagementTables(db);
    const item=CI_PROVIDER_CATALOGUE.find(value=>value.id===safeString(body.provider_id||"",60).toLowerCase());
    const config=item?await db.prepare("SELECT enabled,authorized FROM ci_provider_registry WHERE provider_id=?").bind(item.id).first():null;
    if(item?.integration==="new_isolated"&&(!config||!config.authorized)){
      try{return json({success:true,...await testCIProviderBeforeAuthorization(db,env,item.id,body)});}
      catch(error){return errorResponse(safeString(error.message||"Test isolé refusé.",1000),400);}
    }
  }
  return await ciChapter14PreviousRoutes(request,env,ctx,route);
};


/* Adaptateurs de lecture contrôlée pour les nouvelles sources du catalogue. */
async function fetchCIProviderReferenceData(db,env,body){
  await ensureCIProviderManagementTables(db);
  const id=safeString(body.provider_id||"",60).toLowerCase();
  const operation=safeString(body.operation||"",60).toLowerCase();
  const config=await db.prepare("SELECT enabled,authorized FROM ci_provider_registry WHERE provider_id=?").bind(id).first();
  if(!config||!config.enabled||!config.authorized)throw new Error("Source non autorisée ou désactivée.");
  const cacheKey="ci-provider-data:"+id+":"+operation+":"+safeString(body.symbol||"",20).toUpperCase();
  const cached=await cacheGet(db,cacheKey);
  if(cached)return {...cached,cached:true};
  const started=Date.now();
  let result,statusCode=200;
  if(id==="defillama"&&operation==="protocols"){
    const response=await externalJSON("https://api.llama.fi/protocols");statusCode=response.status;
    result={provider:id,operation,data:Array.isArray(response.data)?response.data:[],fetched_at:nowISO(),cached:false};
  }else if(id==="blockscout"&&operation==="stats"){
    const response=await externalJSON("https://eth.blockscout.com/api/v2/stats");statusCode=response.status;
    result={provider:id,operation,data:response.data,fetched_at:nowISO(),cached:false};
  }else if(id==="etherscan"&&operation==="latest_block"){
    if(!env.ETHERSCAN_API_KEY)throw new Error("Secret ETHERSCAN_API_KEY absent des secrets Worker.");
    const endpoint=new URL("https://api.etherscan.io/v2/api");endpoint.searchParams.set("chainid","1");endpoint.searchParams.set("module","proxy");endpoint.searchParams.set("action","eth_blockNumber");endpoint.searchParams.set("apikey",env.ETHERSCAN_API_KEY);
    const response=await externalJSON(endpoint.toString());statusCode=response.status;
    if(!response.data.result)throw new Error(safeString(response.data.message||response.data.result||"Réponse Etherscan sans numéro de bloc.",500));
    result={provider:id,operation,chain_id:"1",block_number_hex:response.data.result,fetched_at:nowISO(),cached:false};
  }else if(id==="coinmarketcap"&&operation==="quotes_latest"){
    if(!env.COINMARKETCAP_API_KEY)throw new Error("Secret COINMARKETCAP_API_KEY absent des secrets Worker.");
    const symbol=safeString(body.symbol||"",20).toUpperCase();
    if(!/^[A-Z0-9]{2,20}$/.test(symbol))throw new Error("Un symbole de crypto-actif valide est obligatoire.");
    const endpoint=new URL("https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest");endpoint.searchParams.set("symbol",symbol);endpoint.searchParams.set("convert","USD");
    const response=await externalJSON(endpoint.toString(),{headers:{"X-CMC_PRO_API_KEY":env.COINMARKETCAP_API_KEY}});statusCode=response.status;
    result={provider:id,operation,symbol,data:response.data.data||null,fetched_at:nowISO(),cached:false};
  }else{
    throw new Error("Opération non prise en charge pour ce fournisseur. Aucune autre chaîne n'est ajoutée.");
  }
  const latency=Date.now()-started,timestamp=nowISO();
  await cacheSet(db,cacheKey,result,id==="defillama"?300:60);
  await db.prepare("INSERT INTO ci_provider_usage_metrics (metric_id,provider_id,operation,success,status_code,latency_ms,created_at) VALUES (?,?,?,?,?,?,?)").bind(
    cryptoRandomId(),id,operation,1,statusCode,latency,timestamp
  ).run();
  return {...result,latency_ms:latency};
}

const ciChapter14DashboardBeforeMonthly = getCIProviderDashboard;
getCIProviderDashboard = async function(db,env){
  const dashboard=await ciChapter14DashboardBeforeMonthly(db,env);
  const monthly=await db.prepare("SELECT provider_id,COUNT(*) AS calls,SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) AS successes,SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS failures FROM ci_provider_usage_metrics WHERE created_at>=? GROUP BY provider_id").bind(new Date(Date.now()-30*86400000).toISOString()).all();
  const monthlyMap=new Map((monthly.results||[]).map(row=>[row.provider_id,row]));
  dashboard.providers=dashboard.providers.map(item=>({...item,calls_last_30d:Number(monthlyMap.get(item.id)?.calls)||0,successes_last_30d:Number(monthlyMap.get(item.id)?.successes)||0,failures_last_30d:Number(monthlyMap.get(item.id)?.failures)||0}));
  return dashboard;
};

const ciChapter14RoutesBeforeData = handleProtectedRoutes;
handleProtectedRoutes = async function(request,env,ctx,route){
  if(route.path==="/api/providers/data"&&route.method==="POST"){
    const db=getDB(env);await initializeBackendTables(db);await ensureCIProviderManagementTables(db);
    try{return json({success:true,...await fetchCIProviderReferenceData(db,env,await readBody(request))});}
    catch(error){return errorResponse(safeString(error.message||"Lecture fournisseur impossible.",1000),400);}
  }
  return await ciChapter14RoutesBeforeData(request,env,ctx,route);
};


/* -------------------------------------------------------------------------- */
/* CHAPITRE 15 — ORCHESTRATION CENTRALE DES API, QUOTAS ET PRIORITÉS           */
/* -------------------------------------------------------------------------- */

const CI_PROVIDER_PRIORITY = {
  critical_security:1,
  new_token_pair:2,
  monitored_asset_change:3,
  opportunity_check:4,
  normal_refresh:5,
  historical_analysis:6
};
const CI_PROVIDER_PRIORITY_LABELS = Object.keys(CI_PROVIDER_PRIORITY);

async function ensureCIProviderOrchestratorTables(db){
  await ensureCIProviderManagementTables(db);
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_provider_runtime_state (
      provider_id TEXT PRIMARY KEY, paused INTEGER NOT NULL DEFAULT 0,
      cooldown_until TEXT, consecutive_errors INTEGER NOT NULL DEFAULT 0,
      last_http_429_at TEXT, last_error TEXT, updated_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_provider_request_queue (
      request_id TEXT PRIMARY KEY, dedupe_key TEXT NOT NULL,
      provider_id TEXT NOT NULL, operation TEXT NOT NULL,
      priority INTEGER NOT NULL, priority_label TEXT NOT NULL,
      payload_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
      attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3,
      next_attempt_at TEXT NOT NULL, result_json TEXT, last_error TEXT,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_provider_queue_ready ON ci_provider_request_queue(status,priority,next_attempt_at,created_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_provider_queue_dedupe ON ci_provider_request_queue(dedupe_key,status)"),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_provider_quota_events (
      event_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL,
      event_type TEXT NOT NULL, period_key TEXT, observed_count INTEGER,
      configured_limit INTEGER, details_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_provider_quota_events_provider_date ON ci_provider_quota_events(provider_id,created_at)")
  ]);
  for(const item of CI_PROVIDER_CATALOGUE){
    await db.prepare("INSERT OR IGNORE INTO ci_provider_runtime_state (provider_id,updated_at) VALUES (?,?)").bind(item.id,nowISO()).run();
  }
}

function ciProviderPeriodKeys(timestamp=new Date()){
  return {day:timestamp.toISOString().slice(0,10),month:timestamp.toISOString().slice(0,7)};
}

async function ciProviderRuntimeGate(db,providerId){
  await ensureCIProviderOrchestratorTables(db);
  const state=await db.prepare("SELECT * FROM ci_provider_runtime_state WHERE provider_id=?").bind(providerId).first();
  if(state?.paused)return {allowed:false,reason:"provider_paused",retry_at:null};
  if(state?.cooldown_until&&Date.parse(state.cooldown_until)>Date.now())return {allowed:false,reason:"provider_backoff",retry_at:state.cooldown_until};
  const registry=await db.prepare("SELECT daily_limit,monthly_limit FROM ci_provider_registry WHERE provider_id=?").bind(providerId).first();
  const keys=ciProviderPeriodKeys();
  const counts=await db.prepare(`SELECT
    SUM(CASE WHEN created_at>=? THEN 1 ELSE 0 END) AS daily_count,
    SUM(CASE WHEN created_at>=? THEN 1 ELSE 0 END) AS monthly_count
    FROM ci_provider_usage_metrics WHERE provider_id=?`).bind(
      new Date(Date.now()-86400000).toISOString(),new Date(Date.now()-30*86400000).toISOString(),providerId
    ).first();
  const daily=Number(counts?.daily_count)||0,monthly=Number(counts?.monthly_count)||0;
  if(registry?.daily_limit!==null&&registry?.daily_limit!==undefined&&daily>=Number(registry.daily_limit)){
    await ciProviderQuotaEvent(db,providerId,"daily_limit_reached",keys.day,daily,Number(registry.daily_limit),{});
    return {allowed:false,reason:"daily_limit_reached",retry_at:new Date(Date.now()+86400000).toISOString(),daily_count:daily,monthly_count:monthly};
  }
  if(registry?.monthly_limit!==null&&registry?.monthly_limit!==undefined&&monthly>=Number(registry.monthly_limit)){
    await ciProviderQuotaEvent(db,providerId,"monthly_limit_reached",keys.month,monthly,Number(registry.monthly_limit),{});
    return {allowed:false,reason:"monthly_limit_reached",retry_at:null,daily_count:daily,monthly_count:monthly};
  }
  return {allowed:true,daily_count:daily,monthly_count:monthly,daily_limit:registry?.daily_limit??null,monthly_limit:registry?.monthly_limit??null};
}

async function ciProviderQuotaEvent(db,providerId,eventType,periodKey,count,limit,details){
  await db.prepare("INSERT INTO ci_provider_quota_events (event_id,provider_id,event_type,period_key,observed_count,configured_limit,details_json,created_at) VALUES (?,?,?,?,?,?,?,?)").bind(
    cryptoRandomId(),providerId,eventType,periodKey,count,limit,JSON.stringify(details||{}),nowISO()
  ).run();
}

async function ciRecordManagedProviderResult(db,providerId,operation,success,statusCode,latencyMs,errorMessage=null){
  await ensureCIProviderOrchestratorTables(db);
  const timestamp=nowISO();
  await db.prepare("INSERT INTO ci_provider_usage_metrics (metric_id,provider_id,operation,success,status_code,latency_ms,created_at) VALUES (?,?,?,?,?,?,?)").bind(
    cryptoRandomId(),providerId,operation,success?1:0,statusCode||null,Math.max(0,Number(latencyMs)||0),timestamp
  ).run();
  const state=await db.prepare("SELECT consecutive_errors FROM ci_provider_runtime_state WHERE provider_id=?").bind(providerId).first();
  const errors=success?0:(Number(state?.consecutive_errors)||0)+1;
  const retryDelay=success?0:Math.min(15*60,Math.pow(2,Math.min(errors-1,4))*60);
  const cooldown=success?null:new Date(Date.now()+retryDelay*1000).toISOString();
  await db.prepare("UPDATE ci_provider_runtime_state SET consecutive_errors=?,cooldown_until=?,last_http_429_at=CASE WHEN ?=429 THEN ? ELSE last_http_429_at END,last_error=?,updated_at=? WHERE provider_id=?").bind(
    errors,cooldown,Number(statusCode)||0,timestamp,errorMessage?safeString(errorMessage,700):null,timestamp,providerId
  ).run();
  if(!success)await ciProviderQuotaEvent(db,providerId,Number(statusCode)===429?"http_429_backoff":"provider_failure",null,errors,null,{status_code:statusCode||null,retry_at:cooldown,error:errorMessage||null});
  return {consecutive_errors:errors,cooldown_until:cooldown};
}

async function enqueueCIProviderRequest(db,body){
  await ensureCIProviderOrchestratorTables(db);
  const provider=safeString(body.provider_id||"",60).toLowerCase();
  const operation=safeString(body.operation||"",60).toLowerCase();
  const priorityLabel=safeString(body.priority||"normal_refresh",50);
  const priority=CI_PROVIDER_PRIORITY[priorityLabel];
  if(!CI_PROVIDER_CATALOGUE.some(item=>item.id===provider))throw new Error("Fournisseur inconnu.");
  if(!priority)throw new Error("Priorité inconnue.");
  const payload={symbol:safeString(body.symbol||"",20).toUpperCase()};
  if(body.contract_address)payload.contract_address=safeString(body.contract_address,100);
  const allowed={
    defillama:["protocols"],blockscout:["stats"],etherscan:["latest_block"],
    coinmarketcap:["quotes_latest"]
  };
  if(!allowed[provider]?.includes(operation))throw new Error("Opération absente de la liste blanche du gestionnaire central.");
  if(operation==="quotes_latest"&&!/^[A-Z0-9]{2,20}$/.test(payload.symbol))throw new Error("Symbole valide obligatoire.");
  const dedupeKey=provider+":"+operation+":"+payload.symbol+":"+payload.contract_address;
  const existing=await db.prepare("SELECT request_id,status FROM ci_provider_request_queue WHERE dedupe_key=? AND status IN ('pending','running') ORDER BY created_at DESC LIMIT 1").bind(dedupeKey).first();
  if(existing)return {request_id:existing.request_id,status:existing.status,deduplicated:true,priority:priorityLabel};
  const id=cryptoRandomId(),timestamp=nowISO();
  await db.prepare("INSERT INTO ci_provider_request_queue (request_id,dedupe_key,provider_id,operation,priority,priority_label,payload_json,status,attempts,max_attempts,next_attempt_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'pending',0,3,?,?,?)").bind(
    id,dedupeKey,provider,operation,priority,priorityLabel,JSON.stringify(payload),timestamp,timestamp,timestamp
  ).run();
  return {request_id:id,status:"pending",deduplicated:false,priority:priorityLabel};
}

async function processCIProviderQueue(db,env,limit=5){
  await ensureCIProviderOrchestratorTables(db);
  const max=Math.max(1,Math.min(10,Number(limit)||5));
  const ready=await db.prepare("SELECT * FROM ci_provider_request_queue WHERE status='pending' AND next_attempt_at<=? ORDER BY priority ASC,created_at ASC LIMIT ?").bind(nowISO(),max).all();
  const results=[];
  for(const job of ready.results||[]){
    const gate=await ciProviderRuntimeGate(db,job.provider_id);
    if(!gate.allowed){
      results.push({request_id:job.request_id,status:"deferred",reason:gate.reason,retry_at:gate.retry_at});
      if(gate.retry_at)await db.prepare("UPDATE ci_provider_request_queue SET next_attempt_at=?,updated_at=? WHERE request_id=? AND status='pending'").bind(gate.retry_at,nowISO(),job.request_id).run();
      continue;
    }
    const claim=await db.prepare("UPDATE ci_provider_request_queue SET status='running',attempts=attempts+1,updated_at=? WHERE request_id=? AND status='pending'").bind(nowISO(),job.request_id).run();
    if(!claim.meta?.changes)continue;
    const started=Date.now();
    try{
      const payload=JSON.parse(job.payload_json||"{}");
      const data=await fetchCIProviderReferenceData(db,env,{provider_id:job.provider_id,operation:job.operation,...payload});
      await ciRecordManagedProviderResult(db,job.provider_id,job.operation,true,200,Date.now()-started,null);
      await db.prepare("UPDATE ci_provider_request_queue SET status='completed',result_json=?,last_error=NULL,updated_at=? WHERE request_id=?").bind(JSON.stringify(data),nowISO(),job.request_id).run();
      results.push({request_id:job.request_id,status:"completed",provider_id:job.provider_id,operation:job.operation});
    }catch(error){
      const message=safeString(error.message||"Erreur fournisseur.",700),statusCode=Number(error.status)||null;
      const state=await ciRecordManagedProviderResult(db,job.provider_id,job.operation,false,statusCode,Date.now()-started,message);
      const attempts=Number(job.attempts)+1,canRetry=attempts<Number(job.max_attempts);
      const next=state.cooldown_until||new Date(Date.now()+60000).toISOString();
      await db.prepare("UPDATE ci_provider_request_queue SET status=?,next_attempt_at=?,last_error=?,updated_at=? WHERE request_id=?").bind(
        canRetry?"pending":"failed",next,message,nowISO(),job.request_id
      ).run();
      results.push({request_id:job.request_id,status:canRetry?"retry_scheduled":"failed",error:message,retry_at:canRetry?next:null});
    }
  }
  return {processed:results.length,results,priority_order:"critical_security_to_historical_analysis",paid_overage:false};
}

async function getCIProviderQueueDashboard(db,limit=100){
  await ensureCIProviderOrchestratorTables(db);
  const jobs=await db.prepare("SELECT request_id,provider_id,operation,priority_label,status,attempts,max_attempts,next_attempt_at,last_error,created_at,updated_at FROM ci_provider_request_queue ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'running' THEN 1 ELSE 2 END,priority ASC,created_at ASC LIMIT ?").bind(Math.max(1,Math.min(300,Number(limit)||100))).all();
  const states=await db.prepare("SELECT * FROM ci_provider_runtime_state ORDER BY provider_id").all();
  const quota=await db.prepare("SELECT provider_id,event_type,period_key,observed_count,configured_limit,details_json,created_at FROM ci_provider_quota_events ORDER BY created_at DESC LIMIT ?").bind(Math.max(1,Math.min(200,Number(limit)||100))).all();
  return {queue:jobs.results||[],provider_states:states.results||[],quota_events:quota.results||[],priorities:CI_PROVIDER_PRIORITY};
}

async function setCIProviderRuntimeControl(db,body){
  await ensureCIProviderOrchestratorTables(db);
  const id=safeString(body.provider_id||"",60).toLowerCase();
  if(!CI_PROVIDER_CATALOGUE.some(item=>item.id===id))throw new Error("Fournisseur inconnu.");
  if(typeof body.paused!=="boolean")throw new Error("paused doit être true ou false.");
  const timestamp=nowISO();
  await db.prepare("UPDATE ci_provider_runtime_state SET paused=?,cooldown_until=CASE WHEN ?=1 THEN NULL ELSE cooldown_until END,updated_at=? WHERE provider_id=?").bind(body.paused?1:0,body.paused?1:0,timestamp,id).run();
  await audit(db,body.paused?"provider_paused":"provider_resumed",id);
  return {provider_id:id,paused:body.paused,updated_at:timestamp};
}

const ciChapter15OriginalFetchProviderData = fetchCIProviderReferenceData;
fetchCIProviderReferenceData = async function(db,env,body){
  const id=safeString(body.provider_id||"",60).toLowerCase();
  const operation=safeString(body.operation||"",60).toLowerCase();
  const gate=await ciProviderRuntimeGate(db,id);
  if(!gate.allowed){
    const error=new Error("Requête fournisseur différée : "+gate.reason);
    error.status=429;error.retry_at=gate.retry_at;throw error;
  }
  const started=Date.now();
  try{
    const result=await ciChapter15OriginalFetchProviderData(db,env,body);
    await ciRecordManagedProviderResult(db,id,operation,true,200,Date.now()-started,null);
    return result;
  }catch(error){
    if(error.status!==429||!String(error.message||"").includes("différée"))await ciRecordManagedProviderResult(db,id,operation,false,error.status||500,Date.now()-started,error.message);
    throw error;
  }
};

const ciChapter15OriginalCallAIProvider = callAIProvider;
callAIProvider = async function(provider,env,prompt){
  const db=env?.DB;
  if(!db)return await ciChapter15OriginalCallAIProvider(provider,env,prompt);
  const gate=await ciProviderRuntimeGate(db,provider);
  if(!gate.allowed){
    const error=new Error("Fournisseur IA différé par le gestionnaire central : "+gate.reason);
    error.status=429;error.retry_at=gate.retry_at;throw error;
  }
  const started=Date.now();
  try{
    const result=await ciChapter15OriginalCallAIProvider(provider,env,prompt);
    await ciRecordManagedProviderResult(db,provider,"ai_inference",true,200,Date.now()-started,null);
    return result;
  }catch(error){
    await ciRecordManagedProviderResult(db,provider,"ai_inference",false,error.status||500,Date.now()-started,error.message);
    throw error;
  }
};

const ciChapter15PreviousRoutes = handleProtectedRoutes;
handleProtectedRoutes = async function(request,env,ctx,route){
  const {path,method,url}=route;
  const managedPaths=["/api/providers/queue","/api/providers/queue/process","/api/providers/control"];
  if(managedPaths.includes(path)){
    const db=getDB(env);await initializeBackendTables(db);await ensureCIProviderOrchestratorTables(db);
    if(method==="GET"&&path==="/api/providers/queue"){
      return json({success:true,...await getCIProviderQueueDashboard(db,url.searchParams.get("limit"))});
    }
    if(method==="POST"&&path==="/api/providers/queue"){
      try{return json({success:true,...await enqueueCIProviderRequest(db,await readBody(request))},201);}
      catch(error){return errorResponse(safeString(error.message||"Mise en file refusée.",1000),400);}
    }
    if(method==="POST"&&path==="/api/providers/queue/process"){
      try{return json({success:true,...await processCIProviderQueue(db,env,(await readBody(request)).limit)});}
      catch(error){return errorResponse(safeString(error.message||"Traitement de file impossible.",1000),500);}
    }
    if(method==="POST"&&path==="/api/providers/control"){
      try{return json({success:true,...await setCIProviderRuntimeControl(db,await readBody(request))});}
      catch(error){return errorResponse(safeString(error.message||"Contrôle fournisseur refusé.",1000),400);}
    }
  }
  return await ciChapter15PreviousRoutes(request,env,ctx,route);
};


/* Chapitre 15 — alignement des quotas sur les périodes calendaires et comptage unique. */
ciProviderPeriodKeys = function(timestamp=new Date()){
  return {day:timestamp.toISOString().slice(0,10),month:timestamp.toISOString().slice(0,7)};
};
ciProviderRuntimeGate = async function(db,providerId){
  await ensureCIProviderOrchestratorTables(db);
  const state=await db.prepare("SELECT * FROM ci_provider_runtime_state WHERE provider_id=?").bind(providerId).first();
  if(state?.paused)return {allowed:false,reason:"provider_paused",retry_at:null};
  if(state?.cooldown_until&&Date.parse(state.cooldown_until)>Date.now())return {allowed:false,reason:"provider_backoff",retry_at:state.cooldown_until};
  const registry=await db.prepare("SELECT daily_limit,monthly_limit FROM ci_provider_registry WHERE provider_id=?").bind(providerId).first();
  const now=new Date(),keys=ciProviderPeriodKeys(now);
  const dayStart=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate())).toISOString();
  const monthStart=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),1)).toISOString();
  const counts=await db.prepare("SELECT SUM(CASE WHEN created_at>=? THEN 1 ELSE 0 END) AS daily_count,SUM(CASE WHEN created_at>=? THEN 1 ELSE 0 END) AS monthly_count FROM ci_provider_usage_metrics WHERE provider_id=?").bind(dayStart,monthStart,providerId).first();
  const daily=Number(counts?.daily_count)||0,monthly=Number(counts?.monthly_count)||0;
  if(registry?.daily_limit!==null&&registry?.daily_limit!==undefined&&daily>=Number(registry.daily_limit)){
    await ciProviderQuotaEvent(db,providerId,"daily_limit_reached",keys.day,daily,Number(registry.daily_limit),{});
    return {allowed:false,reason:"daily_limit_reached",retry_at:new Date(dayStart).getTime()+86400000?new Date(Date.parse(dayStart)+86400000).toISOString():null,daily_count:daily,monthly_count:monthly};
  }
  if(registry?.monthly_limit!==null&&registry?.monthly_limit!==undefined&&monthly>=Number(registry.monthly_limit)){
    await ciProviderQuotaEvent(db,providerId,"monthly_limit_reached",keys.month,monthly,Number(registry.monthly_limit),{});
    return {allowed:false,reason:"monthly_limit_reached",retry_at:new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth()+1,1)).toISOString(),daily_count:daily,monthly_count:monthly};
  }
  return {allowed:true,daily_count:daily,monthly_count:monthly,daily_limit:registry?.daily_limit??null,monthly_limit:registry?.monthly_limit??null};
};

async function processCIProviderQueue(db,env,limit=5){
  await ensureCIProviderOrchestratorTables(db);
  const max=Math.max(1,Math.min(10,Number(limit)||5));
  const ready=await db.prepare("SELECT * FROM ci_provider_request_queue WHERE status='pending' AND next_attempt_at<=? ORDER BY priority ASC,created_at ASC LIMIT ?").bind(nowISO(),max).all();
  const results=[];
  for(const job of ready.results||[]){
    const gate=await ciProviderRuntimeGate(db,job.provider_id);
    if(!gate.allowed){
      results.push({request_id:job.request_id,status:"deferred",reason:gate.reason,retry_at:gate.retry_at});
      if(gate.retry_at)await db.prepare("UPDATE ci_provider_request_queue SET next_attempt_at=?,updated_at=? WHERE request_id=? AND status='pending'").bind(gate.retry_at,nowISO(),job.request_id).run();
      continue;
    }
    const claim=await db.prepare("UPDATE ci_provider_request_queue SET status='running',attempts=attempts+1,updated_at=? WHERE request_id=? AND status='pending'").bind(nowISO(),job.request_id).run();
    if(!claim.meta?.changes)continue;
    const started=Date.now();
    try{
      const payload=JSON.parse(job.payload_json||"{}");
      const data=await ciChapter15OriginalFetchProviderData(db,env,{provider_id:job.provider_id,operation:job.operation,...payload});
      await ciRecordManagedProviderResult(db,job.provider_id,job.operation,true,200,Date.now()-started,null);
      await db.prepare("UPDATE ci_provider_request_queue SET status='completed',result_json=?,last_error=NULL,updated_at=? WHERE request_id=?").bind(JSON.stringify(data),nowISO(),job.request_id).run();
      results.push({request_id:job.request_id,status:"completed",provider_id:job.provider_id,operation:job.operation});
    }catch(error){
      const message=safeString(error.message||"Erreur fournisseur.",700),statusCode=Number(error.status)||null;
      const state=await ciRecordManagedProviderResult(db,job.provider_id,job.operation,false,statusCode,Date.now()-started,message);
      const attempts=Number(job.attempts)+1,canRetry=attempts<Number(job.max_attempts);
      const next=state.cooldown_until||new Date(Date.now()+60000).toISOString();
      await db.prepare("UPDATE ci_provider_request_queue SET status=?,next_attempt_at=?,last_error=?,updated_at=? WHERE request_id=?").bind(canRetry?"pending":"failed",next,message,nowISO(),job.request_id).run();
      results.push({request_id:job.request_id,status:canRetry?"retry_scheduled":"failed",error:message,retry_at:canRetry?next:null});
    }
  }
  return {processed:results.length,results,priority_order:"critical_security_to_historical_analysis",paid_overage:false};
}

function ciProviderIdFromLegacyName(name){
  const value=safeString(name||"",100).toLowerCase();
  if(value.includes("coingecko"))return "coingecko";
  if(value.includes("coinmarketcap")||value==="cmc")return "coinmarketcap";
  if(value.includes("dexscreener"))return "dexscreener";
  if(value.includes("geckoterminal"))return "geckoterminal";
  if(value.includes("defillama"))return "defillama";
  if(value.includes("etherscan"))return "etherscan";
  if(value.includes("blockscout"))return "blockscout";
  if(value.includes("goplus"))return "goplus";
  if(value.includes("honeypot"))return "honeypot";
  if(["gemini","groq","cloudflare","sambanova","cohere"].includes(value))return value;
  return null;
}

const ciChapter15OriginalRecordProviderUsage=recordProviderUsage;
recordProviderUsage=async function(db,provider,success,statusCode){
  await ciChapter15OriginalRecordProviderUsage(db,provider,success,statusCode);
  const id=ciProviderIdFromLegacyName(provider);
  if(!id)return;
  try{
    const existing=await db.prepare("SELECT metric_id FROM ci_provider_usage_metrics WHERE provider_id=? AND operation=? AND created_at>=? ORDER BY created_at DESC LIMIT 1").bind(id,"legacy_provider_call",new Date(Date.now()-5000).toISOString()).first();
    if(existing)return;
    await ciRecordManagedProviderResult(db,id,"legacy_provider_call",Boolean(success),statusCode||null,0,success?null:"Échec signalé par l'adaptateur existant.");
  }catch(error){console.error("Central provider metrics error:",error);}
};

const ciChapter15OriginalFetchRadarSource=fetchRadarSource;
fetchRadarSource=async function(db,provider,url){
  const id=ciProviderIdFromLegacyName(provider);
  if(id){
    const gate=await ciProviderRuntimeGate(db,id);
    if(!gate.allowed)return {ok:false,error:"Requête suspendue par le gestionnaire central: "+gate.reason,retry_at:gate.retry_at||null};
  }
  return await ciChapter15OriginalFetchRadarSource(db,provider,url);
};

const ciChapter15OriginalHoneypot=verifyRadarTokenWithHoneypot;
verifyRadarTokenWithHoneypot=async function(db,item){
  const gate=await ciProviderRuntimeGate(db,"honeypot");
  if(!gate.allowed)return {discovery_key:item.discovery_key,outcome:"unknown",simulation_success:null,risk:"unknown",checked_at:nowISO(),next_check_at:gate.retry_at,evidence:{provider:"Honeypot.is",deferred_by_provider_manager:true,reason:gate.reason},error_message:null};
  return await ciChapter15OriginalHoneypot(db,item);
};

const ciChapter15OriginalGoPlus=verifyRadarTokenWithGoPlus;
verifyRadarTokenWithGoPlus=async function(db,item){
  const gate=await ciProviderRuntimeGate(db,"goplus");
  if(!gate.allowed)return {check_key:item.discovery_key+":goplus",discovery_key:item.discovery_key,provider:"GoPlus",outcome:"unknown",checked_at:nowISO(),evidence:{deferred_by_provider_manager:true,reason:gate.reason},error_message:null};
  return await ciChapter15OriginalGoPlus(db,item);
};


/* Chapitre 15 — comptabilisation exacte des appels et exécution unique des jobs. */
recordProviderUsage=async function(db,provider,success,statusCode){
  await ciChapter15OriginalRecordProviderUsage(db,provider,success,statusCode);
  const id=ciProviderIdFromLegacyName(provider);
  if(id){
    try{await ciRecordManagedProviderResult(db,id,"legacy_provider_call",Boolean(success),statusCode||null,0,success?null:"Échec signalé par l'adaptateur existant.");}
    catch(error){console.error("Central provider metrics error:",error);}
  }
};

processCIProviderQueue=async function(db,env,limit=5){
  await ensureCIProviderOrchestratorTables(db);
  const max=Math.max(1,Math.min(10,Number(limit)||5));
  const ready=await db.prepare("SELECT * FROM ci_provider_request_queue WHERE status='pending' AND next_attempt_at<=? ORDER BY priority ASC,created_at ASC LIMIT ?").bind(nowISO(),max).all();
  const results=[];
  for(const job of ready.results||[]){
    const gate=await ciProviderRuntimeGate(db,job.provider_id);
    if(!gate.allowed){
      results.push({request_id:job.request_id,status:"deferred",reason:gate.reason,retry_at:gate.retry_at});
      if(gate.retry_at)await db.prepare("UPDATE ci_provider_request_queue SET next_attempt_at=?,updated_at=? WHERE request_id=? AND status='pending'").bind(gate.retry_at,nowISO(),job.request_id).run();
      continue;
    }
    const claim=await db.prepare("UPDATE ci_provider_request_queue SET status='running',attempts=attempts+1,updated_at=? WHERE request_id=? AND status='pending'").bind(nowISO(),job.request_id).run();
    if(!claim.meta?.changes)continue;
    try{
      const payload=JSON.parse(job.payload_json||"{}");
      const data=await fetchCIProviderReferenceData(db,env,{provider_id:job.provider_id,operation:job.operation,...payload});
      await db.prepare("UPDATE ci_provider_request_queue SET status='completed',result_json=?,last_error=NULL,updated_at=? WHERE request_id=?").bind(JSON.stringify(data),nowISO(),job.request_id).run();
      results.push({request_id:job.request_id,status:"completed",provider_id:job.provider_id,operation:job.operation});
    }catch(error){
      const message=safeString(error.message||"Erreur fournisseur.",700);
      const attempts=Number(job.attempts)+1,canRetry=attempts<Number(job.max_attempts);
      const state=await db.prepare("SELECT cooldown_until FROM ci_provider_runtime_state WHERE provider_id=?").bind(job.provider_id).first();
      const next=state?.cooldown_until||new Date(Date.now()+60000).toISOString();
      await db.prepare("UPDATE ci_provider_request_queue SET status=?,next_attempt_at=?,last_error=?,updated_at=? WHERE request_id=?").bind(canRetry?"pending":"failed",next,message,nowISO(),job.request_id).run();
      results.push({request_id:job.request_id,status:canRetry?"retry_scheduled":"failed",error:message,retry_at:canRetry?next:null});
    }
  }
  return {processed:results.length,results,priority_order:"critical_security_to_historical_analysis",paid_overage:false};
};


/* Chapitre 15 — éviter le double comptage des inférences IA et des lectures en file. */
fetchCIProviderReferenceData=async function(db,env,body){
  const id=safeString(body.provider_id||"",60).toLowerCase();
  const operation=safeString(body.operation||"",60).toLowerCase();
  const gate=await ciProviderRuntimeGate(db,id);
  if(!gate.allowed){
    const error=new Error("Requête fournisseur différée : "+gate.reason);error.status=429;error.retry_at=gate.retry_at;throw error;
  }
  const started=Date.now();
  try{
    const result=await ciChapter15OriginalFetchProviderData(db,env,body);
    await db.prepare("UPDATE ci_provider_runtime_state SET consecutive_errors=0,cooldown_until=NULL,last_error=NULL,updated_at=? WHERE provider_id=?").bind(nowISO(),id).run();
    return result;
  }catch(error){
    if(!(error.status===429&&String(error.message||"").includes("différée"))){
      await ciRecordManagedProviderResult(db,id,operation,false,error.status||500,Date.now()-started,error.message);
    }
    throw error;
  }
};

callAIProvider=async function(provider,env,prompt){
  const db=env?.DB;
  if(!db)return await ciChapter15OriginalCallAIProvider(provider,env,prompt);
  const gate=await ciProviderRuntimeGate(db,provider);
  if(!gate.allowed){
    const error=new Error("Fournisseur IA différé par le gestionnaire central : "+gate.reason);
    error.status=429;error.retry_at=gate.retry_at;throw error;
  }
  return await ciChapter15OriginalCallAIProvider(provider,env,prompt);
};


/* Chapitre 15 — repli IA contrôlé, uniquement entre fournisseurs configurés. */
async function callCIProviderWithFallback(env,db,prompt,preferredProvider){
  const configured=availableAIProviders(env);
  const preferred=safeString(preferredProvider||"",40).toLowerCase();
  const order=[preferred,...configured.filter(id=>id!==preferred)].filter((id,index,array)=>configured.includes(id)&&array.indexOf(id)===index).slice(0,5);
  if(!order.length)throw new Error("Aucun fournisseur IA configuré pour le repli.");
  const attempts=[];
  for(const provider of order){
    const gate=await ciProviderRuntimeGate(db,provider);
    if(!gate.allowed){
      attempts.push({provider,status:"deferred",reason:gate.reason,retry_at:gate.retry_at||null});
      continue;
    }
    const started=Date.now();
    try{
      const response=await ciChapter15OriginalCallAIProvider(provider,env,prompt);
      await recordProviderUsage(db,provider,true,200);
      attempts.push({provider,status:"completed",latency_ms:Date.now()-started});
      return {success:true,provider_used:provider,response,attempts,fallback_used:provider!==preferred};
    }catch(error){
      const message=safeString(error.message||"Erreur IA.",500);
      await recordProviderUsage(db,provider,false,error.status||500);
      attempts.push({provider,status:"failed",error:message});
    }
  }
  return {success:false,provider_used:null,response:null,attempts,fallback_used:false};
}

const ciChapter15RoutesBeforeFallback=handleProtectedRoutes;
handleProtectedRoutes=async function(request,env,ctx,route){
  if(route.path==="/api/providers/ai/fallback"&&route.method==="POST"){
    const db=getDB(env);await initializeBackendTables(db);await ensureCIProviderOrchestratorTables(db);
    try{
      const body=await readBody(request);
      const prompt=safeString(body.prompt||"",20000);
      if(!prompt)throw new Error("Le prompt est obligatoire.");
      const result=await callCIProviderWithFallback(env,db,prompt,body.preferred_provider);
      return json({success:result.success,...result,fallback_may_change_model:true});
    }catch(error){return errorResponse(safeString(error.message||"Repli IA impossible.",1000),400);}
  }
  return await ciChapter15RoutesBeforeFallback(request,env,ctx,route);
};


/* -------------------------------------------------------------------------- */
/* CHAPITRE 16 — CANAL TELEGRAM PRIVÉ, ALERTES CONTRÔLÉES ET HISTORIQUE       */
/* -------------------------------------------------------------------------- */

const CI_TELEGRAM_ALERT_CATEGORIES = [
  "critical_security","new_token","liquidity_change","whale_activity",
  "investment_opportunity","prediction","system"
];


async function ensureCITelegramTables(db){
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_telegram_alert_queue (
      alert_id TEXT PRIMARY KEY, dedupe_key TEXT NOT NULL UNIQUE,
      category TEXT NOT NULL, asset_name TEXT, asset_symbol TEXT,
      chain TEXT, contract_address TEXT, details TEXT NOT NULL,
      app_url TEXT, status TEXT NOT NULL DEFAULT 'pending',
      attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL,
      telegram_message_id TEXT, last_error TEXT,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, sent_at TEXT
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_telegram_queue_ready ON ci_telegram_alert_queue(status,next_attempt_at,created_at)"),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_telegram_alert_history (
      history_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL,
      category TEXT NOT NULL, asset_symbol TEXT, chain TEXT,
      contract_address TEXT, status TEXT NOT NULL,
      telegram_message_id TEXT, error TEXT, event_at TEXT NOT NULL
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_ci_telegram_history_date ON ci_telegram_alert_history(event_at DESC)"),
    db.prepare(`CREATE TABLE IF NOT EXISTS ci_telegram_rate_limits (
      category TEXT NOT NULL, dedupe_key TEXT NOT NULL,
      last_sent_at TEXT NOT NULL, PRIMARY KEY(category,dedupe_key)
    )`)
  ]);
}

function ciTelegramAssetIdentity(asset){
  return [
    safeString(asset?.chain||"unknown",60).toLowerCase(),
    safeString(asset?.contract_address||asset?.pair_address||asset?.symbol||asset?.name||"unknown",160).toLowerCase()
  ].join(":");
}

function ciTelegramDedupeKey(asset,category,details){
  const identity=ciTelegramAssetIdentity(asset);
  const normalized=safeString(details||"",2000).toLowerCase().replace(/\\s+/g," ").trim();
  let hash=2166136261;
  const source=category+":"+identity+":"+normalized;
  for(let i=0;i<source.length;i++){hash^=source.charCodeAt(i);hash=Math.imul(hash,16777619);}
  return category+":"+identity+":"+((hash>>>0).toString(16));
}

async function enqueueCITelegramAlert(db,body,env){
  await ensureCITelegramTables(db);
  const asset=body.asset||{};
  const category=safeString(body.category||"",60).toLowerCase();
  const details=safeString(body.details||"",2000).trim();
  if(!CI_TELEGRAM_ALERT_CATEGORIES.includes(category))throw new Error("Catégorie d'alerte non autorisée.");
  if(!details)throw new Error("Le détail de l'alerte est obligatoire.");
  const name=safeString(asset.name||"Token inconnu",100);
  const symbol=safeString(asset.symbol||"N/A",30);
  const chain=safeString(asset.chain||"Chaîne inconnue",60);
  const contract=safeString(asset.contract_address||asset.pair_address||"",160);
  if(!asset.name&&!asset.symbol&&!asset.contract_address)throw new Error("L'alerte doit identifier son actif.");
  const dedupe=ciTelegramDedupeKey(asset,category,details);
  const existing=await db.prepare("SELECT alert_id,status FROM ci_telegram_alert_queue WHERE dedupe_key=?").bind(dedupe).first();
  if(existing)return {alert_id:existing.alert_id,status:existing.status,deduplicated:true};
  const id=cryptoRandomId(),timestamp=nowISO();
  await db.prepare("INSERT INTO ci_telegram_alert_queue (alert_id,dedupe_key,category,asset_name,asset_symbol,chain,contract_address,details,app_url,status,attempts,next_attempt_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,'pending',0,?,?,?)").bind(
    id,dedupe,category,name,symbol,chain,contract,details,
    safeString(body.app_url||env.APP_ORIGIN||"",500),timestamp,timestamp,timestamp
  ).run();
  await db.prepare("INSERT INTO ci_telegram_alert_history (history_id,alert_id,category,asset_symbol,chain,contract_address,status,event_at) VALUES (?,?,?,?,?,?,?,?)").bind(
    cryptoRandomId(),id,category,symbol,chain,contract,"queued",timestamp
  ).run();
  return {alert_id:id,status:"pending",deduplicated:false};
}

async function verifyCITelegramChannel(env){
  if(!env.TELEGRAM_BOT_TOKEN||!env.TELEGRAM_CHAT_ID)throw new Error("Secrets Telegram absents. Configurez-les dans Cloudflare Worker.");
  const base="https://api.telegram.org/bot"+env.TELEGRAM_BOT_TOKEN+"/";
  const me=await externalJSON(base+"getMe");
  if(!me.data?.ok||!me.data.result?.id)throw new Error("Impossible de vérifier l'identité du bot Telegram.");
  const chat=await externalJSON(base+"getChat?chat_id="+encodeURIComponent(env.TELEGRAM_CHAT_ID));
  if(!chat.data?.ok||chat.data.result?.type!=="channel")throw new Error("La destination configurée n'est pas un canal Telegram.");
  const member=await externalJSON(base+"getChatMember?chat_id="+encodeURIComponent(env.TELEGRAM_CHAT_ID)+"&user_id="+me.data.result.id);
  const role=member.data?.result;
  const canPost=Boolean(role&&(role.status==="creator"||(role.status==="administrator"&&role.can_post_messages!==false)));
  return {
    bot_username:me.data.result.username||null,
    channel_title:chat.data.result.title||null,
    channel_type:chat.data.result.type,
    bot_status:role?.status||"unknown",
    bot_can_post:canPost,
    verified:canPost,
    subscribers_read_only_by_channel_type:true,
    only_application_backend_exposes_posting_routes:true
  };
}

async function dispatchCITelegramAlerts(db,env,limit=10){
  await ensureCITelegramTables(db);
  const max=Math.max(1,Math.min(25,Number(limit)||10));
  const ready=await db.prepare("SELECT * FROM ci_telegram_alert_queue WHERE status='pending' AND next_attempt_at<=? ORDER BY created_at ASC LIMIT ?").bind(nowISO(),max).all();
  const results=[];
  for(const alert of ready.results||[]){
    const claim=await db.prepare("UPDATE ci_telegram_alert_queue SET status='sending',attempts=attempts+1,updated_at=? WHERE alert_id=? AND status='pending'").bind(nowISO(),alert.alert_id).run();
    if(!claim.meta?.changes)continue;
    try{
      const message=buildAssetAlert({
        name:alert.asset_name,symbol:alert.asset_symbol,chain:alert.chain,
        contract_address:alert.contract_address
      },alert.category,alert.details,alert.app_url);
      const sent=await sendTelegram(env,message);
      const timestamp=nowISO();
      await db.prepare("UPDATE ci_telegram_alert_queue SET status='sent',telegram_message_id=?,last_error=NULL,sent_at=?,updated_at=? WHERE alert_id=?").bind(
        String(sent.message_id||""),timestamp,timestamp,alert.alert_id
      ).run();
      await db.prepare("INSERT INTO ci_telegram_alert_history (history_id,alert_id,category,asset_symbol,chain,contract_address,status,telegram_message_id,event_at) VALUES (?,?,?,?,?,?,?,?,?)").bind(
        cryptoRandomId(),alert.alert_id,alert.category,alert.asset_symbol,alert.chain,alert.contract_address,"sent",String(sent.message_id||""),timestamp
      ).run();
      results.push({alert_id:alert.alert_id,status:"sent",message_id:sent.message_id});
    }catch(error){
      const message=safeString(error.message||"Erreur Telegram.",700);
      const attempts=Number(alert.attempts)+1,canRetry=attempts<4;
      const next=new Date(Date.now()+Math.min(3600000,60000*Math.pow(2,attempts-1))).toISOString();
      const timestamp=nowISO();
      await db.prepare("UPDATE ci_telegram_alert_queue SET status=?,next_attempt_at=?,last_error=?,updated_at=? WHERE alert_id=?").bind(
        canRetry?"pending":"failed",next,message,timestamp,alert.alert_id
      ).run();
      await db.prepare("INSERT INTO ci_telegram_alert_history (history_id,alert_id,category,asset_symbol,chain,contract_address,status,error,event_at) VALUES (?,?,?,?,?,?,?,?,?)").bind(
        cryptoRandomId(),alert.alert_id,alert.category,alert.asset_symbol,alert.chain,alert.contract_address,canRetry?"retry_scheduled":"failed",message,timestamp
      ).run();
      results.push({alert_id:alert.alert_id,status:canRetry?"retry_scheduled":"failed",error:message});
    }
  }
  return {processed:results.length,results,posting_identity:"application_backend_bot_only"};
}

async function getCITelegramAlertHistory(db,limit=100){
  await ensureCITelegramTables(db);
  const rows=await db.prepare("SELECT alert_id,category,asset_symbol,chain,contract_address,status,telegram_message_id,error,event_at FROM ci_telegram_alert_history ORDER BY event_at DESC LIMIT ?").bind(Math.max(1,Math.min(500,Number(limit)||100))).all();
  const queue=await db.prepare("SELECT alert_id,category,asset_symbol,chain,contract_address,status,attempts,last_error,created_at,sent_at FROM ci_telegram_alert_queue ORDER BY created_at DESC LIMIT ?").bind(Math.max(1,Math.min(200,Number(limit)||100))).all();
  return {events:rows.results||[],queue:queue.results||[]};
}


const ciChapter16PreviousRoutes=handleProtectedRoutes;
handleProtectedRoutes=async function(request,env,ctx,route){
  const {path,method,url}=route;
  const telegramPaths=["/api/telegram/verify","/api/telegram/queue","/api/telegram/queue/process","/api/telegram/history"];
  if(telegramPaths.includes(path)||(path==="/api/telegram/alert"&&method==="POST")){
    const db=getDB(env);await initializeBackendTables(db);await ensureCITelegramTables(db);
    if(method==="POST"&&path==="/api/telegram/verify"){
      try{return json({success:true,telegram:await verifyCITelegramChannel(env)});}
      catch(error){return errorResponse(safeString(error.message||"Vérification Telegram impossible.",1000),400);}
    }
    if(method==="POST"&&path==="/api/telegram/alert"){
      try{
        const queued=await enqueueCITelegramAlert(db,await readBody(request),env);
        await audit(db,"telegram_alert_queued",queued.alert_id);
        return json({success:true,telegram:queued},queued.deduplicated?200:202);
      }catch(error){return errorResponse(safeString(error.message||"Alerte Telegram refusée.",1000),400);}
    }
    if(method==="POST"&&path==="/api/telegram/queue"){
      try{return json({success:true,telegram:await enqueueCITelegramAlert(db,await readBody(request),env)},202);}
      catch(error){return errorResponse(safeString(error.message||"Mise en file Telegram refusée.",1000),400);}
    }
    if(method==="POST"&&path==="/api/telegram/queue/process"){
      try{return json({success:true,telegram:await dispatchCITelegramAlerts(db,env,(await readBody(request)).limit)});}
      catch(error){return errorResponse(safeString(error.message||"Distribution Telegram impossible.",1000),500);}
    }
    if(method==="GET"&&path==="/api/telegram/history"){
      return json({success:true,telegram:await getCITelegramAlertHistory(db,url.searchParams.get("limit")||100)});
    }
    if(method==="GET"&&path==="/api/telegram/queue"){
      return json({success:true,telegram:await getCITelegramAlertHistory(db,url.searchParams.get("limit")||100)});
    }
  }
  return await ciChapter16PreviousRoutes(request,env,ctx,route);
};


/* Chapitre 16 — anti-spam par actif/catégorie et reprise des envois interrompus. */
function ciTelegramSafeAppUrl(candidate,env){
  const configured=safeString(env.APP_ORIGIN||"",500);
  if(!configured||!candidate)return "";
  try{
    const expected=new URL(configured),actual=new URL(safeString(candidate,500));
    return actual.origin===expected.origin?actual.toString():"";
  }catch{return "";}
}

async function enqueueCITelegramAlert(db,body,env){
  await ensureCITelegramTables(db);
  const asset=body.asset||{},category=safeString(body.category||"",60).toLowerCase();
  const details=safeString(body.details||"",2000).trim();
  if(!CI_TELEGRAM_ALERT_CATEGORIES.includes(category))throw new Error("Catégorie d'alerte non autorisée.");
  if(!details)throw new Error("Le détail de l'alerte est obligatoire.");
  const name=safeString(asset.name||"Token inconnu",100),symbol=safeString(asset.symbol||"N/A",30);
  const chain=safeString(asset.chain||"Chaîne inconnue",60);
  const contract=safeString(asset.contract_address||asset.pair_address||"",160);
  if(!asset.name&&!asset.symbol&&!asset.contract_address)throw new Error("L'alerte doit identifier son actif.");
  const dedupe=ciTelegramDedupeKey(asset,category,details);
  const existing=await db.prepare("SELECT alert_id,status FROM ci_telegram_alert_queue WHERE dedupe_key=?").bind(dedupe).first();
  if(existing)return {alert_id:existing.alert_id,status:existing.status,deduplicated:true};
  const id=cryptoRandomId(),timestamp=nowISO();
  await db.prepare("INSERT INTO ci_telegram_alert_queue (alert_id,dedupe_key,category,asset_name,asset_symbol,chain,contract_address,details,app_url,status,attempts,next_attempt_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,'pending',0,?,?,?)").bind(
    id,dedupe,category,name,symbol,chain,contract,details,ciTelegramSafeAppUrl(body.app_url||env.APP_ORIGIN,env),timestamp,timestamp,timestamp
  ).run();
  await db.prepare("INSERT INTO ci_telegram_alert_history (history_id,alert_id,category,asset_symbol,chain,contract_address,status,event_at) VALUES (?,?,?,?,?,?,?,?)").bind(
    cryptoRandomId(),id,category,symbol,chain,contract,"queued",timestamp
  ).run();
  return {alert_id:id,status:"pending",deduplicated:false};
}

dispatchCITelegramAlerts=async function(db,env,limit=10){
  await ensureCITelegramTables(db);
  const max=Math.max(1,Math.min(25,Number(limit)||10)),timestamp=nowISO();
  await db.prepare("UPDATE ci_telegram_alert_queue SET status='pending',next_attempt_at=?,updated_at=?,last_error='Récupération après interruption de traitement.' WHERE status='sending' AND updated_at<?").bind(
    timestamp,timestamp,new Date(Date.now()-5*60*1000).toISOString()
  ).run();
  const ready=await db.prepare("SELECT * FROM ci_telegram_alert_queue WHERE status='pending' AND next_attempt_at<=? ORDER BY CASE category WHEN 'critical_security' THEN 0 WHEN 'new_token' THEN 1 WHEN 'liquidity_change' THEN 2 WHEN 'whale_activity' THEN 3 WHEN 'investment_opportunity' THEN 4 WHEN 'prediction' THEN 5 ELSE 6 END,created_at ASC LIMIT ?").bind(timestamp,max).all();
  const results=[];
  for(const alert of ready.results||[]){
    const identity=alert.chain+":"+(alert.contract_address||alert.asset_symbol||alert.asset_name);
    const cooldown=alert.category==="critical_security"?60:600;
    const recent=await db.prepare("SELECT last_sent_at FROM ci_telegram_rate_limits WHERE category=? AND dedupe_key=?").bind(alert.category,identity).first();
    if(recent&&Date.now()-Date.parse(recent.last_sent_at)<cooldown*1000){
      const next=new Date(Date.parse(recent.last_sent_at)+cooldown*1000).toISOString();
      await db.prepare("UPDATE ci_telegram_alert_queue SET next_attempt_at=?,updated_at=? WHERE alert_id=? AND status='pending'").bind(next,nowISO(),alert.alert_id).run();
      results.push({alert_id:alert.alert_id,status:"rate_limited",retry_at:next});continue;
    }
    const claim=await db.prepare("UPDATE ci_telegram_alert_queue SET status='sending',attempts=attempts+1,updated_at=? WHERE alert_id=? AND status='pending'").bind(nowISO(),alert.alert_id).run();
    if(!claim.meta?.changes)continue;
    try{
      const message=buildAssetAlert({name:alert.asset_name,symbol:alert.asset_symbol,chain:alert.chain,contract_address:alert.contract_address},alert.category,alert.details,alert.app_url);
      const sent=await sendTelegram(env,message),sentAt=nowISO();
      await db.prepare("UPDATE ci_telegram_alert_queue SET status='sent',telegram_message_id=?,last_error=NULL,sent_at=?,updated_at=? WHERE alert_id=?").bind(String(sent.message_id||""),sentAt,sentAt,alert.alert_id).run();
      await db.prepare("INSERT OR REPLACE INTO ci_telegram_rate_limits (category,dedupe_key,last_sent_at) VALUES (?,?,?)").bind(alert.category,identity,sentAt).run();
      await db.prepare("INSERT INTO ci_telegram_alert_history (history_id,alert_id,category,asset_symbol,chain,contract_address,status,telegram_message_id,event_at) VALUES (?,?,?,?,?,?,?,?,?)").bind(
        cryptoRandomId(),alert.alert_id,alert.category,alert.asset_symbol,alert.chain,alert.contract_address,"sent",String(sent.message_id||""),sentAt
      ).run();
      results.push({alert_id:alert.alert_id,status:"sent",message_id:sent.message_id});
    }catch(error){
      const message=safeString(error.message||"Erreur Telegram.",700),attempts=Number(alert.attempts)+1,canRetry=attempts<4;
      const next=new Date(Date.now()+Math.min(3600000,60000*Math.pow(2,attempts-1))).toISOString(),at=nowISO();
      await db.prepare("UPDATE ci_telegram_alert_queue SET status=?,next_attempt_at=?,last_error=?,updated_at=? WHERE alert_id=?").bind(canRetry?"pending":"failed",next,message,at,alert.alert_id).run();
      await db.prepare("INSERT INTO ci_telegram_alert_history (history_id,alert_id,category,asset_symbol,chain,contract_address,status,error,event_at) VALUES (?,?,?,?,?,?,?,?,?)").bind(
        cryptoRandomId(),alert.alert_id,alert.category,alert.asset_symbol,alert.chain,alert.contract_address,canRetry?"retry_scheduled":"failed",message,at
      ).run();
      results.push({alert_id:alert.alert_id,status:canRetry?"retry_scheduled":"failed",error:message});
    }
  }
  return {processed:results.length,results,posting_identity:"application_backend_bot_only",category_rate_limits:true};
};
