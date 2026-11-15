

/*
 * CRYPTO INTELLIGENCE — index.js
 * Interface web principale.
 *
 * Ce fichier fonctionne dans le navigateur.
 * Il ne contient aucune clé API ni aucun secret.
 *
 * Il communique avec le backend server.js.
 */

(() => {
  "use strict";

  const APP_NAME = "CRYPTO INTELLIGENCE";
  const API_BASE = "";

  const state = {
    currentPage: "dashboard",
    assets: [],
    providers: [],
    searchResults: [],
    selectedAsset: null,
    loading: false
  };

  const root = document.getElementById("app") || document.body;

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;"
    })[char]);
  }

  function formatNumber(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return "Non disponible";

    return new Intl.NumberFormat("fr-FR", {
      maximumFractionDigits: 8
    }).format(number);
  }

  function formatMoney(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return "Non disponible";

    return new Intl.NumberFormat("fr-FR", {
      style: "currency",
      currency: "USD",
      maximumFractionDigits: 8
    }).format(number);
  }

  function showMessage(message, type = "info") {
    const container = document.getElementById("notifications");
    if (!container) return;

    const item = document.createElement("div");
    item.className = `notification ${type}`;
    item.textContent = message;
    container.appendChild(item);

    setTimeout(() => item.remove(), 5000);
  }

  async function api(path, options = {}) {
    const response = await fetch(`${API_BASE}${path}`, {
      method: options.method || "GET",
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {})
      },
      body: options.body ? JSON.stringify(options.body) : undefined
    });

    let data;

    try {
      data = await response.json();
    } catch {
      throw new Error("Réponse invalide du serveur.");
    }

    if (!response.ok) {
      if (response.status === 401) {
        throw new Error(
          "Authentification requise. La connexion sécurisée au backend doit encore être configurée."
        );
      }

      throw new Error(data.error || `Erreur serveur ${response.status}`);
    }

    return data;
  }

  function setPage(page) {
    state.currentPage = page;
    render();
    loadPageData(page);
  }

  function render() {
    root.innerHTML = `
      <div class="ci-app">
        <aside class="ci-sidebar">
          <div class="ci-brand">
            <div class="ci-logo">CI</div>
            <div>
              <strong>CRYPTO</strong>
              <span>INTELLIGENCE</span>
            </div>
          </div>

          <div class="ci-menu-title">APPLICATION</div>

          <button class="nav-item ${state.currentPage === "dashboard" ? "active" : ""}"
            data-page="dashboard">⌂ Tableau de bord</button>

          <button class="nav-item ${state.currentPage === "market" ? "active" : ""}"
            data-page="market">◈ Marché crypto</button>

          <button class="nav-item ${state.currentPage === "assets" ? "active" : ""}"
            data-page="assets">◆ Mes actifs</button>

          <button class="nav-item ${state.currentPage === "analysis" ? "active" : ""}"
            data-page="analysis">⌕ Laboratoire d'analyse</button>

          <button class="nav-item ${state.currentPage === "security" ? "active" : ""}"
            data-page="security">⬡ Sécurité</button>

          <div class="ci-menu-title">INTELLIGENCE</div>

          <button class="nav-item ${state.currentPage === "conan" ? "active" : ""}"
            data-page="conan">✦ CONAN</button>

          <button class="nav-item ${state.currentPage === "providers" ? "active" : ""}"
            data-page="providers">▤ Fournisseurs</button>

          <button class="nav-item ${state.currentPage === "tasks" ? "active" : ""}"
            data-page="tasks">☷ Tâches</button>

          <div class="ci-sidebar-footer">
            <span class="status-dot"></span>
            <span id="connection-label">Vérification du serveur...</span>
          </div>
        </aside>

        <main class="ci-main">
          <header class="ci-topbar">
            <div>
              <div class="ci-eyebrow">ESPACE PERSONNEL</div>
              <h1 id="page-title">Tableau de bord</h1>
            </div>
            <div class="ci-top-right">
              <span class="ci-version">VERSION 1.0.0</span>
              <span class="ci-avatar">CI</span>
            </div>
          </header>

          <div id="notifications" class="notifications"></div>
          <section id="page-content"></section>

          <footer class="ci-footer">
            CRYPTO INTELLIGENCE — Données à vérifier. Aucun résultat ne constitue une garantie de rendement.
          </footer>
        </main>
      </div>
    `;

    addStyles();
    renderPageContent();
    checkHealth();
  }

  function addStyles() {
    if (document.getElementById("ci-styles")) return;

    const style = document.createElement("style");
    style.id = "ci-styles";

    style.textContent = `
      * { box-sizing: border-box; }

      body {
        margin: 0;
        background: #0a0f18;
        color: #e8edf7;
        font-family: Arial, Helvetica, sans-serif;
      }

      button, input, select, textarea { font: inherit; }

      .ci-app {
        min-height: 100vh;
        display: flex;
      }

      .ci-sidebar {
        width: 245px;
        flex-shrink: 0;
        background: #101827;
        border-right: 1px solid #243047;
        padding: 24px 15px;
        display: flex;
        flex-direction: column;
      }

      .ci-brand {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 4px 8px 30px;
      }

      .ci-logo {
        width: 43px;
        height: 43px;
        border-radius: 12px;
        display: grid;
        place-items: center;
        color: #07111d;
        background: #45d6b5;
        font-weight: 900;
      }

      .ci-brand strong, .ci-brand span {
        display: block;
        letter-spacing: 1px;
      }

      .ci-brand strong { font-size: 14px; }
      .ci-brand span {
        color: #8fa0b8;
        font-size: 10px;
        margin-top: 4px;
      }

      .ci-menu-title {
        color: #72829c;
        font-size: 10px;
        font-weight: bold;
        letter-spacing: 1.5px;
        padding: 18px 10px 9px;
      }

      .nav-item {
        border: 0;
        background: transparent;
        color: #aab7ca;
        text-align: left;
        padding: 12px 11px;
        border-radius: 8px;
        margin: 2px 0;
        cursor: pointer;
        width: 100%;
      }

      .nav-item:hover, .nav-item.active {
        background: #1c3040;
        color: #55dfbd;
      }

      .ci-sidebar-footer {
        margin-top: auto;
        padding: 18px 8px 0;
        border-top: 1px solid #263248;
        color: #9aa9bd;
        font-size: 11px;
      }

      .status-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #e0ad4d;
        margin-right: 7px;
      }

      .ci-main {
        flex: 1;
        min-width: 0;
        padding: 28px;
      }

      .ci-topbar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid #263248;
        padding-bottom: 20px;
        margin-bottom: 25px;
      }

      .ci-eyebrow {
        color: #45d6b5;
        font-size: 10px;
        letter-spacing: 2px;
        margin-bottom: 7px;
      }

      h1 { font-size: 25px; margin: 0; }
      h2 { font-size: 18px; margin: 0 0 15px; }
      h3 { font-size: 15px; margin: 0 0 10px; }

      .ci-top-right {
        display: flex;
        align-items: center;
        gap: 15px;
      }

      .ci-version {
        color: #8191a8;
        font-size: 10px;
      }

      .ci-avatar {
        width: 36px;
        height: 36px;
        border-radius: 50%;
        display: grid;
        place-items: center;
        background: #1c3040;
        color: #55dfbd;
        font-weight: bold;
      }

      .ci-grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 14px;
        margin-bottom: 20px;
      }

      .ci-card {
        background: #111c2c;
        border: 1px solid #26354b;
        border-radius: 12px;
        padding: 18px;
        margin-bottom: 16px;
        min-width: 0;
      }

      .ci-stat-label {
        color: #91a1b8;
        font-size: 12px;
      }

      .ci-stat-value {
        font-size: 25px;
        font-weight: bold;
        margin-top: 12px;
      }

      .ci-muted { color: #91a1b8; font-size: 12px; }
      .ci-green { color: #55dfbd; }
      .ci-yellow { color: #e6bd66; }
      .ci-red { color: #ff7777; }

      .ci-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
      }

      .ci-form {
        display: flex;
        gap: 9px;
        flex-wrap: wrap;
      }

      .ci-input, .ci-select, .ci-textarea {
        background: #0a1320;
        border: 1px solid #33435b;
        color: #e8edf7;
        border-radius: 8px;
        padding: 12px;
        min-width: 0;
      }

      .ci-input { flex: 1; }
      .ci-textarea {
        width: 100%;
        min-height: 110px;
        resize: vertical;
      }

      .ci-button {
        background: #45d6b5;
        color: #07151b;
        border: 0;
        padding: 11px 16px;
        border-radius: 8px;
        font-weight: bold;
        cursor: pointer;
      }

      .ci-button:hover { background: #72e8ce; }
      .ci-button.secondary {
        color: #dce7f5;
        background: #26364b;
      }

      .ci-button:disabled {
        opacity: .5;
        cursor: not-allowed;
      }

      .ci-table-wrap { overflow-x: auto; }

      .ci-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 12px;
      }

      .ci-table th, .ci-table td {
        padding: 12px 9px;
        text-align: left;
        border-bottom: 1px solid #26354b;
        white-space: nowrap;
      }

      .ci-table th {
        color: #8fa0b8;
        font-weight: normal;
      }

      .ci-empty {
        color: #91a1b8;
        text-align: center;
        padding: 25px;
        font-size: 13px;
      }

      .ci-notice {
        background: #282516;
        border: 1px solid #66552b;
        color: #f0d48c;
        border-radius: 9px;
        padding: 13px;
        font-size: 12px;
        line-height: 1.6;
        margin-bottom: 16px;
      }

      .ci-result {
        background: #0a1320;
        border: 1px solid #293a50;
        padding: 14px;
        border-radius: 8px;
        margin-top: 12px;
        overflow-wrap: anywhere;
      }

      .ci-result pre {
        white-space: pre-wrap;
        overflow-wrap: anywhere;
        color: #d3e1ef;
        font-size: 12px;
      }

      .ci-footer {
        color: #71819a;
        font-size: 10px;
        border-top: 1px solid #263248;
        margin-top: 30px;
        padding: 18px 0;
      }

      .notifications {
        position: relative;
        z-index: 5;
      }

      .notification {
        padding: 12px;
        border-radius: 8px;
        margin-bottom: 10px;
        font-size: 12px;
        background: #24364a;
      }

      .notification.error {
        background: #42242a;
        color: #ffc1c1;
      }

      .notification.success {
        background: #173d36;
        color: #a6f4df;
      }

      @media (max-width: 900px) {
        .ci-sidebar { width: 205px; }
        .ci-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .ci-main { padding: 20px; }
      }

      @media (max-width: 650px) {
        .ci-app { display: block; }
        .ci-sidebar {
          width: 100%;
          padding: 12px;
          display: block;
        }
        .ci-brand { padding: 5px 5px 12px; }
        .ci-menu-title { padding: 10px 5px 5px; }
        .nav-item {
          display: inline-block;
          width: auto;
          padding: 9px;
          font-size: 11px;
        }
        .ci-sidebar-footer { margin-top: 10px; }
        .ci-main { padding: 15px; }
        .ci-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .ci-stat-value { font-size: 19px; }
        h1 { font-size: 20px; }
        .ci-version { display: none; }
      }
    `;

    document.head.appendChild(style);
  }

  function renderPageContent() {
    const content = document.getElementById("page-content");
    const title = document.getElementById("page-title");

    const pages = {
      dashboard: ["Tableau de bord", renderDashboard],
      market: ["Marché crypto", renderMarket],
      assets: ["Mes actifs", renderAssets],
      analysis: ["Laboratoire d'analyse", renderAnalysis],
      security: ["Sécurité", renderSecurity],
      conan: ["CONAN", renderConan],
      providers: ["Fournisseurs", renderProviders],
      tasks: ["Tâches", renderTasks]
    };

    const page = pages[state.currentPage] || pages.dashboard;
    title.textContent = page[0];
    content.innerHTML = page[1]();
  }

  function renderDashboard() {
    return `
      <div class="ci-notice">
        Bienvenue dans CRYPTO INTELLIGENCE. Le tableau de bord est prêt.
        Les données réelles apparaîtront après configuration et connexion du backend.
      </div>

      <div class="ci-grid">
        <div class="ci-card">
          <div class="ci-stat-label">Actifs enregistrés</div>
          <div class="ci-stat-value">${state.assets.length}</div>
        </div>
        <div class="ci-card">
          <div class="ci-stat-label">Fournisseurs détectés</div>
          <div class="ci-stat-value">${state.providers.length}</div>
        </div>
        <div class="ci-card">
          <div class="ci-stat-label">Moteur CONAN</div>
          <div class="ci-stat-value ci-yellow">À connecter</div>
        </div>
        <div class="ci-card">
          <div class="ci-stat-label">Backend</div>
          <div class="ci-stat-value ci-yellow" id="dashboard-server">Vérification</div>
        </div>
      </div>

      <div class="ci-card">
        <h2>Recherche rapide d'un crypto ou token</h2>
        <form class="ci-form" id="quick-search-form">
          <input class="ci-input" name="query"
            placeholder="Nom, symbole ou adresse du contrat..." required>
          <button class="ci-button">Rechercher</button>
        </form>
        <div id="quick-search-results"></div>
      </div>

      <div class="ci-card">
        <div class="ci-row">
          <h2>Mes actifs</h2>
          <button class="ci-button secondary" data-page="assets">Voir les actifs</button>
        </div>
        <div id="dashboard-assets" class="ci-empty">Chargement des actifs...</div>
      </div>
    `;
  }

  function renderMarket() {
    return `
      <div class="ci-card">
        <h2>Explorer le marché crypto</h2>
        <p class="ci-muted">
          Recherche de cryptomonnaies, tokens et paires disponibles chez les fournisseurs connectés.
        </p>
        <form class="ci-form" id="market-search-form">
          <input class="ci-input" name="query"
            placeholder="Exemple : BTC, ETH, PEPE..." required>
          <button class="ci-button">Lancer la recherche</button>
        </form>
        <div id="market-results"></div>
      </div>

      <div class="ci-card">
        <h2>Marché CoinGecko</h2>
        <p class="ci-muted">Liste des actifs classés par capitalisation boursière.</p>
        <button class="ci-button" id="load-coingecko">Charger le marché</button>
        <div id="coingecko-results"></div>
      </div>
    `;
  }

  function renderAssets() {
    return `
      <div class="ci-card">
        <h2>Ajouter un actif à surveiller</h2>
        <form class="ci-form" id="add-asset-form">
          <input class="ci-input" name="name" placeholder="Nom">
          <input class="ci-input" name="symbol" placeholder="Symbole">
          <input class="ci-input" name="chain" placeholder="Blockchain">
          <input class="ci-input" name="contract_address" placeholder="Adresse du contrat">
          <button class="ci-button">Ajouter</button>
        </form>
      </div>

      <div class="ci-card">
        <h2>Liste de mes actifs</h2>
        <div id="assets-table" class="ci-empty">Chargement...</div>
      </div>
    `;
  }

  function renderAnalysis() {
    return `
      <div class="ci-card">
        <h2>Conseil des cinq rôles IA</h2>
        <p class="ci-muted">
          Analyse fondamentale, marché, sécurité, croissance et arbitrage.
          Les résultats dépendent des fournisseurs IA configurés et des données disponibles.
        </p>

        <form id="analysis-form">
          <input class="ci-input" name="name"
            placeholder="Nom du crypto ou token" required>
          <input class="ci-input" name="symbol"
            placeholder="Symbole" required>
          <input class="ci-input" name="chain"
            placeholder="Blockchain">
          <input class="ci-input" name="contract_address"
            placeholder="Adresse du contrat">
          <textarea class="ci-textarea" name="market_data"
            placeholder="Informations de marché supplémentaires (facultatif)"></textarea>
          <button class="ci-button">Lancer l'analyse IA</button>
        </form>

        <div id="analysis-results"></div>
      </div>
    `;
  }

  function renderSecurity() {
    return `
      <div class="ci-card">
        <h2>Vérification de sécurité d'un token</h2>
        <p class="ci-muted">
          Recherche de signaux de risque avec GoPlus.
          Une absence d'alerte ne garantit jamais qu'un token est sûr.
        </p>

        <form id="security-form">
          <input class="ci-input" name="chain"
            placeholder="Chain ID (exemple : 1 pour Ethereum)" required>
          <input class="ci-input" name="address"
            placeholder="Adresse du contrat" required>
          <button class="ci-button">Vérifier le contrat</button>
        </form>

        <div id="security-results"></div>
      </div>

      <div class="ci-card">
        <h2>Blockchains prises en charge par GoPlus</h2>
        <button class="ci-button secondary" id="load-security-chains">
          Charger les blockchains
        </button>
        <div id="security-chains-results"></div>
      </div>
    `;
  }

  function renderConan() {
    return `
      <div class="ci-card">
        <h2>✦ CONAN — Intelligence enfant</h2>
        <p class="ci-muted">
          Espace de commande et de suivi du moteur autonome CONAN.
        </p>
        <div id="conan-status" class="ci-notice">
          Vérification de l'état de CONAN...
        </div>
      </div>

      <div class="ci-card">
        <h2>Envoyer une commande</h2>
        <form id="conan-command-form">
          <textarea class="ci-textarea" name="command"
            placeholder="Écris une commande ou une mission pour CONAN..."
            required></textarea>
          <button class="ci-button">Envoyer à CONAN</button>
        </form>
        <div id="conan-command-result"></div>
      </div>

      <div class="ci-card">
        <h2>Mémoire de CONAN</h2>
        <div id="conan-memory" class="ci-muted">
          État de la mémoire non encore chargé.
        </div>
      </div>
    `;
  }

  function renderProviders() {
    return `
      <div class="ci-card">
        <div class="ci-row">
          <h2>État des fournisseurs</h2>
          <button class="ci-button secondary" id="refresh-providers">Actualiser</button>
        </div>
        <p class="ci-muted">
          Les clés doivent être configurées uniquement dans les secrets du backend.
          Aucune clé ne doit être enregistrée dans cette interface.
        </p>
        <div id="providers-table" class="ci-empty">Chargement...</div>
      </div>
    `;
  }

  function renderTasks() {
    return `
      <div class="ci-card">
        <div class="ci-row">
          <h2>File des tâches</h2>
          <button class="ci-button secondary" id="refresh-tasks">Actualiser</button>
        </div>
        <div id="tasks-table" class="ci-empty">Chargement...</div>
      </div>
    `;
  }

  async function checkHealth() {
    try {
      const result = await api("/api/health");
      const label = document.getElementById("connection-label");

      if (label) {
        label.textContent = result.status === "online"
          ? "Backend détecté"
          : "Backend indisponible";
      }

      const dashboardServer = document.getElementById("dashboard-server");
      if (dashboardServer) {
        dashboardServer.textContent = result.status === "online"
          ? "En ligne"
          : "Indisponible";
        dashboardServer.className = "ci-stat-value ci-green";
      }
    } catch (error) {
      const label = document.getElementById("connection-label");
      if (label) label.textContent = "Backend non connecté";
    }
  }

  async function loadPageData(page) {
    try {
      if (page === "dashboard" || page === "assets") {
        await loadAssets();
      }

      if (page === "providers") {
        await loadProviders();
      }

      if (page === "conan") {
        await loadConanStatus();
        await loadConanMemory();
      }

      if (page === "tasks") {
        await loadTasks();
      }
    } catch (error) {
      showMessage(error.message, "error");
    }
  }

  async function loadAssets() {
    const result = await api("/api/assets");
    state.assets = result.assets || [];

    const dashboard = document.getElementById("dashboard-assets");
    if (dashboard) {
      dashboard.innerHTML = state.assets.length
        ? renderAssetsTable(state.assets.slice(0, 8))
        : `<div class="ci-empty">Aucun actif enregistré.</div>`;
    }

    const table = document.getElementById("assets-table");
    if (table) {
      table.innerHTML = state.assets.length
        ? renderAssetsTable(state.assets)
        : `<div class="ci-empty">Aucun actif enregistré pour le moment.</div>`;
    }

    const count = document.querySelector(".ci-grid .ci-stat-value");
    if (count) count.textContent = state.assets.length;
  }

  function renderAssetsTable(assets) {
    return `
      <div class="ci-table-wrap">
        <table class="ci-table">
          <thead>
            <tr>
              <th>Nom</th>
              <th>Symbole</th>
              <th>Blockchain</th>
              <th>Statut</th>
            </tr>
          </thead>
          <tbody>
            ${assets.map((asset) => `
              <tr>
                <td>${escapeHTML(asset.name || "Inconnu")}</td>
                <td>${escapeHTML(asset.symbol || "—")}</td>
                <td>${escapeHTML(asset.chain || "—")}</td>
                <td>${escapeHTML(asset.status || "Non classé")}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  async function loadProviders() {
    const result = await api("/api/providers");
    state.providers = result.providers || [];

    const container = document.getElementById("providers-table");
    if (!container) return;

    container.innerHTML = `
      <div class="ci-table-wrap">
        <table class="ci-table">
          <thead>
            <tr>
              <th>Fournisseur</th>
              <th>Catégorie</th>
              <th>Configuration</th>
              <th>Requêtes 24 h</th>
            </tr>
          </thead>
          <tbody>
            ${state.providers.map((provider) => `
              <tr>
                <td>${escapeHTML(provider.id)}</td>
                <td>${escapeHTML(provider.type)}</td>
                <td class="${provider.configured ? "ci-green" : "ci-yellow"}">
                  ${provider.configured ? "Configuré" : "Non configuré"}
                </td>
                <td>${formatNumber(provider.last_24h?.total_requests || 0)}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;

    const count = document.querySelectorAll(".ci-grid .ci-stat-value")[1];
    if (count) count.textContent = state.providers.length;
  }

  async function loadTasks() {
    const result = await api("/api/tasks");
    const container = document.getElementById("tasks-table");
    if (!container) return;

    const tasks = result.tasks || [];

    container.innerHTML = tasks.length
      ? `
        <div class="ci-table-wrap">
          <table class="ci-table">
            <thead>
              <tr><th>Type</th><th>Statut</th><th>Priorité</th><th>Créée le</th></tr>
            </thead>
            <tbody>
              ${tasks.map((task) => `
                <tr>
                  <td>${escapeHTML(task.task_type)}</td>
                  <td>${escapeHTML(task.status)}</td>
                  <td>${escapeHTML(task.priority)}</td>
                  <td>${escapeHTML(task.created_at)}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      `
      : `<div class="ci-empty">Aucune tâche.</div>`;
  }

  async function loadConanStatus() {
    const result = await api("/api/conan/status");
    const container = document.getElementById("conan-status");
    if (!container) return;

    container.innerHTML = `
      <strong>${escapeHTML(result.conan?.name || "CONAN")}</strong><br>
      Statut : ${escapeHTML(result.conan?.status || "Inconnu")}<br>
      Mémoire personnelle : ${result.conan?.personal_memory ? "Connexion détectée" : "Non configurée"}<br>
      Apprentissage autonome : ${result.conan?.self_learning_engine ? "Actif" : "Pas encore intégré"}<br>
      Cycles de prédiction : ${result.conan?.prediction_cycles ? "Actifs" : "Pas encore intégrés"}
    `;
  }

  async function loadConanMemory() {
    const result = await api("/api/memory/status");
    const container = document.getElementById("conan-memory");
    if (!container) return;

    container.textContent = JSON.stringify(result.memory_layers, null, 2);
  }

  async function performSearch(query, target) {
    const container = document.getElementById(target);
    if (container) container.innerHTML = `<div class="ci-empty">Recherche en cours...</div>`;

    const result = await api(`/api/market/search?q=${encodeURIComponent(query)}`);
    const pairs = result.pairs || [];

    if (container) {
      container.innerHTML = pairs.length
        ? renderPairs(pairs)
        : `<div class="ci-empty">Aucune paire trouvée.</div>`;
    }
  }

  function renderPairs(pairs) {
    return `
      <div class="ci-table-wrap">
        <table class="ci-table">
          <thead>
            <tr>
              <th>Token</th>
              <th>Blockchain</th>
              <th>DEX</th>
              <th>Prix USD</th>
              <th>Liquidité USD</th>
              <th>Volume 24 h</th>
              <th>Variation 24 h</th>
            </tr>
          </thead>
          <tbody>
            ${pairs.map((pair) => `
              <tr>
                <td>${escapeHTML(pair.base_token?.symbol || "—")}</td>
                <td>${escapeHTML(pair.chain || "—")}</td>
                <td>${escapeHTML(pair.dex || "—")}</td>
                <td>${formatMoney(pair.price_usd)}</td>
                <td>${formatMoney(pair.liquidity_usd)}</td>
                <td>${formatMoney(pair.volume_24h)}</td>
                <td>${formatNumber(pair.price_change_24h)} %</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  async function loadCoinGecko() {
    const container = document.getElementById("coingecko-results");
    container.innerHTML = `<div class="ci-empty">Chargement du marché...</div>`;

    const result = await api("/api/market/coingecko?per_page=50&page=1");
    const assets = result.assets || [];

    container.innerHTML = assets.length
      ? `
        <div class="ci-table-wrap">
          <table class="ci-table">
            <thead>
              <tr><th>Rang</th><th>Actif</th><th>Prix USD</th><th>Capitalisation</th><th>Volume 24 h</th></tr>
            </thead>
            <tbody>
              ${assets.map((asset) => `
                <tr>
                  <td>${escapeHTML(asset.market_cap_rank || "—")}</td>
                  <td>${escapeHTML(asset.name)} (${escapeHTML(asset.symbol)})</td>
                  <td>${formatMoney(asset.price)}</td>
                  <td>${formatMoney(asset.market_cap)}</td>
                  <td>${formatMoney(asset.volume_24h)}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      `
      : `<div class="ci-empty">Aucune donnée reçue.</div>`;
  }

  async function submitAnalysis(form) {
    const data = new FormData(form);

    let marketData = {};
    try {
      marketData = JSON.parse(data.get("market_data") || "{}");
    } catch {
      marketData = { notes: data.get("market_data") };
    }

    const container = document.getElementById("analysis-results");
    container.innerHTML = `<div class="ci-empty">Analyse en cours. Cela peut prendre un moment...</div>`;

    const result = await api("/api/analysis", {
      method: "POST",
      body: {
        asset: {
          name: data.get("name"),
          symbol: data.get("symbol"),
          chain: data.get("chain"),
          contract_address: data.get("contract_address")
        },
        market_data: marketData
      }
    });

    container.innerHTML = `
      <div class="ci-result">
        <h3>Rapport d'analyse</h3>
        <pre>${escapeHTML(JSON.stringify(result.report, null, 2))}</pre>
      </div>
    `;
  }

  async function submitSecurity(form) {
    const data = new FormData(form);
    const container = document.getElementById("security-results");

    container.innerHTML = `<div class="ci-empty">Vérification en cours...</div>`;

    const result = await api(
      `/api/security/token?chain=${encodeURIComponent(data.get("chain"))}&address=${encodeURIComponent(data.get("address"))}`
    );

    container.innerHTML = `
      <div class="ci-result">
        <h3>Résultat GoPlus</h3>
        <pre>${escapeHTML(JSON.stringify(result, null, 2))}</pre>
      </div>
    `;
  }

  async function submitConanCommand(form) {
    const data = new FormData(form);
    const container = document.getElementById("conan-command-result");

    const result = await api("/api/conan/command", {
      method: "POST",
      body: { command: data.get("command") }
    });

    container.innerHTML = `
      <div class="ci-result">
        Commande enregistrée.<br>
        Identifiant : ${escapeHTML(result.conan?.task_id)}
      </div>
    `;

    form.reset();
  }

  async function addAsset(form) {
    const data = new FormData(form);

    const result = await api("/api/assets", {
      method: "POST",
      body: {
        name: data.get("name"),
        symbol: data.get("symbol"),
        chain: data.get("chain"),
        contract_address: data.get("contract_address")
      }
    });

    showMessage("Actif ajouté à la liste.", "success");
    form.reset();
    await loadAssets();
  }

  async function loadSecurityChains() {
    const result = await api("/api/security/chains");
    document.getElementById("security-chains-results").innerHTML = `
      <div class="ci-result">
        <pre>${escapeHTML(JSON.stringify(result.data, null, 2))}</pre>
      </div>
    `;
  }

  document.addEventListener("click", async (event) => {
    const pageButton = event.target.closest("[data-page]");

    if (pageButton) {
      setPage(pageButton.dataset.page);
      return;
    }

    try {
      if (event.target.closest("#load-coingecko")) {
        await loadCoinGecko();
      }

      if (event.target.closest("#refresh-providers")) {
        await loadProviders();
      }

      if (event.target.closest("#refresh-tasks")) {
        await loadTasks();
      }

      if (event.target.closest("#load-security-chains")) {
        await loadSecurityChains();
      }
    } catch (error) {
      showMessage(error.message, "error");
    }
  });

  document.addEventListener("submit", async (event) => {
    const form = event.target;
    event.preventDefault();

    try {
      if (form.id === "quick-search-form") {
        const data = new FormData(form);
        await performSearch(data.get("query"), "quick-search-results");
      }

      if (form.id === "market-search-form") {
        const data = new FormData(form);
        await performSearch(data.get("query"), "market-results");
      }

      if (form.id === "add-asset-form") {
        await addAsset(form);
      }

      if (form.id === "analysis-form") {
        await submitAnalysis(form);
      }

      if (form.id === "security-form") {
        await submitSecurity(form);
      }

      if (form.id === "conan-command-form") {
        await submitConanCommand(form);
      }
    } catch (error) {
      showMessage(error.message, "error");
    }
  });

  render();

})();
