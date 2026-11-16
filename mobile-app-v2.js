/* CRYPTO INTELLIGENCE — interface mobile V2 (ajout isolé, sans modifier index.js) */
(() => {
  "use strict";
  const root=document.getElementById("app");
  if(!root)return;
  const NAV=[
    ["dashboard","Tableau de bord","Vue générale"],
    ["universe","Univers crypto","Actifs détectés"],
    ["radar","Radar mondial","Nouveaux tokens et paires"],
    ["quarantine","Quarantaine","Actifs à vérifier"],
    ["precursors","Précurseurs","Signaux préliminaires"],
    ["lab","Laboratoire","Dossiers d'investigation"],
    ["circle","Cercle d'investissement","Actifs éligibles"],
    ["surveillance","Surveillance","Suivi adaptatif"],
    ["asset","Fiche actif","Détail d'un actif"],
    ["whales","Baleines et portefeuilles","Flux et clusters"],
    ["council","Conseil des cinq IA","Avis indépendants"],
    ["predictions","Prédictions Conan","Cycles et résultats"],
    ["incubator","Incubateur Conan","Expériences et modules"],
    ["memory","Mémoire et archives","Souvenirs et sauvegardes"],
    ["providers","Fournisseurs et quotas","APIs et ressources"],
    ["telegram","Telegram","Alertes et historique"],
    ["history","Historique","Traçabilité et intégrité"],
    ["settings","Paramètres et sécurité","État et protections"]
  ];
  const ENDPOINTS={
    dashboard:["/api/health","/api/radar/status","/api/conan/status","/api/providers/usage","/api/history/summary"],
    universe:["/api/radar/discoveries","/api/radar/lifecycle"],
    radar:["/api/radar/status","/api/radar/discoveries","/api/radar/pairs","/api/radar/market-checks","/api/radar/security-checks"],
    quarantine:["/api/radar/lifecycle","/api/radar/lifecycle-history"],
    precursors:["/api/radar/lifecycle","/api/radar/lifecycle-history","/api/radar/discoveries"],
    lab:["/api/radar/investigation/history","/api/radar/investigation/evidence","/api/radar/identity-checks","/api/radar/contract-checks"],
    circle:["/api/radar/investment-circle","/api/radar/investment/evaluations","/api/radar/investment/decisions"],
    surveillance:["/api/conan/adaptive-observation","/api/conan/adaptive-observation/history","/api/conan/surveillance-windows","/api/radar/lifecycle-duration"],
    asset:[],
    whales:["/api/wallets/watchlist","/api/wallets/events","/api/wallets/signals","/api/wallets/clusters"],
    council:["/api/ai/council/sessions","/api/ai/council/opinions"],
    predictions:["/api/conan/prediction-cycles","/api/conan/predictions","/api/conan/prediction-observations","/api/conan/prediction-results","/api/conan/scores","/api/conan/growth"],
    incubator:["/api/conan/incubator","/api/conan/incubator/tools","/api/conan/incubator/experiments","/api/conan/incubator/proposals","/api/conan/incubator/code","/api/conan/incubator/code/revisions","/api/conan/incubator/backups"],
    memory:["/api/conan/memory","/api/conan/memory/records","/api/conan/memory/personal","/api/conan/memory/backups","/api/archives/status","/api/archives"],
    providers:["/api/providers","/api/providers/ai","/api/providers/usage","/api/providers/queue"],
    telegram:["/api/telegram/history","/api/telegram/queue"],
    history:["/api/history/summary","/api/history/events","/api/history/verify","/api/archives/operations"],
    settings:["/api/health","/api/archives/status","/api/archives/restore/status","/api/providers","/api/providers/usage"]
  };
  const TITLES=Object.fromEntries(NAV.map(x=>[x[0],x[1]]));
  let page="dashboard",cache={},busy=false,assetKey="";
  const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const pretty=v=>esc(JSON.stringify(v,null,2));
  const api=async path=>{
    const r=await fetch(path,{headers:{Accept:"application/json"}});
    let data;try{data=await r.json();}catch{throw Error("Réponse serveur non JSON ("+r.status+")");}
    if(!r.ok)throw Error(data.error||("Erreur HTTP "+r.status));
    return data;
  };
  const card=(title,body,sub="")=>'<article class="m-card"><div class="m-card-head"><h3>'+esc(title)+'</h3>'+(sub?'<span>'+esc(sub)+'</span>':"")+'</div>'+body+'</article>';
  const raw=(key,data)=>card(key,'<pre class="m-json">'+pretty(data)+'</pre>');
  const metric=(name,value)=>'<div class="m-metric"><span>'+esc(name)+'</span><strong>'+esc(value??"Non disponible")+'</strong></div>';
  const empty=' <p class="m-muted">Aucune donnée retournée par le backend pour le moment.</p>';
  function shell(){
    root.innerHTML=`
      <div class="m-app">
        <header class="m-header">
          <button class="m-brand" data-action="home"><span class="m-mark">CI</span><span><b>CRYPTO INTELLIGENCE</b><small>PLATEFORME D'INTELLIGENCE CRYPTO</small></span></button>
          <div class="m-head-right"><span id="m-connection" class="m-status">Connexion...</span><button class="m-refresh" data-action="refresh" aria-label="Actualiser">↻</button></div>
        </header>
        <div class="m-layout">
          <nav class="m-nav" aria-label="Navigation principale">
            <div class="m-nav-caption">LES 18 ESPACES</div>
            ${NAV.map(([id,label,desc],i)=>'<button class="m-nav-item" data-m-page="'+id+'"><span class="m-nav-num">'+String(i+1).padStart(2,"0")+'</span><span><b>'+esc(label)+'</b><small>'+esc(desc)+'</small></span></button>').join("")}
          </nav>
          <main class="m-main">
            <div class="m-page-heading"><div><span class="m-kicker">ESPACE DE TRAVAIL</span><h1 id="m-title">Tableau de bord</h1></div><span class="m-live">DONNÉES BACKEND</span></div>
            <div id="m-alert" role="status"></div>
            <section id="m-content"><p class="m-muted">Chargement...</p></section>
            <footer class="m-footer">CRYPTO INTELLIGENCE · Données datées et à vérifier · Aucun rendement garanti</footer>
          </main>
        </div>
        <nav class="m-mobile-tabs" aria-label="Navigation rapide">
          <button data-m-page="dashboard">⌂<small>Accueil</small></button><button data-m-page="radar">◎<small>Radar</small></button><button data-m-page="predictions">✦<small>Conan</small></button><button data-m-page="history">◷<small>Historique</small></button><button data-m-page="settings">⚙<small>Réglages</small></button>
        </nav>
      </div>`;
    styles();health();
  }
  function styles(){
    if(document.getElementById("m-v2-style"))return;
    const s=document.createElement("style");s.id="m-v2-style";s.textContent=`
      :root{color-scheme:dark}*{box-sizing:border-box}.m-app{min-height:100vh;background:#080e18;color:#e9f0fa;font-family:Inter,Arial,sans-serif}
      .m-header{height:70px;position:sticky;top:0;z-index:20;background:#0d1725ee;border-bottom:1px solid #26364c;display:flex;align-items:center;justify-content:space-between;padding:0 22px;backdrop-filter:blur(14px)}
      .m-brand{display:flex;align-items:center;gap:12px;border:0;background:none;color:inherit;text-align:left;cursor:pointer}.m-mark{width:39px;height:39px;border-radius:12px;background:#4bd8b7;color:#07131c;display:grid;place-items:center;font-weight:900}.m-brand b,.m-brand small{display:block}.m-brand b{font-size:12px;letter-spacing:1px}.m-brand small{font-size:9px;color:#8296b1;margin-top:4px;letter-spacing:1px}
      .m-head-right{display:flex;align-items:center;gap:14px}.m-status{font-size:11px;color:#a9b8ca}.m-refresh{border:1px solid #31435c;background:#152338;color:#65e2c3;border-radius:9px;width:36px;height:36px;font-size:20px;cursor:pointer}
      .m-layout{display:grid;grid-template-columns:255px minmax(0,1fr);max-width:1600px;margin:auto}.m-nav{padding:22px 13px;border-right:1px solid #24344a;min-height:calc(100vh - 70px);background:#0c1522}.m-nav-caption,.m-kicker{font-size:9px;letter-spacing:1.8px;color:#64d9bd;font-weight:800}.m-nav-caption{padding:0 10px 12px}.m-nav-item{display:flex;align-items:center;gap:10px;width:100%;padding:10px;border:0;border-radius:9px;background:transparent;color:#aebbd0;text-align:left;cursor:pointer;margin:2px 0}.m-nav-item:hover,.m-nav-item.active{background:#183044;color:#69e3c5}.m-nav-num{font-size:10px;color:#68819d;min-width:20px}.m-nav-item b,.m-nav-item small{display:block}.m-nav-item b{font-size:11px}.m-nav-item small{font-size:9px;color:#7f91a9;margin-top:3px}.m-main{min-width:0;padding:28px clamp(15px,3vw,42px) 90px}.m-page-heading{display:flex;justify-content:space-between;align-items:end;border-bottom:1px solid #24344a;padding-bottom:18px;margin-bottom:22px}.m-page-heading h1{font-size:26px;margin:7px 0 0}.m-live{font-size:9px;letter-spacing:1px;color:#71d7be;border:1px solid #285c53;padding:7px 9px;border-radius:20px}
      .m-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:15px}.m-metric,.m-card{background:#101c2c;border:1px solid #263951;border-radius:13px}.m-metric{padding:15px;min-width:0}.m-metric span{display:block;font-size:10px;color:#8fa2bc}.m-metric strong{display:block;font-size:21px;margin-top:10px;overflow-wrap:anywhere}.m-card{padding:17px;margin-bottom:13px;min-width:0}.m-card-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}.m-card h3{font-size:14px;margin:0}.m-card-head span{font-size:9px;color:#8296b1}.m-muted{font-size:12px;color:#91a4bd;line-height:1.7}.m-json{margin:0;white-space:pre-wrap;overflow-wrap:anywhere;max-height:430px;overflow:auto;color:#cbd9e9;font-size:10px;line-height:1.6;background:#091321;padding:12px;border-radius:8px}.m-actions{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.m-button{border:0;border-radius:8px;padding:10px 13px;background:#4bd8b7;color:#07151b;font-weight:800;font-size:11px;cursor:pointer}.m-button.secondary{background:#20334a;color:#dce8f7;border:1px solid #354a64}.m-input{width:min(100%,420px);background:#091321;color:#eef5ff;border:1px solid #344a64;border-radius:8px;padding:11px;font-size:12px}.m-form{display:flex;gap:8px;flex-wrap:wrap}.m-alert{padding:10px;border-radius:8px;font-size:11px}.m-error{background:#45252d;color:#ffc5ca}.m-success{background:#163d34;color:#b7f7e5}.m-footer{font-size:9px;color:#70839e;border-top:1px solid #26364c;padding:20px 0;margin-top:25px}.m-mobile-tabs{display:none}
      @media(max-width:1050px){.m-layout{grid-template-columns:215px minmax(0,1fr)}.m-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
      @media(max-width:700px){.m-header{height:60px;padding:0 13px}.m-brand b{font-size:10px}.m-brand small{font-size:8px}.m-layout{display:block}.m-nav{display:none}.m-main{padding:20px 13px 95px}.m-page-heading h1{font-size:21px}.m-live{font-size:8px}.m-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.m-metric{padding:12px}.m-metric strong{font-size:18px}.m-card{padding:13px}.m-mobile-tabs{display:flex;position:fixed;z-index:30;bottom:0;left:0;right:0;height:62px;justify-content:space-around;background:#0d1928f5;border-top:1px solid #2b3e55;padding-bottom:env(safe-area-inset-bottom);backdrop-filter:blur(12px)}.m-mobile-tabs button{border:0;background:none;color:#9db0c9;font-size:18px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;min-width:48px}.m-mobile-tabs small{font-size:8px}.m-status{font-size:9px}.m-json{font-size:9px}}
    `;document.head.appendChild(s);
  }
  function notice(message,type="error"){const n=document.getElementById("m-alert");if(n)n.innerHTML='<div class="m-alert '+(type==="success"?"m-success":"m-error")+'">'+esc(message)+'</div>';}
  async function health(){try{const x=await api("/api/health");const n=document.getElementById("m-connection");if(n)n.textContent=x.status==="online"?"Backend détecté":"Backend indisponible";}catch{const n=document.getElementById("m-connection");if(n)n.textContent="Backend non vérifié";}}
  function setPage(id){if(!TITLES[id])return;page=id;document.querySelectorAll(".m-nav-item").forEach(n=>n.classList.toggle("active",n.dataset.page===id));document.getElementById("m-title").textContent=TITLES[id];document.getElementById("m-alert").innerHTML="";load();}
  async function load(){
    if(busy)return;busy=true;const box=document.getElementById("m-content");box.innerHTML='<p class="m-muted">Chargement des informations du backend...</p>';
    try{
      if(page==="asset"){await loadAsset(box);return;}
      const endpoints=ENDPOINTS[page]||[];const results=await Promise.all(endpoints.map(async p=>{try{return [p,await api(p),null];}catch(e){return [p,null,e.message];}}));
      cache[page]=results;box.innerHTML=renderPage(page,results);
      if(results.every(x=>x[1]===null))notice("Les routes de cette section n'ont pas fourni de données. Vérifiez la connexion et les permissions du backend.");
    }catch(e){box.innerHTML="";notice(e.message);}
    finally{busy=false;}
  }
  const pick=(r,part)=>{const x=r.find(v=>v[0]===part);return x?x[1]:null;};
  function renderPage(id,r){
    const values=r.filter(x=>x[1]!==null),failed=r.filter(x=>x[2]);
    let out="";
    if(id==="dashboard"){
      const health=pick(r,"/api/health")||{},radar=pick(r,"/api/radar/status")||{},conan=pick(r,"/api/conan/status")||{},prov=pick(r,"/api/providers/usage")||{},hist=pick(r,"/api/history/summary")||{};
      out='<div class="m-grid">'+metric("Backend",health.status||"Non vérifié")+metric("Radar",radar.status||"État non fourni")+metric("Conan",conan.conan?.status||"Non vérifié")+metric("Événements historiques",hist.history?.events?.total_events??hist.events?.total_events??"—")+'</div>'+raw("État du radar",radar)+raw("Ressources fournisseurs",prov)+raw("État de Conan",conan);
    }else if(id==="asset"){
      out="";
    }else{
      out=values.map(([p,d])=>raw(p,d)).join("");
    }
    if(failed.length)out+='<article class="m-card"><h3>Routes non disponibles</h3><p class="m-muted">'+failed.map(x=>esc(x[0])+": "+esc(x[2])).join("<br>")+'</p></article>';
    if(!values.length)out+='<article class="m-card">'+empty+'</article>';
    if(id==="universe"||id==="radar"||id==="quarantine"||id==="precursors"||id==="lab"||id==="circle"){
      out='<article class="m-card"><h3>Ouvrir une fiche actif</h3><p class="m-muted">Saisissez la clé de découverte pour consulter les données et l'historique associés.</p><form class="m-form" data-form="asset"><input class="m-input" name="key" placeholder="discovery_key" required><button class="m-button">Consulter</button></form></article>'+out;
    }
    if(id==="asset")out='<article class="m-card"><h3>Fiche d’actif</h3><p class="m-muted">Entrez une clé de découverte.</p><form class="m-form" data-form="asset"><input class="m-input" name="key" placeholder="discovery_key" value="'+esc(assetKey)+'" required><button class="m-button">Charger</button></form></article>';
    if(id==="providers"||id==="memory"||id==="incubator"||id==="telegram"||id==="history"||id==="settings")out='<article class="m-card"><p class="m-muted">Affichage en lecture des données et historiques disponibles. Les actions sensibles restent contrôlées côté backend.</p></article>'+out;
    return out;
  }
  async function loadAsset(box){
    if(!assetKey){box.innerHTML=renderPage("asset",[]);return;}
    const key=encodeURIComponent(assetKey);
    const paths=["/api/radar/lifecycle-detail?discovery_key="+key,"/api/radar/investigation/prepare?discovery_key="+key,"/api/radar/investigation/history?discovery_key="+key,"/api/radar/investment/evaluations?discovery_key="+key,"/api/radar/identity-checks?discovery_key="+key];
    const results=await Promise.all(paths.map(async p=>{try{return [p,await api(p),null];}catch(e){return [p,null,e.message];}}));
    box.innerHTML=renderPage("asset",results);
  }
  function renderAssetDetail(results){
    return results.map(([p,d,e])=>d?'<article class="m-card"><h3>'+esc(p)+'</h3><pre class="m-json">'+pretty(d)+'</pre></article>':'<article class="m-card"><h3>'+esc(p)+'</h3><p class="m-muted">'+esc(e||"Aucune donnée")+'</p></article>').join("");
  }
  const baseRender=renderPage;
  // La fiche actif conserve le formulaire et ajoute les résultats chargés.
  function handleAssetResult(box,results){box.innerHTML='<article class="m-card"><h3>Fiche d’actif</h3><form class="m-form" data-form="asset"><input class="m-input" name="key" value="'+esc(assetKey)+'" placeholder="discovery_key" required><button class="m-button">Charger</button></form></article>'+renderAssetDetail(results);}
  async function loadAsset(box){
    if(!assetKey){box.innerHTML=baseRender("asset",[]);return;}
    const key=encodeURIComponent(assetKey);
    const paths=["/api/radar/lifecycle-detail?discovery_key="+key,"/api/radar/investigation/prepare?discovery_key="+key,"/api/radar/investigation/history?discovery_key="+key,"/api/radar/investment/evaluations?discovery_key="+key,"/api/radar/identity-checks?discovery_key="+key];
    const results=await Promise.all(paths.map(async p=>{try{return [p,await api(p),null];}catch(e){return [p,null,e.message];}}));
    handleAssetResult(box,results);
  }
  document.addEventListener("click",e=>{
    const nav=e.target.closest("[data-m-page]");if(nav){setPage(nav.dataset.page);return;}
    const act=e.target.closest("[data-action]");if(act?.dataset.action==="refresh")load();if(act?.dataset.action==="home")setPage("dashboard");
  });
  document.addEventListener("submit",e=>{
    const f=e.target.closest('form[data-form="asset"]');if(!f)return;e.preventDefault();assetKey=new FormData(f).get("key").trim();setPage("asset");
  });
  shell();
  // L'interface V2 est un complément isolé : l'ancien index.js reste intact.
  setPage("dashboard");
})();
