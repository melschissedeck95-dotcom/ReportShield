{/* TEMPLATE PDF COMPLET POUR AUDIT / PENTEST EN 8 ÉTAPES */}
{reportType === "Pentest" && (
  <div className="space-y-5 text-xs text-slate-900">
    
    {/* 1. PAGE DE GARDE & MÉTADONNÉES DU LIVRABLE */}
    <div className="border-b-2 border-slate-900 pb-3">
      <div className="flex justify-between items-start">
        <div>
          <h2 className="text-sm font-extrabold uppercase tracking-wide text-slate-900">
            Rapport d'Audit de Sécurité & Test d'Intrusion
          </h2>
          <p className="text-[10px] text-slate-600 font-semibold mt-0.5">
            Référentiels : PTES | OWASP Top 10 | NIST SP 800-115 — Version : {reportVersion || "v1.0"}
          </p>
        </div>
        <div className="text-right text-[10px] bg-amber-50 border border-amber-300 px-2 py-1 rounded">
          <span className="font-bold text-amber-900 block">{tlpMarking || "TLP:AMBER"}</span>
          <span className="text-amber-700">Strictement Confidentiel</span>
        </div>
      </div>
    </div>

    {/* 2. SYNTHÈSE EXÉCUTIVE (MANAGEMENT SUMMARY) */}
    <div>
      <h3 className="text-[10px] font-bold uppercase text-slate-800 border-b pb-1 mb-1.5 flex justify-between items-center">
        <span>1. Synthèse Exécutive & Posture de Sécurité</span>
        <span className="bg-red-600 text-white text-[9px] px-2 py-0.5 rounded font-bold">
          Risque Global : {overallRiskRating || "Élevé / High"}
        </span>
      </h3>
      <p className="text-xs text-slate-800 bg-slate-50 p-2.5 rounded border border-slate-200 leading-relaxed">
        {execSummary || "L'audit de sécurité réalisé met en évidence un niveau de risque global élevé. Plusieurs vulnérabilités critiques ont été identifiées et exploitées avec succès, permettant une compromission des données sensibles et le contournement des contrôles d'accès."}
      </p>
    </div>

    {/* 3. PÉRIMÈTRE & RÈGLES D'ENGAGEMENT (SCOPE) */}
    <div>
      <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">
        2. Périmètre d'Audit & Règles d'Engagement (Scope)
      </h3>
      <div className="grid grid-cols-2 gap-2 text-[11px] bg-slate-50 p-2 rounded border border-slate-200">
        <div>
          <span className="font-bold text-slate-900 block">Cibles Autorisées (In-Scope) :</span>
          <span className="text-slate-800 font-mono">{inScopeTarget || pentestTarget || "API de Paiement & Portail Web Client"}</span>
        </div>
        <div>
          <span className="font-bold text-slate-900 block">Exclusions (Out-of-Scope) :</span>
          <span className="text-slate-800 font-mono">{outScopeTarget || "Environnement ERP de Production, TPE physiques"}</span>
        </div>
      </div>
    </div>

    {/* 4. MATRICE DE COTATION & CVSS V3.1 */}
    <div className="bg-amber-50/60 border border-amber-200 p-2.5 rounded-lg flex justify-between items-center">
      <div>
        <span className="text-[10px] font-bold uppercase text-amber-800 block">3. Cotation de la Vulnérabilité Principale</span>
        <span className="text-xs font-bold text-slate-900">{vulnName || "Injection SQL non authentifiée & BOLA"}</span>
      </div>
      <div className="text-right">
        <span className="bg-amber-600 text-white font-extrabold text-xs px-2.5 py-1 rounded block">
          CVSS v3.1 : {computedCvssScore || 9.8} / 10
        </span>
        <span className="text-[9px] font-mono text-slate-600">
          AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H
        </span>
      </div>
    </div>

    {/* 5. FICHES DÉTAILLÉES DE VULNÉRABILITÉS & POC PAS-À-PAS */}
    <div>
      <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1 flex justify-between">
        <span>4. Preuve de Concept Technique (Proof of Concept)</span>
        <span className="text-slate-500 font-normal">{owaspCategory || "OWASP A03:2021 - Injection / CWE-89"}</span>
      </h3>
      <div className="bg-slate-100 p-3 rounded border border-slate-200 font-mono text-xs whitespace-pre-line leading-relaxed text-slate-900">
        {pocSteps || `1. Envoi du payload SQLi sur le paramètre /api/v1/user?id=1' UNION SELECT NULL--.
2. Contournement de l'authentification et récupération des tables d'utilisateurs.
3. Exploitation du BOLA pour accéder aux données bancaires de clients tiers.`}
      </div>
    </div>

    {/* 6. CHEMIN D'EXPLOITATION & MAPPING MITRE ATT&CK */}
    <div>
      <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">
        5. Scénario d'Attaque & Alignment MITRE ATT&CK
      </h3>
      <div className="bg-purple-50 p-2.5 rounded border border-purple-200 flex justify-between items-center">
        <p className="text-xs text-purple-950 font-medium">
          {attackPathDescription || "L'attaquant s'est appuyé sur l'injection SQL pour exfiltrer les identifiants administrateurs, puis a exploité l'absence de contrôle d'accès pour pivoter sur les comptes clients."}
        </p>
        <span className="bg-purple-700 text-white font-mono font-bold text-[10px] px-2 py-1 rounded ml-3 shrink-0">
          {mitreTactic || "Credential Access"} / {mitreTechnique || "T1110"}
        </span>
      </div>
    </div>

    {/* 7. PLAN DE REMÉDIATION PRIORISÉ (REMEDIATION ROADMAP) */}
    <div>
      <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">
        6. Plan d'Action & Feuille de Route de Remédiation
      </h3>
      <div className="bg-green-50 p-3 rounded border border-green-200 text-xs font-mono text-green-950 space-y-1.5 leading-relaxed">
        <p><strong>P1 [Immédiat] :</strong> {p1Actions || "1. Remplacer les requêtes dynamiques par des requêtes préparées (Parameterized Queries)."}</p>
        <p><strong>P2 [Sous 15 jours] :</strong> {p2Actions || "2. Implémenter un contrôle d'accès au niveau des objets (ABAC/RBAC) sur chaque endpoint d'API."}</p>
        <p><strong>P3 [Sous 30 jours] :</strong> {p3Actions || "3. Mettre en place un Web Application Firewall (WAF) en mode bloquant et intégrer la journalisation SIEM."}</p>
      </div>
    </div>

    {/* 8. ANNEXES & CERTIFICAT DE PENTEST */}
    <div className="border-t pt-2 mt-2">
      <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">
        7. Annexe — Attestation Officielle de Réalisation
      </h3>
      <p className="text-[10px] text-slate-600 italic">
        {certificateText || "Il est certifié par la présente que l'organisation Client SA a fait l'objet d'un test d'intrusion technique complet réalisé conformément aux règles de l'art par notre équipe d'évaluation."}
      </p>
      <p className="text-[9px] font-mono text-slate-400 mt-1">
        Outillage utilisé : {toolsUsed || "Burp Suite Professional, Nmap, Metasploit Framework, SQLmap"}
      </p>
    </div>

  </div>
)}