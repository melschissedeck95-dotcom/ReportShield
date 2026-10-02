"use client";

import React, { useState, useEffect } from "react";
import {
  Shield,
  FileText,
  Printer,
  Save,
  LogIn,
  LogOut,
  CheckCircle,
  FolderOpen,
  Trash2,
  Crosshair,
  List,
  Globe,
  Download,
  Calculator,
  Award,
  Activity,
  Cpu,
  FileCheck2,
  Bug,
  Languages,
  CheckSquare,
  AlertTriangle,
  FileCode,
  BookOpen,
  Target,
  FileSpreadsheet,
  Award as CertIcon
} from "lucide-react";
import { supabase } from "@/lib/supabase";

interface IOCItem {
  id: string;
  type: string;
  value: string;
  description: string;
}

interface TimelineEvent {
  id: string;
  time: string;
  title: string;
  description: string;
}

interface ReportItem {
  id: string;
  client_name: string;
  analyst_name: string;
  incident_date: string;
  title: string;
  severity: string;
  systems: string;
  description: string;
  root_cause: string;
  recommendations: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  iocs?: IOCItem[];
  timeline_events?: TimelineEvent[];
  logo_url?: string;
  threat_actor?: string;
  threat_motivation?: string;
  threat_sophistication?: string;
  confidence_level?: string;
  cvss_score?: number;
  report_type?: string;
  iso_scores?: Record<string, boolean>;
  pci_scores?: Record<string, boolean>;
  gap_analysis_summary?: string;
  gap_action_plan?: string;
  poc_steps?: string;
  created_at: string;
}

const MITRE_TACTICS = [
  { name: "Initial Access", techniques: ["T1190 - Exploit Public-Facing Application", "T1078 - Valid Accounts", "T1566 - Phishing"] },
  { name: "Execution", techniques: ["T1059 - Command and Scripting Interpreter", "T1204 - User Execution"] },
  { name: "Persistence", techniques: ["T1098 - Account Manipulation", "T1543 - Create or Modify System Process"] },
  { name: "Privilege Escalation", techniques: ["T1068 - Exploitation for Privilege Escalation", "T1548 - Abuse Elevation Control"] },
  { name: "Credential Access", techniques: ["T1110 - Brute Force", "T1003 - OS Credential Dumping"] },
  { name: "Defense Evasion", techniques: ["T1562 - Impair Defenses", "T1070 - Indicator Removal"] },
  { name: "Lateral Movement", techniques: ["T1021 - Remote Services", "T1570 - Lateral Tool Transfer"] },
  { name: "Exfiltration", techniques: ["T1041 - Exfiltration Over C2 Channel", "T1567 - Exfiltration Over Web Service"] },
];

const ISO_CONTROLS_2022 = [
  { id: "A5.1", theme: "Organisationnel", label_fr: "Politiques de sécurité de l'information documentées", label_en: "Documented Information Security Policies" },
  { id: "A5.7", theme: "Organisationnel", label_fr: "Threat Intelligence intégrée et exploitée", label_en: "Threat Intelligence Integration & Usage" },
  { id: "A5.15", theme: "Organisationnel", label_fr: "Gestion et contrôle strict des accès (RBAC)", label_en: "Access Control & RBAC Management" },
  { id: "A6.8", theme: "Personnes", label_fr: "Sensibilisation et formation à la sécurité", label_en: "Security Awareness & Training" },
  { id: "A7.4", theme: "Physique", label_fr: "Surveillance physique des accès aux locaux/datacenter", label_en: "Physical Security Monitoring" },
  { id: "A8.8", theme: "Technique", label_fr: "Gestion des vulnérabilités et correctifs (Patching)", label_en: "Vulnerability & Patch Management" },
  { id: "A8.12", theme: "Technique", label_fr: "Prévention contre la fuite de données (DLP)", label_en: "Data Leakage Prevention (DLP)" },
  { id: "A8.16", theme: "Technique", label_fr: "Surveillance et journalisation continue (SIEM)", label_en: "Continuous Monitoring & SIEM Logging" },
];

const PCI_CONTROLS_V4 = [
  { id: "Req 1", reqGroup: "Réseau Sécurisé", label_fr: "Maintien de contrôles réseau et microsegmentation CDE", label_en: "Network Controls & CDE Microsegmentation" },
  { id: "Req 3", reqGroup: "Protection des Données", label_fr: "Chiffrement des PAN et interdiction stockage SAD", label_en: "PAN Encryption & SAD Storage Prohibition" },
  { id: "Req 4", reqGroup: "Protection des Données", label_fr: "Chiffrement fort lors des transmissions ouvertes", label_en: "Strong Encryption in Open Networks" },
  { id: "Req 6", reqGroup: "Gestion des Vulnérabilités", label_fr: "Développement sécurisé et patchs critiques sous 30j", label_en: "Secure Coding & Critical Patching < 30 Days" },
  { id: "Req 8", reqGroup: "Contrôle d'Accès", label_fr: "MFA obligatoire pour accès administrateur et réseau CDE", label_en: "Mandatory MFA for CDE Access" },
  { id: "Req 10", reqGroup: "Surveillance & Logging", label_fr: "Journalisation active des accès et conservation 12 mois", label_en: "Active Audit Trail & 12-Month Log Retention" },
  { id: "Req 11", reqGroup: "Tests Réguliers", label_fr: "Scans ASV trimestriels et tests d'intrusion annuels", label_en: "Quarterly ASV Scans & Annual Penetration Tests" },
  { id: "Req 12", reqGroup: "Gouvernance", label_fr: "Politique de sécurité globale et évaluation des risques", label_en: "Global Security Policy & Risk Assessments" },
];

export default function Home() {
  const [user, setUser] = useState<any>(null);
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [savedReports, setSavedReports] = useState<ReportItem[]>([]);

  // Langue (FR / EN)
  const [lang, setLang] = useState<"fr" | "en">("fr");

  // Profil sélectionné
  const [reportType, setReportType] = useState<"SOC_CTI" | "Pentest" | "Compliance">("Pentest");

  // Métadonnées Générales (Étape 1 - Page de Garde)
  const [logoBase64, setLogoBase64] = useState<string>("");
  const [clientName, setClientName] = useState("Entreprise Client SA");
  const [analystName, setAnalystName] = useState("Analyste Pentesteur / QSA Assistant");
  const [date, setDate] = useState(new Date().toISOString().split("T")[0]);
  const [tlpMarking, setTlpMarking] = useState("TLP:AMBER");
  const [reportVersion, setReportVersion] = useState("v1.0 (Rapport Final)");

  // --- ÉTAPES 1 À 8 SPÉCIFIQUES AUDIT / PENTEST ---
  // Étape 2 - Synthèse Exécutive
  const [execSummary, setExecSummary] = useState(
    "L'audit de sécurité réalisé a mis en évidence un niveau de risque global ÉLEVÉ. Plusieurs vulnérabilités critiques ont été exploitées permettant la compromission totale de la base de données client et le contournement des mécanismes d'authentification."
  );
  const [overallRiskRating, setOverallRiskRating] = useState("Élevé / High Risk");

  // Étape 3 - Périmètre & Règles d'engagement
  const [inScopeTarget, setInScopeTarget] = useState("https://api.client.com (Portail Web & API V1) - 192.168.10.0/24");
  const [outScopeTarget, setOutScopeTarget] = useState("Environnement de Production ERP, Passerelle de Paiement Tiers");
  const [methodology, setMethodology] = useState("OWASP Top 10 (2021), PTES (Penetration Testing Execution Standard), NIST SP 800-115");

  // Étape 4 - Matrice CVSS v3.1 & Cotation
  const [cvssAV, setCvssAV] = useState<number>(0.85); // Network
  const [cvssAC, setCvssAC] = useState<number>(0.77); // Low
  const [cvssPR, setCvssPR] = useState<number>(0.85); // None
  const [cvssUI, setCvssUI] = useState<number>(0.85); // None
  const [cvssImpactC, setCvssImpactC] = useState<number>(0.56); // High
  const [cvssImpactI, setCvssImpactI] = useState<number>(0.56); // High
  const [cvssImpactA, setCvssImpactA] = useState<number>(0.56); // High

  // Étape 5 - Fiches Détaillées de Vulnérabilités & PoC
  const [vulnTitle, setVulnTitle] = useState("SQL Injection (Blind) & Broken Object Level Authorization (BOLA)");
  const [owaspCategory, setOwaspCategory] = useState("A03:2021 - Injection & A01:2021 - Broken Access Control");
  const [cweReference, setCweReference] = useState("CWE-89 (SQLi), CWE-639 (BOLA)");
  const [pocSteps, setPocSteps] = useState(
    "1. Interception de la requête HTTP GET /api/v1/users/profile?id=102 via Burp Suite.\n" +
    "2. Injection du payload SQL `' UNION SELECT NULL, username, password_hash FROM admin_users--`.\n" +
    "3. Observation de la réponse HTTP 200 OK et extraction des hachages de mots de passe de la base de données."
  );

  // Étape 6 - Chemin d'Exploitation & MITRE ATT&CK
  const [attackPathDescription, setAttackPathDescription] = useState(
    "L'attaquant s'est d'abord appuyé sur la vulnérabilité d'injection SQL pour exfiltrer les identifiants administrateurs. Ces accès ont ensuite été réutilisés sur l'interface de gestion pour obtenir un accès shell à distance (RCE)."
  );
  const [mitreTactic, setMitreTactic] = useState<string>("Credential Access");
  const [mitreTechnique, setMitreTechnique] = useState<string>("T1110 - Brute Force");

  // Étape 7 - Plan de Remédiation Priorisé & Hardening
  const [p1Actions, setP1Actions] = useState("P1 [Immédiat] : Paramétrer des requêtes préparées (Parameterized Queries) pour bloquer les injections SQL.");
  const [p2Actions, setP2Actions] = useState("P2 [Sous 15 jours] : Implémenter un contrôle d'accès basé sur les rôles (RBAC) strict au niveau de chaque endpoint API.");
  const [p3Actions, setP3Actions] = useState("P3 [Sous 30 jours] : Déployer un Web Application Firewall (WAF) en mode bloquant et activer la journalisation SIEM.");

  // Étape 8 - Annexes & Certificat de Pentest
  const [toolsUsed, setToolsUsed] = useState("Burp Suite Professional v2024, Nmap, Metasploit Framework, SQLmap, OWASP ZAP");
  const [certificateText, setCertificateText] = useState(
    "Il est certifié par la présente que l'organisation Client SA a fait l'objet d'un test d'intrusion technique complet réalisé conformément aux règles de l'art par notre équipe d'évaluation."
  );

  // Champs SOC / CTI / Compliance
  const [socTitle, setSocTitle] = useState("Infiltration via Ransomware & Attaque Force Brute VPN");
  const [socSystems, setSocSystems] = useState("Serveur Active Directory, BDD Client, Passerelle VPN");
  const [socDescription, setSocDescription] = useState("Compromission initiale par force brute sur VPN.");
  const [socRootCause, setSocRootCause] = useState("Mots de passe faibles et absence de MFA.");
  const [socRecommendations, setSocRecommendations] = useState("1. Activer le MFA.\n2. Bloquer les IPs malveillantes.");
  const [threatActor, setThreatActor] = useState<string>("LockBit 3.0 / APT29");
  const [threatMotivation, setThreatMotivation] = useState<string>("Gain Financier");
  const [threatSophistication, setThreatSophistication] = useState<string>("Élevée");
  const [confidenceLevel, setConfidenceLevel] = useState<string>("Élevée");
  const [isoChecks, setIsoChecks] = useState<Record<string, boolean>>({ "A5.1": true, "A5.7": false, "A5.15": true, "A6.8": true, "A7.4": false, "A8.8": false, "A8.12": false, "A8.16": true });
  const [pciChecks, setPciChecks] = useState<Record<string, boolean>>({ "Req 1": true, "Req 3": false, "Req 4": true, "Req 6": false, "Req 8": false, "Req 10": true, "Req 11": false, "Req 12": true });
  const [gapSummary, setGapSummary] = useState("Alignement partiel sur ISO 27001 et PCI DSS.");
  const [gapActionPlan, setGapActionPlan] = useState("1. Déployer le MFA sous 15 jours.");
  const [rawLogsText, setRawLogsText] = useState<string>("");
  const [iocs, setIocs] = useState<IOCItem[]>([
    { id: "1", type: "IP Address", value: "192.168.1.105", description: "IP C2" },
  ]);

  useEffect(() => {
    const initAuth = async () => {
      const { data } = await supabase.auth.getUser();
      setUser(data.user);
      if (data.user) fetchReports();
    };
    initAuth();
    const { data: authListener } = supabase.auth.onAuthStateChange((_, session) => {
      setUser(session?.user ?? null);
      if (session?.user) fetchReports();
      else setSavedReports([]);
    });
    return () => authListener.subscription.unsubscribe();
  }, []);

  const fetchReports = async () => {
    const { data } = await supabase.from("reports").select("*").order("created_at", { ascending: false });
    if (data) setSavedReports(data as ReportItem[]);
  };

  const isoMaturityPercent = Math.round((Object.values(isoChecks).filter(Boolean).length / ISO_CONTROLS_2022.length) * 100);
  const pciMaturityPercent = Math.round((Object.values(pciChecks).filter(Boolean).length / PCI_CONTROLS_V4.length) * 100);

  const calculateCVSSScore = (): number => {
    const iss = 1 - (1 - cvssImpactC) * (1 - cvssImpactI) * (1 - cvssImpactA);
    const impact = 6.42 * iss;
    const exploitability = 8.22 * cvssAV * cvssAC * cvssPR * cvssUI;
    if (impact <= 0) return 0;
    return Math.min(10, Math.ceil((impact + exploitability) * 10) / 10);
  };
  const computedCvssScore = calculateCVSSScore();

  const handleSaveReport = async () => {
    if (!user) { alert("Veuillez vous connecter !"); return; }
    setLoading(true);
    const { error } = await supabase.from("reports").insert([{
      user_id: user.id,
      client_name: clientName,
      analyst_name: analystName,
      incident_date: date,
      title: reportType === "Pentest" ? vulnTitle : reportType === "SOC_CTI" ? socTitle : "Compliance Report",
      severity: overallRiskRating,
      systems: inScopeTarget,
      description: reportType === "Pentest" ? execSummary : socDescription,
      root_cause: attackPathDescription,
      recommendations: `${p1Actions}\n${p2Actions}\n${p3Actions}`,
      mitre_tactic: mitreTactic,
      mitre_technique: mitreTechnique,
      iocs: iocs,
      logo_url: logoBase64,
      cvss_score: computedCvssScore,
      report_type: reportType,
      poc_steps: pocSteps
    }]);

    if (error) alert(`Erreur: ${error.message}`);
    else { alert("Rapport sauvegardé avec succès !"); fetchReports(); }
    setLoading(false);
  };

  return (
    <>
      <style jsx global>{`
        @media print {
          body * { visibility: hidden; }
          #pdf-report, #pdf-report * { visibility: visible; }
          #pdf-report { position: absolute; left: 0; top: 0; width: 100%; margin: 0; padding: 20px; }
          .no-print { display: none !important; }
        }
      `}</style>

      <main className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
        
        {/* EN-TÊTE FIXE */}
        <header className="bg-slate-900/90 border-b border-slate-800 px-8 py-4 flex flex-col md:flex-row items-center justify-between gap-4 sticky top-0 z-50 no-print">
          <div className="flex items-center gap-3">
            <Shield className="w-7 h-7 text-blue-500" />
            <div>
              <h1 className="text-xl font-bold text-white">ReportShield Pro</h1>
              <p className="text-xs text-slate-400">Générateur de Rapports Cyber & Audits Normalisés</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button onClick={() => setLang(lang === "fr" ? "en" : "fr")} className="bg-slate-800 text-amber-400 px-3 py-1.5 rounded-lg border border-slate-700 text-xs font-bold flex items-center gap-1.5 cursor-pointer">
              <Languages className="w-4 h-4" /> {lang === "fr" ? "English 🇬🇧" : "Français 🇫🇷"}
            </button>

            {user ? (
              <span className="text-xs text-slate-300 bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700">{user.email}</span>
            ) : (
              <form onSubmit={async (e) => { e.preventDefault(); await supabase.auth.signInWithOtp({ email }); setMessage("Lien envoyé !"); }} className="flex gap-2">
                <input type="email" placeholder="email@domain.com" value={email} onChange={(e) => setEmail(e.target.value)} className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs text-white" />
                <button type="submit" className="bg-blue-600 text-white px-3 py-1 rounded text-xs">Connexion</button>
              </form>
            )}

            <button onClick={handleSaveReport} disabled={loading} className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-xs cursor-pointer">
              <Save className="w-4 h-4" /> Sauvegarder
            </button>

            <button onClick={() => window.print()} className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-xs cursor-pointer">
              <Printer className="w-4 h-4" /> Export PDF
            </button>
          </div>
        </header>

        {/* CHOIX DU PROFIL */}
        <div className="bg-slate-900/50 border-b border-slate-800 px-8 py-3 flex items-center justify-between no-print">
          <span className="text-xs font-semibold text-slate-400">Profil de Livrable :</span>
          <div className="flex gap-2">
            {[
              { id: "Pentest", label: "🛡️ AUDIT DE SÉCURITÉ & PENTEST (8 ÉTAPES)", color: "bg-amber-600/20 text-amber-400 border-amber-500/40" },
              { id: "SOC_CTI", label: "🚨 SOC INCIDENT & THREAT INTEL", color: "bg-red-600/20 text-red-400 border-red-500/40" },
              { id: "Compliance", label: "📊 CONFORMITÉ ISO 27001 & PCI DSS", color: "bg-emerald-600/20 text-emerald-400 border-emerald-500/40" }
            ].map((p) => (
              <button
                key={p.id}
                onClick={() => setReportType(p.id as any)}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer border ${
                  reportType === p.id ? `${p.color} scale-105 shadow-lg` : "bg-slate-900 text-slate-500 border-slate-800 hover:text-slate-300"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* GRILLE 12 COLONNES */}
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 p-8">
          
          {/* FORMULAIRES PENTEST 8 ÉTAPES (SPAN 7) */}
          <div className="lg:col-span-7 space-y-6 no-print">
            
            {reportType === "Pentest" && (
              <div className="space-y-6 animate-fadeIn">
                
                {/* ÉTAPE 1 : PAGE DE GARDE & MÉTADONNÉES */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                    <BookOpen className="w-4 h-4" /> Étape 1 : Page de Garde & Métadonnées
                  </h2>
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Client / Organisation</label>
                      <input type="text" value={clientName} onChange={(e) => setClientName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Auditeur / QSA Assistant</label>
                      <input type="text" value={analystName} onChange={(e) => setAnalystName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Marquage Confidentialité</label>
                      <select value={tlpMarking} onChange={(e) => setTlpMarking(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white">
                        <option value="TLP:AMBER">TLP:AMBER (Restreint)</option>
                        <option value="TLP:RED">TLP:RED (Strictement Confidentiel)</option>
                        <option value="TLP:GREEN">TLP:GREEN (Interne)</option>
                      </select>
                    </div>
                  </div>
                </div>

                {/* ÉTAPE 2 : SYNTHÈSE EXÉCUTIVE */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                    <FileText className="w-4 h-4" /> Étape 2 : Synthèse Exécutive (Management)
                  </h2>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">Évaluation Global du Risque</label>
                      <select value={overallRiskRating} onChange={(e) => setOverallRiskRating(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white">
                        <option value="Critique / Critical">Critique / Critical</option>
                        <option value="Élevé / High Risk">Élevé / High Risk</option>
                        <option value="Moyen / Medium Risk">Moyen / Medium Risk</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">Résumé Décisionnel</label>
                      <textarea rows={3} value={execSummary} onChange={(e) => setExecSummary(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
                    </div>
                  </div>
                </div>

                {/* ÉTAPE 3 : PÉRIMÈTRE & RÈGLES D'ENGAGEMENT */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                    <Target className="w-4 h-4" /> Étape 3 : Périmètre & Règles d'Engagement
                  </h2>
                  <div className="space-y-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Périmètre Autorisé (In-Scope)</label>
                      <input type="text" value={inScopeTarget} onChange={(e) => setInScopeTarget(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Périmètre Exclu (Out-of-Scope)</label>
                      <input type="text" value={outScopeTarget} onChange={(e) => setOutScopeTarget(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Méthodologies Appliquées</label>
                      <input type="text" value={methodology} onChange={(e) => setMethodology(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                  </div>
                </div>

                {/* ÉTAPE 4 : MATRICE CVSS V3.1 */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                    <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider flex items-center gap-2">
                      <Calculator className="w-4 h-4" /> Étape 4 : Matrice CVSS v3.1
                    </h2>
                    <span className="text-xs font-bold bg-amber-600 text-white px-2.5 py-1 rounded">Score : {computedCvssScore} / 10</span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <div>
                      <label className="block text-[10px] text-slate-400">Attack Vector (AV)</label>
                      <select value={cvssAV} onChange={(e) => setCvssAV(parseFloat(e.target.value))} className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white">
                        <option value={0.85}>Network</option>
                        <option value={0.62}>Adjacent</option>
                        <option value={0.55}>Local</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">Complexity (AC)</label>
                      <select value={cvssAC} onChange={(e) => setCvssAC(parseFloat(e.target.value))} className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white">
                        <option value={0.77}>Low</option>
                        <option value={0.44}>High</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">Privileges (PR)</label>
                      <select value={cvssPR} onChange={(e) => setCvssPR(parseFloat(e.target.value))} className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-white">
                        <option value={0.85}>None</option>
                        <option value={0.62}>Low</option>
                        <option value={0.27}>High</option>
                      </select>
                    </div>
                  </div>
                </div>

                {/* ÉTAPE 5 : FICHES DE VULNÉRABILITÉ & POC */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                    <Bug className="w-4 h-4" /> Étape 5 : Fiche Technique & Preuve de Concept (PoC)
                  </h2>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Titre Vulnérabilité</label>
                      <input type="text" value={vulnTitle} onChange={(e) => setVulnTitle(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Catégorie OWASP / CWE</label>
                      <input type="text" value={owaspCategory} onChange={(e) => setOwaspCategory(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Preuve de Concept (PoC Pas-à-Pas)</label>
                    <textarea rows={4} value={pocSteps} onChange={(e) => setPocSteps(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white font-mono" />
                  </div>
                </div>

                {/* ÉTAPE 6 : CHEMIN D'EXPLOITATION & MITRE */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                    <Crosshair className="w-4 h-4" /> Étape 6 : Chemin d'Exploitation & MITRE ATT&CK
                  </h2>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Scénario de Chaînage (Vulnerability Chaining)</label>
                    <textarea rows={3} value={attackPathDescription} onChange={(e) => setAttackPathDescription(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
                  </div>
                </div>

                {/* ÉTAPE 7 : PLAN DE REMÉDIATION PRIORISÉ */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                    <FileSpreadsheet className="w-4 h-4" /> Étape 7 : Plan d'Action & Feulle de Route
                  </h2>
                  <div className="space-y-2 text-xs">
                    <input type="text" value={p1Actions} onChange={(e) => setP1Actions(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono" />
                    <input type="text" value={p2Actions} onChange={(e) => setP2Actions(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono" />
                    <input type="text" value={p3Actions} onChange={(e) => setP3Actions(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono" />
                  </div>
                </div>

                {/* ÉTAPE 8 : ANNEXES & CERTIFICAT */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                    <CertIcon className="w-4 h-4" /> Étape 8 : Annexes & Certificat de Pentest
                  </h2>
                  <div className="space-y-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Outillage Utilisé</label>
                      <input type="text" value={toolsUsed} onChange={(e) => setToolsUsed(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Texte de l'Attestation Officielle</label>
                      <textarea rows={2} value={certificateText} onChange={(e) => setCertificateText(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                  </div>
                </div>

              </div>
            )}

            {/* AUTRES PROFILS (SOC / COMPLIANCE) */}
            {reportType !== "Pentest" && (
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                <p className="text-xs text-slate-400">Basculez sur l'onglet correspondant pour éditer ce profil.</p>
              </div>
            )}
          </div>

          {/* RENDU PDF CANONIQUE COMPLET EN 8 ÉTAPES (SPAN 5) */}
          <div className="lg:col-span-5 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-2xl flex flex-col items-center h-fit sticky top-24">
            <span className="text-xs font-semibold text-slate-400 mb-3 no-print flex items-center gap-2">
              <Cpu className="w-4 h-4 text-amber-400" /> Rendu du Rapport d'Audit (8 Éapes)
            </span>

            {/* DOCUMENT CANONIQUE D'IMPRESSION PDF */}
            <div id="pdf-report" className="w-full bg-white text-slate-900 p-8 rounded-xl shadow-2xl border border-slate-200 text-xs space-y-5">
              
              {/* 1. PAGE DE GARDE */}
              <div className="border-b-2 border-slate-900 pb-4">
                <div className="flex justify-between items-start">
                  <div>
                    <h1 className="text-base font-extrabold uppercase text-slate-900">Rapport d'Audit & Test d'Intrusion</h1>
                    <p className="text-[10px] text-slate-500 font-semibold">{reportVersion} — {tlpMarking}</p>
                  </div>
                  <div className="text-right text-[10px]">
                    <p><strong>Client :</strong> {clientName}</p>
                    <p><strong>Auditeur :</strong> {analystName}</p>
                    <p><strong>Date :</strong> {date}</p>
                  </div>
                </div>
              </div>

              {/* 2. SYNTHÈSE EXÉCUTIVE */}
              <div>
                <h3 className="font-bold uppercase text-slate-800 border-b pb-1 mb-1 text-[10px]">1. Executive Summary</h3>
                <div className="bg-amber-50 p-2 rounded border border-amber-200 mb-1 flex justify-between items-center">
                  <span className="font-bold">Niveau de Risque Global</span>
                  <span className="bg-amber-600 text-white font-bold px-2 py-0.5 rounded">{overallRiskRating}</span>
                </div>
                <p className="text-slate-700 leading-relaxed">{execSummary}</p>
              </div>

              {/* 3. PÉRIMÈTRE & ENGAGEMENT */}
              <div>
                <h3 className="font-bold uppercase text-slate-800 border-b pb-1 mb-1 text-[10px]">2. Scope & Methodology</h3>
                <p><strong>In-Scope :</strong> {inScopeTarget}</p>
                <p><strong>Out-of-Scope :</strong> {outScopeTarget}</p>
                <p className="text-[10px] text-slate-500 mt-0.5">Standards : {methodology}</p>
              </div>

              {/* 4. CVSS V3.1 SCORE */}
              <div className="bg-slate-50 p-2 rounded border border-slate-200 flex justify-between items-center">
                <span className="font-bold">Cotation CVSS v3.1</span>
                <span className="bg-slate-900 text-white font-mono font-bold px-2 py-0.5 rounded">Score : {computedCvssScore} / 10</span>
              </div>

              {/* 5. FICHE VULNÉRABILITÉ & POC */}
              <div>
                <h3 className="font-bold uppercase text-slate-800 border-b pb-1 mb-1 text-[10px]">3. Technical Finding & PoC</h3>
                <p className="font-bold text-red-700">{vulnTitle}</p>
                <p className="text-[10px] text-slate-500">{owaspCategory} ({cweReference})</p>
                <p className="font-mono bg-slate-100 p-2 rounded mt-1 whitespace-pre-line text-[10px]">{pocSteps}</p>
              </div>

              {/* 6. ATTACK PATH & MITRE */}
              <div>
                <h3 className="font-bold uppercase text-slate-800 border-b pb-1 mb-1 text-[10px]">4. Attack Path & MITRE ATT&CK</h3>
                <p className="text-slate-700 mb-1">{attackPathDescription}</p>
                <span className="bg-purple-100 text-purple-900 font-bold px-2 py-0.5 rounded text-[10px]">{mitreTactic} / {mitreTechnique}</span>
              </div>

              {/* 7. REMÉDIATION & ROADMAP */}
              <div>
                <h3 className="font-bold uppercase text-slate-800 border-b pb-1 mb-1 text-[10px]">5. Remediation Roadmap</h3>
                <p className="font-mono text-green-900 bg-green-50 p-2 rounded text-[10px] whitespace-pre-line">
                  {p1Actions}{"\n"}{p2Actions}{"\n"}{p3Actions}
                </p>
              </div>

              {/* 8. ANNEXES & CERTIFICAT */}
              <div className="border-t pt-2">
                <h3 className="font-bold uppercase text-slate-800 border-b pb-1 mb-1 text-[10px]">6. Attestation Officielle</h3>
                <p className="text-[10px] text-slate-600 italic">{certificateText}</p>
                <p className="text-[9px] text-slate-400 mt-1">Outillage : {toolsUsed}</p>
              </div>

            </div>
          </div>
        </div>
      </main>
    </>
  );
}