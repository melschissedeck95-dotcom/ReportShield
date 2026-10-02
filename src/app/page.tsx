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
  Wand2,
  Calculator,
  Award,
  Activity,
  Cpu,
  FileCheck2,
  Bug,
  Languages
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

  // Profil sélectionné (SOC+CTI, Pentest, Compliance)
  const [reportType, setReportType] = useState<"SOC_CTI" | "Pentest" | "Compliance">("SOC_CTI");

  // Formulaire Générique
  const [logoBase64, setLogoBase64] = useState<string>("");
  const [clientName, setClientName] = useState("Entreprise Client SA");
  const [analystName, setAnalystName] = useState("Analyste Cyber / RSSI");
  const [date, setDate] = useState(new Date().toISOString().split("T")[0]);
  const [severity, setSeverity] = useState("Élevée / High");

  // Champs Profil 1 : Combined SOC + CTI
  const [socTitle, setSocTitle] = useState("Infiltration via Ransomware & Attaque Force Brute VPN");
  const [socSystems, setSocSystems] = useState("Serveur Active Directory, BDD Client, Passerelle VPN");
  const [socDescription, setSocDescription] = useState("Compromission initiale par attaque de force brute sur le portail VPN, suivie d'un mouvement latéral et d'une tentative d'exfiltration de données.");
  const [socRootCause, setSocRootCause] = useState("Mots de passe faibles et absence d'authentification multifacteur (MFA) sur les accès distants.");
  const [socRecommendations, setSocRecommendations] = useState("1. Déploiement immédiat du MFA sur tous les accès VPN.\n2. Blocage permanent des adresses IP malveillantes listées dans les IOCs.\n3. Réinitialisation globale des secrets Kerberos et mots de passe AD.");
  const [threatActor, setThreatActor] = useState<string>("LockBit 3.0 / APT29");
  const [threatMotivation, setThreatMotivation] = useState<string>("Gain Financier (Ransomware / Extorsion)");
  const [threatSophistication, setThreatSophistication] = useState<string>("Élevée (Organisé / State-Sponsored)");
  const [confidenceLevel, setConfidenceLevel] = useState<string>("Élevée (High Confidence)");
  const [mitreTactic, setMitreTactic] = useState<string>("Credential Access");
  const [mitreTechnique, setMitreTechnique] = useState<string>("T1110 - Brute Force");

  // Champs Profil 2 : Audit & Pentest
  const [pentestTarget, setPentestTarget] = useState("API de Paiement & Portail Web Client");
  const [vulnName, setVulnName] = useState("Injection SQL non authentifiée (Blind SQLi) & Broken Object Level Authorization (BOLA)");
  const [pocSteps, setPocSteps] = useState("1. Envoi du payload SQLi sur le paramètre `/api/v1/user?id=1' UNION SELECT NULL--`.\n2. Contournement de l'authentification et récupération des tables d'utilisateurs.\n3. Exploitation du BOLA pour accéder aux données bancaires de clients tiers.");
  const [pentestFix, setPentestFix] = useState("1. Remplacer les requêtes dynamiques par des requêtes préparées (Parameterized Queries).\n2. Implémenter un contrôle d'accès au niveau des objets (ABAC/RBAC).\n3. Mettre en place un WAF (Web Application Firewall) en mode bloquant.");

  // CVSS v3.1
  const [cvssAV, setCvssAV] = useState<number>(0.85);
  const [cvssAC, setCvssAC] = useState<number>(0.77);
  const [cvssPR, setCvssPR] = useState<number>(0.85);
  const [cvssUI, setCvssUI] = useState<number>(0.85);
  const [cvssImpactC, setCvssImpactC] = useState<number>(0.56);
  const [cvssImpactI, setCvssImpactI] = useState<number>(0.56);
  const [cvssImpactA, setCvssImpactA] = useState<number>(0.56);

  // Champs Profil 3 : Conformité & Compliance
  const [isoChecks, setIsoChecks] = useState<Record<string, boolean>>({ "A5.1": true, "A5.7": false, "A5.15": true, "A6.8": true, "A7.4": false, "A8.8": false, "A8.12": false, "A8.16": true });
  const [pciChecks, setPciChecks] = useState<Record<string, boolean>>({ "Req 1": true, "Req 3": false, "Req 4": true, "Req 6": false, "Req 8": false, "Req 10": true, "Req 11": false, "Req 12": true });
  const [gapSummary, setGapSummary] = useState("Alignement partiel sur ISO 27001:2022 et PCI DSS v4.0. Écarts critiques identifiés sur l'absence de MFA et la fréquence des scans ASV.");
  const [gapActionPlan, setGapActionPlan] = useState("1. [Priorité Urgente] Déploiement du MFA généralisé sous 15 jours.\n2. [Priorité Haute] Mise en conformité de la gestion des correctifs sous 30 jours.\n3. [Priorité Moyenne] Intégration d'une solution DLP et surveillance SIEM 24/7.");

  // IOCs & Parseur
  const [rawLogsText, setRawLogsText] = useState<string>("");
  const [iocs, setIocs] = useState<IOCItem[]>([
    { id: "1", type: "IP Address", value: "192.168.1.105", description: "IP C2 Attaquant" },
    { id: "2", type: "Hash SHA256", value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", description: "Payload LockBit 3.0" }
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

  const handleParseLogs = () => {
    if (!rawLogsText) return;
    const extracted: IOCItem[] = [];
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const ips = Array.from(new Set(rawLogsText.match(ipRegex) || []));
    ips.forEach(ip => {
      if (ip !== "127.0.0.1") extracted.push({ id: Math.random().toString(), type: "IP Address", value: ip, description: lang === "fr" ? "Extrait des logs" : "Extracted from logs" });
    });
    if (extracted.length > 0) {
      setIocs([...iocs, ...extracted]);
      setRawLogsText("");
      alert(lang === "fr" ? `${extracted.length} IOC(s) extrait(s) !` : `${extracted.length} IOC(s) extracted!`);
    } else alert(lang === "fr" ? "Aucun IOC trouvé." : "No IOCs found.");
  };

  const handleExportSTIX = () => {
    const stixBundle = {
      type: "bundle",
      id: `bundle--${crypto.randomUUID()}`,
      objects: iocs.map(ioc => ({
        type: "indicator",
        spec_version: "2.1",
        id: `indicator--${ioc.id}`,
        pattern: `[ipv4-addr:value = '${ioc.value}']`,
        description: ioc.description
      }))
    };
    const blob = new Blob([JSON.stringify(stixBundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `STIX2.1_${clientName}.json`;
    link.click();
  };

  const handleSaveReport = async () => {
    if (!user) { alert(lang === "fr" ? "Veuillez vous connecter !" : "Please log in!"); return; }
    setLoading(true);
    const { error } = await supabase.from("reports").insert([{
      user_id: user.id,
      client_name: clientName,
      analyst_name: analystName,
      incident_date: date,
      title: reportType === "SOC_CTI" ? socTitle : reportType === "Pentest" ? vulnName : "ISO 27001 / PCI DSS Compliance Report",
      severity: severity,
      systems: socSystems,
      description: reportType === "SOC_CTI" ? socDescription : reportType === "Pentest" ? pocSteps : gapSummary,
      root_cause: socRootCause,
      recommendations: reportType === "SOC_CTI" ? socRecommendations : pentestFix,
      mitre_tactic: mitreTactic,
      mitre_technique: mitreTechnique,
      iocs: iocs,
      logo_url: logoBase64,
      threat_actor: threatActor,
      threat_motivation: threatMotivation,
      threat_sophistication: threatSophistication,
      confidence_level: confidenceLevel,
      cvss_score: computedCvssScore,
      report_type: reportType,
      iso_scores: isoChecks,
      pci_scores: pciChecks,
      gap_analysis_summary: gapSummary,
      gap_action_plan: gapActionPlan,
      poc_steps: pocSteps
    }]);

    if (error) alert(`Erreur: ${error.message}`);
    else { alert(lang === "fr" ? "Rapport sauvegardé avec succès !" : "Report saved successfully!"); fetchReports(); }
    setLoading(false);
  };

  const selectedTacticObj = MITRE_TACTICS.find(t => t.name === mitreTactic);

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
        
        {/* EN-TÊTE FIXE PANORAMIQUE */}
        <header className="bg-slate-900/90 border-b border-slate-800 px-8 py-4 flex flex-col md:flex-row items-center justify-between gap-4 sticky top-0 z-50 no-print">
          <div className="flex items-center gap-3">
            <Shield className="w-7 h-7 text-blue-500" />
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white">ReportShield Pro</h1>
              <p className="text-xs text-slate-400">
                {lang === "fr" ? "Plateforme SOC & CTI Combinée, Audit Pentest & Conformité" : "Combined SOC & CTI Platform, Pentest Audit & Compliance"}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* COMMUTATEUR DE LANGUE */}
            <button
              onClick={() => setLang(lang === "fr" ? "en" : "fr")}
              className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-amber-400 px-3 py-1.5 rounded-lg border border-slate-700 text-xs cursor-pointer font-bold"
            >
              <Languages className="w-4 h-4" /> {lang === "fr" ? "English 🇬🇧" : "Français 🇫🇷"}
            </button>

            {user ? (
              <span className="text-xs text-slate-300 bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700">{user.email}</span>
            ) : (
              <form onSubmit={async (e) => { e.preventDefault(); await supabase.auth.signInWithOtp({ email }); setMessage(lang === "fr" ? "Lien envoyé !" : "Link sent!"); }} className="flex gap-2">
                <input type="email" placeholder="email@domain.com" value={email} onChange={(e) => setEmail(e.target.value)} className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs text-white" />
                <button type="submit" className="bg-blue-600 text-white px-3 py-1 rounded text-xs">{lang === "fr" ? "Connexion" : "Login"}</button>
              </form>
            )}

            <button onClick={handleSaveReport} disabled={loading} className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-xs cursor-pointer">
              <Save className="w-4 h-4" /> {lang === "fr" ? "Sauvegarder" : "Save"}
            </button>

            <button onClick={() => window.print()} className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-xs cursor-pointer">
              <Printer className="w-4 h-4" /> {lang === "fr" ? "Export PDF" : "PDF Export"}
            </button>
          </div>
        </header>

        {/* SELECTION DU PROFIL DE RAPPORT */}
        <div className="bg-slate-900/50 border-b border-slate-800 px-8 py-3 flex items-center justify-between no-print">
          <span className="text-xs font-semibold text-slate-400">
            {lang === "fr" ? "Choix du Profil & Livrable :" : "Select Report Profile:"}
          </span>
          <div className="flex gap-2">
            {[
              { id: "SOC_CTI", label_fr: "🚨 INCIDENT SOC & THREAT INTEL (CTI) COMBINÉ", label_en: "🚨 COMBINED SOC INCIDENT & CTI REPORT", color: "bg-red-600/20 text-red-400 border-red-500/40" },
              { id: "Pentest", label_fr: "🛡️ AUDIT DE SÉCURITÉ & PENTEST DÉTAILLÉ", label_en: "🛡️ DETAILED PENTEST & AUDIT REPORT", color: "bg-amber-600/20 text-amber-400 border-amber-500/40" },
              { id: "Compliance", label_fr: "📊 RAPPORT DE CONFORMITÉ ISO 27001 & PCI DSS", label_en: "📊 ISO 27001 & PCI DSS COMPLIANCE REPORT", color: "bg-emerald-600/20 text-emerald-400 border-emerald-500/40" }
            ].map((p) => (
              <button
                key={p.id}
                onClick={() => setReportType(p.id as any)}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer border ${
                  reportType === p.id ? `${p.color} scale-105 shadow-lg` : "bg-slate-900 text-slate-500 border-slate-800 hover:text-slate-300"
                }`}
              >
                {lang === "fr" ? p.label_fr : p.label_en}
              </button>
            ))}
          </div>
        </div>

        {/* CONTENU PANORAMIQUE EN 2 COLONNES */}
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 p-8">
          
          {/* COLONNE GAUCHE : FORMULAIRES SPÉCIFIQUES (SPAN 7) */}
          <div className="lg:col-span-7 space-y-6 no-print">

            {/* CONTEXTE ORGANISATIONNEL COMMON */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider border-b border-slate-800 pb-2">
                {lang === "fr" ? "Informations Générales Client" : "General Client Metadata"}
              </h2>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Organisation Client" : "Client Organization"}</label>
                  <input type="text" value={clientName} onChange={(e) => setClientName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Analyste / Auditeur" : "Analyst / Auditor"}</label>
                  <input type="text" value={analystName} onChange={(e) => setAnalystName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Date</label>
                  <input type="date" value={date} onChange={(e) => setDate(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                </div>
              </div>
            </div>

            {/* PROFIL 1 : COMBINÉ SOC + CTI */}
            {reportType === "SOC_CTI" && (
              <div className="space-y-6 animate-fadeIn">
                {/* PARTIE INCIDENT SOC */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-base font-bold flex items-center gap-2 text-red-400 border-b border-slate-800 pb-3">
                    <Activity className="w-5 h-5" /> {lang === "fr" ? "Volet SOC : Investigation d'Incident" : "SOC Section: Incident Investigation"}
                  </h2>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Titre de l'Incident" : "Incident Title"}</label>
                      <input type="text" value={socTitle} onChange={(e) => setSocTitle(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Sévérité / Severity" : "Severity / Impact"}</label>
                      <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white">
                        <option value="Faible / Low">Faible / Low</option>
                        <option value="Moyenne / Medium">Moyenne / Medium</option>
                        <option value="Élevée / High">Élevée / High</option>
                        <option value="Critique / Critical">Critique / Critical</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Périmètre Impacté" : "Impacted Perimeter"}</label>
                    <input type="text" value={socSystems} onChange={(e) => setSocSystems(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                  </div>

                  <div>
                    <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Analyse du Déroulement" : "Timeline & Incident Analysis"}</label>
                    <textarea rows={3} value={socDescription} onChange={(e) => setSocDescription(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                  </div>

                  <div>
                    <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Cause Racine (Root Cause)" : "Root Cause Analysis"}</label>
                    <textarea rows={2} value={socRootCause} onChange={(e) => setSocRootCause(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                  </div>
                </div>

                {/* PARTIE THREAT INTEL CTI */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-base font-bold flex items-center gap-2 text-cyan-400 border-b border-slate-800 pb-3">
                    <Globe className="w-5 h-5" /> {lang === "fr" ? "Volet CTI : Threat Intelligence & Attribution" : "CTI Section: Threat Intelligence & Attribution"}
                  </h2>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Groupe / Attaquant (Threat Actor)" : "Threat Actor Group"}</label>
                      <input type="text" value={threatActor} onChange={(e) => setThreatActor(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Niveau de Confiance" : "Confidence Level"}</label>
                      <select value={confidenceLevel} onChange={(e) => setConfidenceLevel(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white">
                        <option value="Faible / Low">Faible / Low</option>
                        <option value="Moyenne / Medium">Moyenne / Medium</option>
                        <option value="Élevée / High Confidence">Élevée / High Confidence</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Motivation" : "Motivation"}</label>
                      <input type="text" value={threatMotivation} onChange={(e) => setThreatMotivation(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Sophistication" : "Sophistication"}</label>
                      <input type="text" value={threatSophistication} onChange={(e) => setThreatSophistication(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4 border-t border-slate-800 pt-3">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">MITRE ATT&CK Tactic</label>
                      <select value={mitreTactic} onChange={(e) => setMitreTactic(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white">
                        {MITRE_TACTICS.map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">MITRE ATT&CK Technique</label>
                      <select value={mitreTechnique} onChange={(e) => setMitreTechnique(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white">
                        {selectedTacticObj?.techniques.map((tech) => <option key={tech} value={tech}>{tech}</option>)}
                      </select>
                    </div>
                  </div>
                </div>

                {/* TABLEAU IOCS & PARSEUR LOGS */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                    <h2 className="text-sm font-bold text-red-400 flex items-center gap-2">
                      <List className="w-4 h-4" /> {lang === "fr" ? "Indicateurs de Compromission (IOCs)" : "Indicators of Compromise (IOCs)"}
                    </h2>
                    <button type="button" onClick={handleExportSTIX} className="bg-slate-800 text-xs text-white px-2.5 py-1 rounded border border-slate-700 flex items-center gap-1">
                      <Download className="w-3 h-3 text-cyan-400" /> Export STIX 2.1
                    </button>
                  </div>
                  <div className="space-y-2 bg-slate-950/60 p-3 border border-slate-800 rounded-xl">
                    <textarea rows={2} placeholder={lang === "fr" ? "Collez vos logs bruts..." : "Paste raw logs here..."} value={rawLogsText} onChange={(e) => setRawLogsText(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                    <button type="button" onClick={handleParseLogs} className="w-full bg-yellow-600 text-slate-950 font-bold py-1 text-xs rounded">
                      {lang === "fr" ? "Parser les logs & Extraire les IOCs" : "Parse Logs & Extract IOCs"}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* PROFIL 2 : AUDIT & PENTEST */}
            {reportType === "Pentest" && (
              <div className="space-y-6 animate-fadeIn">
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-base font-bold flex items-center gap-2 text-amber-400 border-b border-slate-800 pb-3">
                    <Bug className="w-5 h-5" /> {lang === "fr" ? "Audit de Sécurité & Test d'Intrusion Détaillé" : "Detailed Pentest & Security Audit"}
                  </h2>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Périmètre Cible" : "Target Scope"}</label>
                      <input type="text" value={pentestTarget} onChange={(e) => setPentestTarget(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Intitulé de la Vulnérabilité" : "Vulnerability Title"}</label>
                      <input type="text" value={vulnName} onChange={(e) => setVulnName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                    </div>
                  </div>

                  {/* CALCULATEUR CVSS V3.1 */}
                  <div className="border border-amber-500/30 bg-amber-950/20 p-4 rounded-xl space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-xs font-bold text-amber-400 flex items-center gap-1">
                        <Calculator className="w-4 h-4" /> CVSS v3.1 Calculator
                      </span>
                      <span className="text-xs font-bold bg-amber-600 text-white px-2 py-0.5 rounded">CVSS Score : {computedCvssScore} / 10</span>
                    </div>

                    <div className="grid grid-cols-3 gap-2 text-xs">
                      <div>
                        <label className="block text-[10px] text-slate-400">Attack Vector (AV)</label>
                        <select value={cvssAV} onChange={(e) => setCvssAV(parseFloat(e.target.value))} className="w-full bg-slate-950 border border-slate-800 rounded p-1 text-white">
                          <option value={0.85}>Network</option>
                          <option value={0.62}>Adjacent</option>
                          <option value={0.55}>Local</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-[10px] text-slate-400">Attack Complexity (AC)</label>
                        <select value={cvssAC} onChange={(e) => setCvssAC(parseFloat(e.target.value))} className="w-full bg-slate-950 border border-slate-800 rounded p-1 text-white">
                          <option value={0.77}>Low</option>
                          <option value={0.44}>High</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-[10px] text-slate-400">Privileges Required (PR)</label>
                        <select value={cvssPR} onChange={(e) => setCvssPR(parseFloat(e.target.value))} className="w-full bg-slate-950 border border-slate-800 rounded p-1 text-white">
                          <option value={0.85}>None</option>
                          <option value={0.62}>Low</option>
                          <option value={0.27}>High</option>
                        </select>
                      </div>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Preuve de Concept (PoC Pas-à-Pas)" : "Proof of Concept (PoC Steps)"}</label>
                    <textarea rows={4} value={pocSteps} onChange={(e) => setPocSteps(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white font-mono" />
                  </div>

                  <div>
                    <label className="block text-xs text-slate-400 mb-1">{lang === "fr" ? "Plan de Remédiation & Hardening" : "Remediation & Hardening Plan"}</label>
                    <textarea rows={3} value={pentestFix} onChange={(e) => setPentestFix(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                  </div>
                </div>
              </div>
            )}

            {/* PROFIL 3 : CONFORMITÉ ISO & PCI DSS */}
            {reportType === "Compliance" && (
              <div className="space-y-6 animate-fadeIn">
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                    <h2 className="text-base font-bold text-emerald-400 flex items-center gap-2">
                      <Award className="w-5 h-5" /> ISO/IEC 27001:2022 Controls
                    </h2>
                    <span className="text-xs font-bold text-emerald-400 bg-emerald-950 border border-emerald-800 px-2.5 py-1 rounded-lg">
                      Maturity : {isoMaturityPercent}%
                    </span>
                  </div>

                  <div className="space-y-2">
                    {ISO_CONTROLS_2022.map((ctrl) => (
                      <label key={ctrl.id} className="flex items-center gap-3 p-2 bg-slate-950 rounded-lg border border-slate-800 cursor-pointer">
                        <input type="checkbox" checked={!!isoChecks[ctrl.id]} onChange={(e) => setIsoChecks({ ...isoChecks, [ctrl.id]: e.target.checked })} className="accent-emerald-500" />
                        <span className="text-xs text-slate-200"><strong className="text-emerald-400">[{ctrl.id}]</strong> {lang === "fr" ? ctrl.label_fr : ctrl.label_en}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                    <h2 className="text-base font-bold text-blue-400 flex items-center gap-2">
                      <FileCheck2 className="w-5 h-5" /> PCI DSS v4.0 Requirements
                    </h2>
                    <span className="text-xs font-bold text-blue-400 bg-blue-950 border border-blue-800 px-2.5 py-1 rounded-lg">
                      Maturity : {pciMaturityPercent}%
                    </span>
                  </div>

                  <div className="space-y-2">
                    {PCI_CONTROLS_V4.map((ctrl) => (
                      <label key={ctrl.id} className="flex items-center gap-3 p-2 bg-slate-950 rounded-lg border border-slate-800 cursor-pointer">
                        <input type="checkbox" checked={!!pciChecks[ctrl.id]} onChange={(e) => setPciChecks({ ...pciChecks, [ctrl.id]: e.target.checked })} className="accent-blue-500" />
                        <span className="text-xs text-slate-200"><strong className="text-blue-400">[{ctrl.id}]</strong> {lang === "fr" ? ctrl.label_fr : ctrl.label_en}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-base font-bold text-amber-400 border-b border-slate-800 pb-2">Gap Analysis & Action Plan</h2>
                  <textarea rows={3} value={gapSummary} onChange={(e) => setGapSummary(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
                  <textarea rows={4} value={gapActionPlan} onChange={(e) => setGapActionPlan(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white font-mono" />
                </div>
              </div>
            )}
          </div>

          {/* COLONNE DROITE : APERÇU PDF ADAPTÉ & DÉDIÉ (SPAN 5) */}
          <div className="lg:col-span-5 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-2xl flex flex-col items-center h-fit sticky top-24">
            <span className="text-xs font-semibold text-slate-400 mb-3 no-print flex items-center gap-2">
              <Cpu className="w-4 h-4 text-blue-400" /> {lang === "fr" ? "Aperçu du Document PDF Officiel" : "Official PDF Document Rendering"}
            </span>

            {/* DOCUMENT IMPRIMABLE CANONIQUE */}
            <div id="pdf-report" className="w-full bg-white text-slate-900 p-8 rounded-xl shadow-2xl border border-slate-200 text-sm space-y-5">
              
              {/* HEADER PDF */}
              <div className="flex justify-between items-start border-b-2 border-slate-900 pb-4">
                <div>
                  <h1 className="text-sm font-bold uppercase tracking-wide text-slate-900">
                    {reportType === "SOC_CTI" ? (lang === "fr" ? "Rapport d'Incident SOC & Intelligence Menaces" : "SOC Incident & Threat Intel Report") :
                     reportType === "Pentest" ? (lang === "fr" ? "Rapport d'Audit de Sécurité & Pentest" : "Penetration Testing Audit Report") :
                     (lang === "fr" ? "Rapport de Conformité ISO 27001 & PCI DSS" : "ISO 27001 & PCI DSS Compliance Report")}
                  </h1>
                  <p className="text-[10px] text-slate-500">ReportShield Cyber Security Deliverable</p>
                </div>
                <div className="text-right text-[10px] text-slate-600">
                  <p><strong>Client :</strong> {clientName}</p>
                  <p><strong>Analyst :</strong> {analystName}</p>
                  <p><strong>Date :</strong> {date}</p>
                </div>
              </div>

              {/* CONTENU PDF PROFIL 1 : SOC + CTI COMBINÉ */}
              {reportType === "SOC_CTI" && (
                <div className="space-y-4">
                  <div className="bg-red-50 border border-red-200 p-3 rounded-lg flex justify-between items-center">
                    <div>
                      <span className="text-[10px] text-red-600 font-bold uppercase block">{lang === "fr" ? "Incident & Menace" : "Incident & Threat"}</span>
                      <h2 className="text-xs font-bold text-red-950">{socTitle}</h2>
                    </div>
                    <span className="bg-red-600 text-white font-bold text-[10px] px-2 py-0.5 rounded">{severity}</span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] bg-cyan-50 border border-cyan-200 p-2 rounded">
                    <div><strong>Threat Actor :</strong> {threatActor}</div>
                    <div><strong>Confidence :</strong> {confidenceLevel}</div>
                    <div><strong>Motivation :</strong> {threatMotivation}</div>
                    <div><strong>Sophistication :</strong> {threatSophistication}</div>
                  </div>

                  <div>
                    <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">{lang === "fr" ? "Analyse Chronologique SOC" : "SOC Timeline Analysis"}</h3>
                    <p className="text-xs text-slate-800 whitespace-pre-line">{socDescription}</p>
                  </div>

                  <div>
                    <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">MITRE ATT&CK Mapping</h3>
                    <p className="text-xs text-purple-900 font-semibold bg-purple-50 p-2 rounded border border-purple-200">{mitreTactic} / {mitreTechnique}</p>
                  </div>

                  {iocs.length > 0 && (
                    <div>
                      <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">Indicators of Compromise (IOCs)</h3>
                      <div className="border rounded overflow-hidden text-xs">
                        {iocs.map((ioc, idx) => (
                          <div key={idx} className="p-1.5 border-b last:border-0 flex justify-between font-mono">
                            <span className="font-bold text-red-600">[{ioc.type}]</span>
                            <span>{ioc.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* CONTENU PDF PROFIL 2 : AUDIT / PENTEST */}
              {reportType === "Pentest" && (
                <div className="space-y-4">
                  <div className="bg-amber-50 border border-amber-200 p-3 rounded-lg flex justify-between items-center">
                    <div>
                      <span className="text-[10px] text-amber-700 font-bold uppercase block">{lang === "fr" ? "Vulnérabilité Auditée" : "Audited Vulnerability"}</span>
                      <h2 className="text-xs font-bold text-amber-950">{vulnName}</h2>
                    </div>
                    <span className="bg-amber-600 text-white font-bold text-[10px] px-2 py-0.5 rounded">CVSS v3.1 : {computedCvssScore}</span>
                  </div>

                  <div>
                    <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">{lang === "fr" ? "Périmètre Cible" : "Target Scope"}</h3>
                    <p className="text-xs text-slate-800 bg-slate-100 p-2 rounded">{pentestTarget}</p>
                  </div>

                  <div>
                    <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">{lang === "fr" ? "Preuve de Concept (PoC)" : "Proof of Concept (PoC)"}</h3>
                    <p className="text-xs text-slate-900 font-mono bg-slate-100 p-2.5 rounded whitespace-pre-line border border-slate-200">{pocSteps}</p>
                  </div>

                  <div>
                    <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">{lang === "fr" ? "Plan de Remédiation & Hardening" : "Remediation & Hardening Plan"}</h3>
                    <p className="text-xs text-green-900 bg-green-50 p-2.5 rounded font-mono border border-green-200">{pentestFix}</p>
                  </div>
                </div>
              )}

              {/* CONTENU PDF PROFIL 3 : CONFORMITÉ */}
              {reportType === "Compliance" && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-2 text-xs border p-2.5 rounded bg-slate-50">
                    <div><strong>Maturité ISO 27001:2022 :</strong> {isoMaturityPercent}%</div>
                    <div><strong>Maturité PCI DSS v4.0 :</strong> {pciMaturityPercent}%</div>
                  </div>

                  <div>
                    <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">Gap Analysis Summary</h3>
                    <p className="text-xs text-slate-800 bg-amber-50 p-2.5 rounded border border-amber-200">{gapSummary}</p>
                  </div>

                  <div>
                    <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">Remediation Roadmap</h3>
                    <p className="text-xs text-slate-800 font-mono bg-slate-100 p-2.5 rounded whitespace-pre-line border border-slate-200">{gapActionPlan}</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </>
  );
}