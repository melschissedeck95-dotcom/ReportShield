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
  BookOpen,
  Target,
  FileSpreadsheet,
  Share2,
  Send,
  UserCog,
  Settings
} from "lucide-react";
import { supabase } from "@/lib/supabase";

interface IOCItem {
  id: string;
  type: string;
  value: string;
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
  cvss_score?: number;
  report_type?: string;
  iso_scores?: Record<string, number>;
  pci_scores?: Record<string, number>;
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

const ISO_DOMAINS_2022 = [
  { id: "ISO_C4_Context", label: "Clause 4 : Contexte de l'organisation & enjeux" },
  { id: "ISO_C5_Leadership", label: "Clause 5 : Leadership & Engagement de la Direction" },
  { id: "ISO_C6_Planning", label: "Clause 6 : Planification (Gestion des risques & objectifs)" },
  { id: "ISO_C7_Support", label: "Clause 7 : Support (Ressources, compétences, sensibilisation)" },
  { id: "ISO_C8_Operation", label: "Clause 8 : Fonctionnement (Maîtrise opérationnelle & traitements)" },
  { id: "ISO_C9_Performance", label: "Clause 9 : Évaluation des performances (Audits internes, revues)" },
  { id: "ISO_C10_Improvement", label: "Clause 10 : Amélioration continue & actions correctives" },
  { id: "ISO_A5_Org", label: "Annexe A.5 : Mesures Organisationnelles (Gouvernance, politiques)" },
  { id: "ISO_A6_People", label: "Annexe A.6 : Mesures relatives aux Personnes (RH, sensibilisation)" },
  { id: "ISO_A7_Physical", label: "Annexe A.7 : Sécurité Physique & Environnementale" },
  { id: "ISO_A8_Tech", label: "Annexe A.8 : Mesures Techniques (Chiffrement, SIEM, vulnérabilités)" },
];

const PCI_REQUIREMENTS_V4 = [
  { id: "PCI_Req1", label: "Req 1 : Installation et maintenance des contrôles réseau" },
  { id: "PCI_Req2", label: "Req 2 : Configurations sécurisées des systèmes et équipements" },
  { id: "PCI_Req3", label: "Req 3 : Protection des données des porteurs de cartes stockées (PAN/SAD)" },
  { id: "PCI_Req4", label: "Req 4 : Chiffrement fort des PAN lors des transmissions sur réseaux ouverts" },
  { id: "PCI_Req5", label: "Req 5 : Protection de tous les systèmes contre les malwares" },
  { id: "PCI_Req6", label: "Req 6 : Développement et maintenance de logiciels et systèmes sécurisés" },
  { id: "PCI_Req7", label: "Req 7 : Restriction d'accès aux données de cartes selon le besoin d'en connaître" },
  { id: "PCI_Req8", label: "Req 8 : Identification et authentification robustes (MFA obligatoire)" },
  { id: "PCI_Req9", label: "Req 9 : Restriction de l'accès physique aux données de cartes" },
  { id: "PCI_Req10", label: "Req 10 : Suivi et journalisation de tous les accès (SIEM & Logs)" },
  { id: "PCI_Req11", label: "Req 11 : Tests réguliers de sécurité (Scans ASV & Tests d'intrusion)" },
  { id: "PCI_Req12", label: "Req 12 : Politiques de sécurité et gestion globale des risques" },
];

export default function Home() {
  const [user, setUser] = useState<any>(null);
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [savedReports, setSavedReports] = useState<ReportItem[]>([]);

  // Modal de configuration du compte
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [fullName, setFullName] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [jobTitle, setJobTitle] = useState("Junior SOC Analyst / QSA Assistant");

  const [lang, setLang] = useState<"fr" | "en">("fr");
  const [reportType, setReportType] = useState<"SOC_CTI" | "Pentest" | "Compliance">("Pentest");

  // Métadonnées du rapport
  const [clientName, setClientName] = useState("Entreprise Client SA");
  const [analystName, setAnalystName] = useState("Analyste Cyber / RSSI");
  const [date, setDate] = useState(new Date().toISOString().split("T")[0]);
  const [tlpMarking, setTlpMarking] = useState("TLP:AMBER");
  const [reportVersion, setReportVersion] = useState("v1.0 (Rapport Final)");

  // --- ÉTATS PROFIL 1 : SOC + CTI ---
  const [socTitle, setSocTitle] = useState("Infiltration par Force Brute VPN & Exfiltration");
  const [socSystems, setSocSystems] = useState("Active Directory, Passerelle VPN, BDD Clients");
  const [socDescription, setSocDescription] = useState("Détection d'une authentification anormale suivie d'un mouvement latéral.");
  const [socRootCause, setSocRootCause] = useState("Absence d'authentification multifacteur (MFA).");
  const [socRecommendations, setSocRecommendations] = useState(
    "1. CONFINEMENT IMMÉDIAT (H+0 à H+2) : Isolation des hôtes compromis et révocation des sessions.\n" +
    "2. ÉRADICATION (J+1 à J+3) : Réinitialisation forcée des mots de passe et déploiement du MFA.\n" +
    "3. HARDENING & CTI (J+7 à J+30) : Blocage des IOCs et intégration des flux STIX/TAXII."
  );
  const [threatActor, setThreatActor] = useState("LockBit 3.0 / APT29");
  const [threatMotivation, setThreatMotivation] = useState("Gain Financier / Extorsion");
  const [threatSophistication, setThreatSophistication] = useState("Élevée");
  const [confidenceLevel, setConfidenceLevel] = useState("Élevée (High Confidence)");
  const [rawLogsText, setRawLogsText] = useState("");
  const [iocs, setIocs] = useState<IOCItem[]>([
    { id: "1", type: "IP Address", value: "192.168.1.105", description: "IP C2 Attaquant" }
  ]);

  // --- ÉTATS PROFIL 2 : AUDIT & PENTEST (8 ÉTAPES) ---
  const [execSummary, setExecSummary] = useState("L'audit a mis en évidence un niveau de risque global ÉLEVÉ avec compromission possible de l'application.");
  const [overallRiskRating, setOverallRiskRating] = useState("Élevé / High Risk");
  const [inScopeTarget, setInScopeTarget] = useState("https://api.client.com (Portail & API V1)");
  const [outScopeTarget, setOutScopeTarget] = useState("ERP de Production Interne");
  const [methodology, setMethodology] = useState("OWASP Top 10, PTES, NIST SP 800-115");
  const [cvssAV, setCvssAV] = useState<number>(0.85);
  const [cvssAC, setCvssAC] = useState<number>(0.77);
  const [cvssPR, setCvssPR] = useState<number>(0.85);
  const [cvssUI, setCvssUI] = useState<number>(0.85);
  const [cvssImpactC, setCvssImpactC] = useState<number>(0.56);
  const [cvssImpactI, setCvssImpactI] = useState<number>(0.56);
  const [cvssImpactA, setCvssImpactA] = useState<number>(0.56);
  const [vulnTitle, setVulnTitle] = useState("SQL Injection & BOLA");
  const [owaspCategory, setOwaspCategory] = useState("OWASP A03:2021 - Injection");
  const [pocSteps, setPocSteps] = useState("1. Interception de la requête HTTP via Burp Suite.\n2. Injection du payload SQL et extraction des données.");
  const [attackPathDescription, setAttackPathDescription] = useState("Exploitation de la vulnérabilité SQLi pour remonter aux privilèges administrateur.");
  const [mitreTactic, setMitreTactic] = useState("Credential Access");
  const [mitreTechnique, setMitreTechnique] = useState("T1110 - Brute Force");
  const [p1Actions, setP1Actions] = useState("P1 [Immédiat] : Utilisation de requêtes préparées.");
  const [p2Actions, setP2Actions] = useState("P2 [Sous 15j] : Mise en place d'un contrôle RBAC.");
  const [p3Actions, setP3Actions] = useState("P3 [Sous 30j] : Déploiement d'un WAF.");
  const [toolsUsed, setToolsUsed] = useState("Burp Suite Professional, Nmap, SQLmap");
  const [certificateText, setCertificateText] = useState("Attestation officielle de réalisation d'un test d'intrusion technique.");

  // --- ÉTATS PROFIL 3 : CONFORMITÉ & MATURITÉ ---
  const [isoMaturityScores, setIsoMaturityScores] = useState<Record<string, number>>(
    Object.fromEntries(ISO_DOMAINS_2022.map(d => [d.id, 2]))
  );
  const [pciMaturityScores, setPciMaturityScores] = useState<Record<string, number>>(
    Object.fromEntries(PCI_REQUIREMENTS_V4.map(r => [r.id, 2]))
  );
  const [gapSummary, setGapSummary] = useState("Alignement partiel sur ISO 27001:2022 et PCI DSS v4.0 (Maturité globale Niveau 2/5).");
  const [gapActionPlan, setGapActionPlan] = useState("1. Formalisation des politiques de sécurité sous 30 jours.\n2. Déploiement du SIEM et journalisation sur 12 mois.");

  useEffect(() => {
    const initAuth = async () => {
      const { data } = await supabase.auth.getUser();
      setUser(data.user);
      if (data.user) {
        fetchReports();
        fetchUserProfile(data.user.id);
      }
    };
    initAuth();
    const { data: authListener } = supabase.auth.onAuthStateChange((_, session) => {
      setUser(session?.user ?? null);
      if (session?.user) {
        fetchReports();
        fetchUserProfile(session.user.id);
      }
    });
    return () => authListener.subscription.unsubscribe();
  }, []);

  const fetchUserProfile = async (userId: string) => {
    const { data } = await supabase.from("profiles").select("*").eq("id", userId).single();
    if (data) {
      if (data.full_name) setFullName(data.full_name);
      if (data.company_name) setCompanyName(data.company_name);
      if (data.job_title) {
        setJobTitle(data.job_title);
        setAnalystName(`${data.full_name || user?.email} (${data.job_title})`);
      }
    }
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    setLoading(true);
    const { error } = await supabase.from("profiles").upsert({
      id: user.id,
      full_name: fullName,
      company_name: companyName,
      job_title: jobTitle,
      updated_at: new Date().toISOString()
    });

    if (error) alert(`Erreur de configuration: ${error.message}`);
    else {
      alert("Profil configuré avec succès !");
      setAnalystName(`${fullName} (${jobTitle})`);
      setShowConfigModal(false);
    }
    setLoading(false);
  };

  const fetchReports = async () => {
    const { data } = await supabase.from("reports").select("*").order("created_at", { ascending: false });
    if (data) setSavedReports(data as ReportItem[]);
  };

  const calculateCVSSScore = (): number => {
    const iss = 1 - (1 - cvssImpactC) * (1 - cvssImpactI) * (1 - cvssImpactA);
    const impact = 6.42 * iss;
    const exploitability = 8.22 * cvssAV * cvssAC * cvssPR * cvssUI;
    if (impact <= 0) return 0;
    return Math.min(10, Math.ceil((impact + exploitability) * 10) / 10);
  };
  const computedCvssScore = calculateCVSSScore();

  const avgIsoScore = Math.round((Object.values(isoMaturityScores).reduce((a, b) => a + b, 0) / (ISO_DOMAINS_2022.length * 5)) * 100);
  const avgPciScore = Math.round((Object.values(pciMaturityScores).reduce((a, b) => a + b, 0) / (PCI_REQUIREMENTS_V4.length * 5)) * 100);

  const handleParseLogs = () => {
    if (!rawLogsText) return;
    const extracted: IOCItem[] = [];
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const ips = Array.from(new Set(rawLogsText.match(ipRegex) || []));
    ips.forEach(ip => {
      if (ip !== "127.0.0.1") extracted.push({ id: Math.random().toString(), type: "IP Address", value: ip, description: "Extrait des logs" });
    });
    if (extracted.length > 0) {
      setIocs([...iocs, ...extracted]);
      setRawLogsText("");
      alert(`${extracted.length} IOC(s) extrait(s) !`);
    } else alert("Aucun IOC trouvé.");
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
    if (!user) { alert("Veuillez vous connecter ou créer un compte !"); return; }
    setLoading(true);
    const { error } = await supabase.from("reports").insert([{
      user_id: user.id,
      client_name: clientName,
      analyst_name: analystName,
      incident_date: date,
      title: reportType === "Pentest" ? vulnTitle : reportType === "SOC_CTI" ? socTitle : "ISO 27001 & PCI DSS Maturity Assessment",
      severity: reportType === "Pentest" ? overallRiskRating : "Élevée",
      systems: reportType === "Pentest" ? inScopeTarget : socSystems,
      description: reportType === "Pentest" ? execSummary : socDescription,
      root_cause: reportType === "Pentest" ? attackPathDescription : socRootCause,
      recommendations: reportType === "Pentest" ? `${p1Actions}\n${p2Actions}\n${p3Actions}` : socRecommendations,
      mitre_tactic: mitreTactic,
      mitre_technique: mitreTechnique,
      iocs: iocs,
      cvss_score: computedCvssScore,
      report_type: reportType,
      iso_scores: isoMaturityScores,
      pci_scores: pciMaturityScores,
      gap_analysis_summary: gapSummary,
      gap_action_plan: gapActionPlan,
      poc_steps: pocSteps
    }]);

    if (error) alert(`Erreur: ${error.message}`);
    else { alert("Rapport sauvegardé avec succès !"); fetchReports(); }
    setLoading(false);
  };

  const shareTitle = encodeURIComponent(`Rapport d'Expertise Cyber - ReportShield Pro (${clientName})`);
  const shareUrl = encodeURIComponent(typeof window !== "undefined" ? window.location.href : "https://reportshield.vercel.app");
  
  const shareLinks = {
    linkedin: `https://www.linkedin.com/sharing/share-offsite/?url=${shareUrl}`,
    twitter: `https://twitter.com/intent/tweet?text=${shareTitle}&url=${shareUrl}`,
    whatsapp: `https://api.whatsapp.com/send?text=${shareTitle}%20-%20${shareUrl}`,
    telegram: `https://t.me/share/url?url=${shareUrl}&text=${shareTitle}`
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
        
        {/* EN-TÊTE FIXE */}
        <header className="bg-slate-900/90 border-b border-slate-800 px-8 py-4 flex flex-col md:flex-row items-center justify-between gap-4 sticky top-0 z-50 no-print">
          <div className="flex items-center gap-3">
            <Shield className="w-7 h-7 text-blue-500" />
            <div>
              <h1 className="text-xl font-bold text-white">ReportShield Pro</h1>
              <p className="text-xs text-slate-400">Plateforme Multi-Profils SOC/CTI, Pentest & Conformité</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button onClick={() => setLang(lang === "fr" ? "en" : "fr")} className="bg-slate-800 text-amber-400 px-3 py-1.5 rounded-lg border border-slate-700 text-xs font-bold flex items-center gap-1.5 cursor-pointer">
              <Languages className="w-4 h-4" /> {lang === "fr" ? "English 🇬🇧" : "Français 🇫🇷"}
            </button>

            {user ? (
              <div className="flex items-center gap-2">
                <button onClick={() => setShowConfigModal(true)} className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg border border-slate-700 text-xs flex items-center gap-1.5 cursor-pointer">
                  <UserCog className="w-4 h-4 text-blue-400" /> {fullName || user.email}
                </button>
                <button onClick={async () => { await supabase.auth.signOut(); setUser(null); }} className="bg-red-600/20 text-red-400 p-1.5 rounded-lg border border-red-500/30 hover:bg-red-600/30 cursor-pointer" title="Déconnexion">
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <form onSubmit={async (e) => {
                e.preventDefault();
                const { error } = await supabase.auth.signInWithOtp({ email });
                if (error) alert(error.message);
                else setMessage("Lien de connexion / création envoyé par email !");
              }} className="flex gap-2">
                <input type="email" placeholder="votre@email.com" value={email} onChange={(e) => setEmail(e.target.value)} className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs text-white" />
                <button type="submit" className="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1 rounded text-xs cursor-pointer">S'inscrire / Connexion</button>
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

        {message && <div className="bg-emerald-950 border border-emerald-800 text-emerald-200 text-xs px-8 py-2 text-center no-print">{message}</div>}

        {/* MODAL DE CONFIGURATION DU COMPTE */}
        {showConfigModal && (
          <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 no-print">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 w-full max-w-md shadow-2xl space-y-4">
              <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Settings className="w-4 h-4 text-blue-400" /> Configuration du Compte & Analyste
                </h3>
                <button onClick={() => setShowConfigModal(false)} className="text-slate-400 hover:text-white text-xs">✕ Fermer</button>
              </div>

              <form onSubmit={handleSaveProfile} className="space-y-4 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">Nom Complet (Prénom Nom)</label>
                  <input type="text" value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="ex: Kossonou Fieny" className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Entreprise / Organisation</label>
                  <input type="text" value={companyName} onChange={(e) => setCompanyName(e.target.value)} placeholder="ex: Colombe Cyber Defense (CCDOC)" className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Intitulé de Poste / Rôle</label>
                  <input type="text" value={jobTitle} onChange={(e) => setJobTitle(e.target.value)} placeholder="ex: Junior SOC Analyst / QSA Assistant" className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <button type="submit" disabled={loading} className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 rounded-lg cursor-pointer">
                  Enregistrer les paramètres
                </button>
              </form>
            </div>
          </div>
        )}

        {/* SÉLECTION DES 3 PROFILS */}
        <div className="bg-slate-900/50 border-b border-slate-800 px-8 py-3 flex items-center justify-between no-print">
          <span className="text-xs font-semibold text-slate-400">Sélectionnez le Profil Métier :</span>
          <div className="flex gap-2">
            {[
              { id: "SOC_CTI", label: "🚨 1. SOC INCIDENT & THREAT INTEL", color: "bg-red-600/20 text-red-400 border-red-500/40" },
              { id: "Pentest", label: "🛡️ 2. AUDIT & PENTEST (8 ÉTAPES)", color: "bg-amber-600/20 text-amber-400 border-amber-500/40" },
              { id: "Compliance", label: "📊 3. MATURITÉ ISO & PCI DSS", color: "bg-emerald-600/20 text-emerald-400 border-emerald-500/40" }
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
          
          {/* FORMULAIRES (SPAN 7) */}
          <div className="lg:col-span-7 space-y-6 no-print">

            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider border-b border-slate-800 pb-2">Informations Générales du Client</h2>
              <div className="grid grid-cols-3 gap-3 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">Organisation Client</label>
                  <input type="text" value={clientName} onChange={(e) => setClientName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Analyste / Signataire</label>
                  <input type="text" value={analystName} onChange={(e) => setAnalystName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Date</label>
                  <input type="date" value={date} onChange={(e) => setDate(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
              </div>
            </div>

            {/* ================= PROFIL 1 : SOC + CTI ================= */}
            {reportType === "SOC_CTI" && (
              <div className="space-y-6 animate-fadeIn">
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-base font-bold flex items-center gap-2 text-red-400 border-b border-slate-800 pb-3">
                    <Activity className="w-5 h-5" /> Volet 1 : Investigation d'Incident SOC
                  </h2>
                  <div className="grid grid-cols-2 gap-4 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Titre de l'Incident</label>
                      <input type="text" value={socTitle} onChange={(e) => setSocTitle(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Périmètre / Systèmes</label>
                      <input type="text" value={socSystems} onChange={(e) => setSocSystems(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Analyse Chronologique</label>
                    <textarea rows={3} value={socDescription} onChange={(e) => setSocDescription(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Cause Racine (Root Cause)</label>
                    <textarea rows={2} value={socRootCause} onChange={(e) => setSocRootCause(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-base font-bold flex items-center gap-2 text-cyan-400 border-b border-slate-800 pb-3">
                    <Globe className="w-5 h-5" /> Volet 2 : Threat Intelligence & CTI
                  </h2>
                  <div className="grid grid-cols-2 gap-4 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Threat Actor</label>
                      <input type="text" value={threatActor} onChange={(e) => setThreatActor(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Niveau de Confiance</label>
                      <input type="text" value={confidenceLevel} onChange={(e) => setConfidenceLevel(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Motivation</label>
                      <input type="text" value={threatMotivation} onChange={(e) => setThreatMotivation(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Sophistication</label>
                      <input type="text" value={threatSophistication} onChange={(e) => setThreatSophistication(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4 pt-2 border-t border-slate-800 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Tactique MITRE ATT&CK</label>
                      <select value={mitreTactic} onChange={(e) => setMitreTactic(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white">
                        {MITRE_TACTICS.map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Technique Associée</label>
                      <select value={mitreTechnique} onChange={(e) => setMitreTechnique(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white">
                        {selectedTacticObj?.techniques.map((tech) => <option key={tech} value={tech}>{tech}</option>)}
                      </select>
                    </div>
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                    <h2 className="text-sm font-bold text-red-400 flex items-center gap-2">
                      <List className="w-4 h-4" /> Indicateurs de Compromission (IOCs) & STIX 2.1
                    </h2>
                    <button type="button" onClick={handleExportSTIX} className="bg-slate-800 text-xs text-white px-2.5 py-1 rounded border border-slate-700 flex items-center gap-1 cursor-pointer">
                      <Download className="w-3 h-3 text-cyan-400" /> Export STIX 2.1
                    </button>
                  </div>
                  <textarea rows={2} placeholder="Collez vos logs bruts ici..." value={rawLogsText} onChange={(e) => setRawLogsText(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
                  <button type="button" onClick={handleParseLogs} className="w-full bg-yellow-600 text-slate-950 font-bold py-1.5 text-xs rounded cursor-pointer">Parser les logs & Extraire les IOCs</button>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-base font-bold flex items-center gap-2 text-emerald-400 border-b border-slate-800 pb-3">
                    <FileCheck2 className="w-5 h-5" /> Volet 3 : Plan de Remédiation & Hardening (SOC/CTI)
                  </h2>
                  <textarea rows={5} value={socRecommendations} onChange={(e) => setSocRecommendations(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white font-mono leading-relaxed" />
                </div>
              </div>
            )}

            {/* ================= PROFIL 2 : PENTEST (8 ÉTAPES) ================= */}
            {reportType === "Pentest" && (
              <div className="space-y-6 animate-fadeIn">
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                    <BookOpen className="w-4 h-4" /> Étape 1 & 2 : Synthèse Exécutive & Métadonnées
                  </h2>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Niveau de Risque Global</label>
                      <select value={overallRiskRating} onChange={(e) => setOverallRiskRating(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white">
                        <option value="Critique / Critical">Critique / Critical</option>
                        <option value="Élevé / High Risk">Élevé / High Risk</option>
                        <option value="Moyen / Medium Risk">Moyen / Medium Risk</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Résumé Décisionnel</label>
                      <textarea rows={2} value={execSummary} onChange={(e) => setExecSummary(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                    <Target className="w-4 h-4" /> Étape 3 : Périmètre & Règles d'Engagement
                  </h2>
                  <div className="space-y-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Cibles Autorisées (In-Scope)</label>
                      <input type="text" value={inScopeTarget} onChange={(e) => setInScopeTarget(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Éléments Exclus (Out-of-Scope)</label>
                      <input type="text" value={outScopeTarget} onChange={(e) => setOutScopeTarget(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                    <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                      <Calculator className="w-4 h-4" /> Étape 4 : Matrice CVSS v3.1
                    </h2>
                    <span className="text-xs font-bold bg-amber-600 text-white px-2.5 py-1 rounded">Score : {computedCvssScore} / 10</span>
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                    <Bug className="w-4 h-4" /> Étape 5 & 6 : Fiche Technique, PoC & MITRE
                  </h2>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Titre Vulnérabilité</label>
                      <input type="text" value={vulnTitle} onChange={(e) => setVulnTitle(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Catégorie OWASP</label>
                      <input type="text" value={owaspCategory} onChange={(e) => setOwaspCategory(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Preuve de Concept (PoC Pas-à-Pas)</label>
                    <textarea rows={3} value={pocSteps} onChange={(e) => setPocSteps(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white font-mono" />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Scénario d'Attaque (Attack Path)</label>
                    <textarea rows={2} value={attackPathDescription} onChange={(e) => setAttackPathDescription(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-sm font-bold text-amber-400 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-2">
                    <FileSpreadsheet className="w-4 h-4" /> Étape 7 & 8 : Remédiation & Certificat
                  </h2>
                  <div className="space-y-2 text-xs">
                    <input type="text" value={p1Actions} onChange={(e) => setP1Actions(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono" />
                    <input type="text" value={p2Actions} onChange={(e) => setP2Actions(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono" />
                    <input type="text" value={p3Actions} onChange={(e) => setP3Actions(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono" />
                  </div>
                </div>
              </div>
            )}

            {/* ================= PROFIL 3 : CONFORMITÉ & MATURITÉ ================= */}
            {reportType === "Compliance" && (
              <div className="space-y-6 animate-fadeIn">
                <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 text-xs space-y-2">
                  <span className="font-bold text-slate-300 block">Échelle de Maturité CMMI (1 à 5) :</span>
                  <div className="grid grid-cols-5 gap-2 text-[10px] text-center">
                    <div className="bg-red-950/60 border border-red-800 p-1.5 rounded"><strong className="block text-red-400">1 - Initial</strong></div>
                    <div className="bg-orange-950/60 border border-orange-800 p-1.5 rounded"><strong className="block text-orange-400">2 - Géré</strong></div>
                    <div className="bg-yellow-950/60 border border-yellow-800 p-1.5 rounded"><strong className="block text-yellow-400">3 - Défini</strong></div>
                    <div className="bg-blue-950/60 border border-blue-800 p-1.5 rounded"><strong className="block text-blue-400">4 - Mesuré</strong></div>
                    <div className="bg-emerald-950/60 border border-emerald-800 p-1.5 rounded"><strong className="block text-emerald-400">5 - Optimisé</strong></div>
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                    <h2 className="text-base font-bold text-emerald-400 flex items-center gap-2">
                      <Award className="w-5 h-5" /> SMSI — ISO/IEC 27001:2022
                    </h2>
                    <span className="text-xs font-bold text-emerald-400 bg-emerald-950 border border-emerald-800 px-2.5 py-1 rounded">
                      Maturité : {avgIsoScore}%
                    </span>
                  </div>
                  <div className="space-y-3">
                    {ISO_DOMAINS_2022.map((domain) => (
                      <div key={domain.id} className="bg-slate-950 p-3 rounded-xl border border-slate-800 flex justify-between items-center text-xs">
                        <span className="text-slate-200 font-medium">{domain.label}</span>
                        <select
                          value={isoMaturityScores[domain.id] || 2}
                          onChange={(e) => setIsoMaturityScores({ ...isoMaturityScores, [domain.id]: parseInt(e.target.value) })}
                          className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-white text-xs font-bold"
                        >
                          <option value={1}>1 - Initial</option>
                          <option value={2}>2 - Géré</option>
                          <option value={3}>3 - Défini</option>
                          <option value={4}>4 - Mesuré</option>
                          <option value={5}>5 - Optimisé</option>
                        </select>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                    <h2 className="text-base font-bold text-blue-400 flex items-center gap-2">
                      <FileCheck2 className="w-5 h-5" /> PCI DSS v4.0 (12 Exigences)
                    </h2>
                    <span className="text-xs font-bold text-blue-400 bg-blue-950 border border-blue-800 px-2.5 py-1 rounded">
                      Maturité : {avgPciScore}%
                    </span>
                  </div>
                  <div className="space-y-3">
                    {PCI_REQUIREMENTS_V4.map((req) => (
                      <div key={req.id} className="bg-slate-950 p-3 rounded-xl border border-slate-800 flex justify-between items-center text-xs">
                        <span className="text-slate-200 font-medium">{req.label}</span>
                        <select
                          value={pciMaturityScores[req.id] || 2}
                          onChange={(e) => setPciMaturityScores({ ...pciMaturityScores, [req.id]: parseInt(e.target.value) })}
                          className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-white text-xs font-bold"
                        >
                          <option value={1}>1 - Initial</option>
                          <option value={2}>2 - Géré</option>
                          <option value={3}>3 - Défini</option>
                          <option value={4}>4 - Mesuré</option>
                          <option value={5}>5 - Optimisé</option>
                        </select>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-sm font-bold text-amber-400 border-b border-slate-800 pb-2">Gap Analysis & Feuille de Route</h2>
                  <textarea rows={3} value={gapSummary} onChange={(e) => setGapSummary(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
                  <textarea rows={4} value={gapActionPlan} onChange={(e) => setGapActionPlan(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white font-mono" />
                </div>
              </div>
            )}
          </div>

          {/* APERÇU PDF & LIENS DE PARTAGE (SPAN 5) */}
          <div className="lg:col-span-5 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-2xl flex flex-col items-center h-fit sticky top-24 space-y-4">
            
            <div className="w-full flex items-center justify-between no-print">
              <span className="text-xs font-semibold text-slate-400 flex items-center gap-2">
                <Cpu className="w-4 h-4 text-blue-400" /> Rendu PDF : [{reportType}]
              </span>
              
              {/* BARRE DE PARTAGE RAPIDE */}
              <div className="flex items-center gap-1.5 bg-slate-950 p-1.5 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-400 px-1 font-semibold flex items-center gap-1"><Share2 className="w-3 h-3" /> Partager :</span>
                <a href={shareLinks.linkedin} target="_blank" rel="noopener noreferrer" title="Partager sur LinkedIn" className="p-1.5 bg-blue-900/40 text-blue-400 hover:bg-blue-900 rounded transition">
                  <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24"><path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.88 8.56a1.68 1.68 0 0 0 1.68-1.68c0-.93-.75-1.69-1.68-1.69a1.69 1.69 0 0 0-1.69 1.69c0 .93.76 1.68 1.69 1.68m1.39 9.94v-8.37H5.5v8.37h2.77z"/></svg>
                </a>
                <a href={shareLinks.twitter} target="_blank" rel="noopener noreferrer" title="Partager sur X (Twitter)" className="p-1.5 bg-slate-800 text-slate-200 hover:bg-slate-700 rounded transition">
                  <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
                </a>
                <a href={shareLinks.whatsapp} target="_blank" rel="noopener noreferrer" title="Partager sur WhatsApp" className="p-1.5 bg-emerald-950 text-emerald-400 hover:bg-emerald-900 rounded transition">
                  <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24"><path d="M.057 24l1.687-6.163c-1.041-1.804-1.588-3.849-1.587-5.946.003-6.556 5.338-11.891 11.893-11.891 3.181.001 6.167 1.24 8.413 3.488 2.245 2.248 3.481 5.236 3.48 8.414-.003 6.557-5.338 11.892-11.893 11.892-1.99-.001-3.951-.5-5.688-1.448l-6.305 1.654zm6.597-3.807c1.676.995 3.276 1.591 5.392 1.592 5.448 0 9.886-4.434 9.889-9.885.002-5.462-4.415-9.89-9.881-9.892-5.452 0-9.887 4.434-9.889 9.884-.001 2.225.651 3.891 1.746 5.634l-.999 3.648 3.742-.981zm11.387-5.464c-.074-.124-.272-.198-.57-.347-.297-.149-1.758-.868-2.031-.967-.272-.099-.47-.149-.669.149-.198.297-.768.967-.941 1.165-.173.198-.347.223-.644.074-.297-.149-1.255-.462-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.297-.347.446-.521.151-.172.2-.296.3-.495.099-.198.05-.372-.025-.521-.075-.148-.669-1.611-.916-2.206-.242-.579-.487-.501-.669-.51l-.57-.01c-.198 0-.52.074-.792.372s-1.04 1.016-1.04 2.479 1.065 2.876 1.213 3.074c.149.198 2.095 3.2 5.076 4.487.709.306 1.263.489 1.694.626.712.226 1.36.194 1.872.118.571-.085 1.758-.719 2.006-1.413.248-.695.248-1.29.173-1.414z"/></svg>
                </a>
                <a href={shareLinks.telegram} target="_blank" rel="noopener noreferrer" title="Partager sur Telegram" className="p-1.5 bg-sky-950 text-sky-400 hover:bg-sky-900 rounded transition">
                  <Send className="w-3.5 h-3.5" />
                </a>
              </div>
            </div>

            {/* DOCUMENT CANONIQUE D'IMPRESSION PDF */}
            <div id="pdf-report" className="w-full bg-white text-slate-900 p-8 rounded-xl shadow-2xl border border-slate-200 text-xs space-y-5">
              
              <div className="border-b-2 border-slate-900 pb-4">
                <div className="flex justify-between items-start">
                  <div>
                    <h1 className="text-base font-extrabold uppercase text-slate-900">
                      {reportType === "SOC_CTI" ? "Rapport d'Incident SOC & Threat Intel" :
                       reportType === "Pentest" ? "Rapport d'Audit de Sécurité & Pentest" :
                       "Rapport d'Évaluation de Maturité SMSI & PCI DSS"}
                    </h1>
                    <p className="text-[10px] text-slate-500 font-semibold">{reportVersion} — {tlpMarking}</p>
                  </div>
                  <div className="text-right text-[10px] text-slate-600">
                    <p><strong>Client :</strong> {clientName}</p>
                    <p><strong>Analyste :</strong> {analystName}</p>
                    <p><strong>Date :</strong> {date}</p>
                  </div>
                </div>
              </div>

              {/* PDF PROFIL 1 : SOC + CTI */}
              {reportType === "SOC_CTI" && (
                <div className="space-y-4">
                  <div className="bg-red-50 border border-red-200 p-3 rounded-lg flex justify-between items-center">
                    <div>
                      <span className="text-[10px] text-red-600 font-bold uppercase block">Incident SOC</span>
                      <h2 className="text-xs font-bold text-red-950">{socTitle}</h2>
                    </div>
                    <span className="bg-red-600 text-white font-bold text-[10px] px-2 py-0.5 rounded">Élevée</span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] bg-cyan-50 border border-cyan-200 p-2.5 rounded">
                    <div><strong>Threat Actor :</strong> {threatActor}</div>
                    <div><strong>Confiance :</strong> {confidenceLevel}</div>
                    <div><strong>Motivation :</strong> {threatMotivation}</div>
                    <div><strong>Sophistication :</strong> {threatSophistication}</div>
                  </div>

                  <div>
                    <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">Analyse & Chronologie</h3>
                    <p className="text-xs text-slate-800">{socDescription}</p>
                  </div>

                  {iocs.length > 0 && (
                    <div>
                      <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">Indicateurs de Compromission (IOCs)</h3>
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

                  <div>
                    <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">Plan de Remédiation & Hardening</h3>
                    <p className="text-[11px] font-mono text-emerald-950 bg-emerald-50 p-2.5 rounded whitespace-pre-line border border-emerald-200 leading-relaxed">
                      {socRecommendations}
                    </p>
                  </div>
                </div>
              )}

              {/* PDF PROFIL 2 : PENTEST */}
              {reportType === "Pentest" && (
                <div className="space-y-4 text-xs">
                  <div>
                    <h3 className="font-bold uppercase text-slate-800 border-b pb-1 mb-1 text-[10px]">1. Executive Summary</h3>
                    <div className="bg-amber-50 p-2 rounded border border-amber-200 mb-1 flex justify-between items-center">
                      <span className="font-bold">Risque Global</span>
                      <span className="bg-amber-600 text-white font-bold px-2 py-0.5 rounded">{overallRiskRating}</span>
                    </div>
                    <p className="text-slate-700">{execSummary}</p>
                  </div>

                  <div className="bg-slate-50 p-2 rounded border flex justify-between items-center">
                    <span className="font-bold">Cotation CVSS v3.1</span>
                    <span className="bg-slate-900 text-white font-mono font-bold px-2 py-0.5 rounded">Score : {computedCvssScore} / 10</span>
                  </div>

                  <div>
                    <h3 className="font-bold uppercase text-slate-800 border-b pb-1 mb-1 text-[10px]">2. Technical Finding & PoC</h3>
                    <p className="font-bold text-red-700">{vulnTitle}</p>
                    <p className="font-mono bg-slate-100 p-2 rounded mt-1 whitespace-pre-line text-[10px]">{pocSteps}</p>
                  </div>

                  <div>
                    <h3 className="font-bold uppercase text-slate-800 border-b pb-1 mb-1 text-[10px]">3. Remediation Roadmap</h3>
                    <p className="font-mono text-green-900 bg-green-50 p-2 rounded text-[10px] whitespace-pre-line">
                      {p1Actions}{"\n"}{p2Actions}{"\n"}{p3Actions}
                    </p>
                  </div>
                </div>
              )}

              {/* PDF PROFIL 3 : CONFORMITÉ & MATURITÉ */}
              {reportType === "Compliance" && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-2 text-xs border p-2.5 rounded bg-slate-50 text-center">
                    <div><strong>Maturité ISO 27001 :</strong> <span className="text-emerald-700 font-bold text-sm">{avgIsoScore}%</span></div>
                    <div><strong>Maturité PCI DSS :</strong> <span className="text-blue-700 font-bold text-sm">{avgPciScore}%</span></div>
                  </div>

                  <div>
                    <h3 className="text-[10px] font-bold uppercase text-slate-800 border-b pb-1 mb-1">Gap Analysis Summary</h3>
                    <p className="text-xs text-slate-800 bg-amber-50 p-2.5 rounded border border-amber-200">{gapSummary}</p>
                  </div>

                  <div>
                    <h3 className="text-[10px] font-bold uppercase text-slate-800 border-b pb-1 mb-1">Strategic Action Plan (RSSI)</h3>
                    <p className="text-xs text-slate-800 font-mono bg-slate-100 p-2.5 rounded whitespace-pre-line border border-slate-200">{gapActionPlan}</p>
                  </div>
                </div>
              )}

              {/* EN-TÊTE SUPPORT & CONTACT DANS LE RAPPORT PDF */}
              <div className="border-t pt-3 mt-4 text-[9px] text-slate-500 flex justify-between items-center">
                <span>Plateforme ReportShield Pro — Livrable certifié</span>
                <span>Support & Partenariats : support@reportshield.io</span>
              </div>

            </div>
          </div>
        </div>
      </main>
    </>
  );
}