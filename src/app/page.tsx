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
  Settings,
  UserPlus,
  Upload,
  LifeBuoy,
  PhoneCall,
  Mail
} from "lucide-react";
import { supabase } from "@/lib/supabase";

interface IOCItem {
  id: string;
  type: string;
  value: string;
  description: string;
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
  const [password, setPassword] = useState("");
  const [isSignUpMode, setIsSignUpMode] = useState(false);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [showSupportModal, setShowSupportModal] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  // Support technique form
  const [supportMessage, setSupportMessage] = useState("");

  // Configuration du compte
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
  const [newIocType, setNewIocType] = useState("IP Address");
  const [newIocValue, setNewIocValue] = useState("");
  const [newIocDesc, setNewIocDesc] = useState("");

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
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);

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
      if (data.user) fetchUserProfile(data.user.id);
    };
    initAuth();
    const { data: authListener } = supabase.auth.onAuthStateChange((_, session) => {
      setUser(session?.user ?? null);
      if (session?.user) fetchUserProfile(session.user.id);
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

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage("");

    if (isSignUpMode) {
      const { data, error } = await supabase.auth.signUp({ email, password });
      if (error) {
        setMessage(`Erreur d'inscription : ${error.message}`);
      } else {
        setMessage("Compte créé avec succès ! Vérifiez votre boîte mail si requis.");
        setShowAuthModal(false);
      }
    } else {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) {
        setMessage(`Erreur de connexion : ${error.message}`);
      } else {
        setMessage("Connexion réussie !");
        setShowAuthModal(false);
      }
    }
    setLoading(false);
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
      if (ip !== "127.0.0.1") extracted.push({ id: Math.random().toString(), type: "IP Address", value: ip, description: "Extrait automatique des logs" });
    });
    if (extracted.length > 0) {
      setIocs([...iocs, ...extracted]);
      setRawLogsText("");
      alert(`${extracted.length} IOC(s) extrait(s) !`);
    } else alert("Aucun IOC IP trouvé.");
  };

  const handleAddManualIoc = () => {
    if (!newIocValue) return;
    setIocs([...iocs, { id: Math.random().toString(), type: newIocType, value: newIocValue, description: newIocDesc || "Manuel" }]);
    setNewIocValue("");
    setNewIocDesc("");
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

  // Gestion des fichiers téléversés
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setUploadedFileName(file.name);
      alert(`Fichier "${file.name}" téléversé et rattaché avec succès au rapport !`);
    }
  };

  const handleDownloadReportJson = () => {
    const reportData = {
      clientName,
      analystName,
      date,
      reportType,
      cvssScore: computedCvssScore,
      iocs,
      isoScores: isoMaturityScores,
      pciScores: pciMaturityScores
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `Report_${clientName.replace(/\s+/g, '_')}.json`;
    link.click();
  };

  const handleSaveReport = async () => {
    if (!user) { alert("Veuillez vous connecter ou créer un compte !"); setShowAuthModal(true); return; }
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
    else alert("Rapport sauvegardé avec succès dans Supabase !");
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

          <div className="flex items-center gap-3 flex-wrap">
            <button onClick={() => setLang(lang === "fr" ? "en" : "fr")} className="bg-slate-800 text-amber-400 px-3 py-1.5 rounded-lg border border-slate-700 text-xs font-bold flex items-center gap-1.5 cursor-pointer">
              <Languages className="w-4 h-4" /> {lang === "fr" ? "English 🇬🇧" : "Français 🇫🇷"}
            </button>

            <button onClick={() => setShowSupportModal(true)} className="bg-slate-800 hover:bg-slate-700 text-cyan-400 px-3 py-1.5 rounded-lg border border-slate-700 text-xs font-bold flex items-center gap-1.5 cursor-pointer">
              <LifeBuoy className="w-4 h-4" /> Support
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
              <button onClick={() => { setIsSignUpMode(false); setShowAuthModal(true); }} className="bg-blue-600 hover:bg-blue-500 text-white px-3.5 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 cursor-pointer shadow-lg">
                <LogIn className="w-4 h-4" /> Connexion
              </button>
            )}

            <button onClick={handleSaveReport} disabled={loading} className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white px-3.5 py-1.5 rounded-lg text-xs font-bold cursor-pointer shadow">
              <Save className="w-4 h-4" /> Sauvegarder
            </button>
            <button onClick={handleDownloadReportJson} className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 px-3.5 py-1.5 rounded-lg text-xs border border-slate-700 cursor-pointer">
              <Download className="w-4 h-4" /> Télécharger JSON
            </button>
            <button onClick={() => window.print()} className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white px-3.5 py-1.5 rounded-lg text-xs cursor-pointer shadow">
              <Printer className="w-4 h-4" /> Export PDF
            </button>
          </div>
        </header>

        {/* MODAL AUTHENTIFICATION & CRÉATION DE COMPTE */}
        {showAuthModal && (
          <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 no-print">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 w-full max-w-md shadow-2xl space-y-4">
              <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Shield className="w-4 h-4 text-blue-500" /> {isSignUpMode ? "Créer un Compte ReportShield" : "Connexion à ReportShield Pro"}
                </h3>
                <button onClick={() => setShowAuthModal(false)} className="text-slate-400 hover:text-white text-xs cursor-pointer">✕</button>
              </div>

              {message && <div className="bg-slate-950 p-2 text-xs text-amber-400 rounded border border-slate-800">{message}</div>}

              <form onSubmit={handleAuthSubmit} className="space-y-4 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">Adresse Email</label>
                  <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="analyste@cyber.com" className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Mot de passe</label>
                  <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-white" />
                </div>

                <button type="submit" disabled={loading} className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-2.5 rounded-lg cursor-pointer">
                  {isSignUpMode ? "Créer mon compte" : "Se Connecter"}
                </button>
              </form>

              <div className="flex justify-between items-center pt-2 border-t border-slate-800 text-xs">
                <button onClick={() => setIsSignUpMode(!isSignUpMode)} className="text-blue-400 hover:underline cursor-pointer flex items-center gap-1">
                  <UserPlus className="w-3.5 h-3.5" />
                  {isSignUpMode ? "Déjà un compte ? Connectez-vous" : "Pas de compte ? Créer un compte"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* MODAL SUPPORT TECHNIQUE */}
        {showSupportModal && (
          <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 no-print">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 w-full max-w-md shadow-2xl space-y-4">
              <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <LifeBuoy className="w-4 h-4 text-cyan-400" /> Centre d'Assistance & Support Technique
                </h3>
                <button onClick={() => setShowSupportModal(false)} className="text-slate-400 hover:text-white text-xs cursor-pointer">✕</button>
              </div>

              <div className="text-xs space-y-3 text-slate-300">
                <p>Besoin d'aide avec un rapport, un calcul CVSS ou un export STIX ? Notre équipe SOC/SecOps vous répond 24/7.</p>
                <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-2">
                  <div className="flex items-center gap-2 text-slate-200">
                    <Mail className="w-4 h-4 text-blue-400" /> support@reportshield-pro.com
                  </div>
                  <div className="flex items-center gap-2 text-slate-200">
                    <PhoneCall className="w-4 h-4 text-emerald-400" /> +33 (0)1 89 00 24 70 (Ligne Directe SOC)
                  </div>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Envoyer un message au support :</label>
                  <textarea rows={3} value={supportMessage} onChange={(e) => setSupportMessage(e.target.value)} placeholder="Décrivez votre problème technique..." className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <button onClick={() => { alert("Message envoyé au support technique ! Un opérateur va vous contacter."); setSupportMessage(""); setShowSupportModal(false); }} className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-2 rounded cursor-pointer">
                  Envoyer la requête
                </button>
              </div>
            </div>
          </div>
        )}

        {/* MODAL CONFIGURATION DU COMPTE */}
        {showConfigModal && (
          <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 no-print">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 w-full max-w-md shadow-2xl space-y-4">
              <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Settings className="w-4 h-4 text-blue-400" /> Paramètres du Compte Analyste
                </h3>
                <button onClick={() => setShowConfigModal(false)} className="text-slate-400 hover:text-white text-xs cursor-pointer">✕</button>
              </div>

              <form onSubmit={handleSaveProfile} className="space-y-4 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">Nom Complet</label>
                  <input type="text" value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="ex: Kossonou Fieny" className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Entreprise / Organisation</label>
                  <input type="text" value={companyName} onChange={(e) => setCompanyName(e.target.value)} placeholder="ex: Colombe Cyber Defense (CCDOC)" className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Intitulé de Poste</label>
                  <input type="text" value={jobTitle} onChange={(e) => setJobTitle(e.target.value)} placeholder="ex: Junior SOC Analyst / QSA Assistant" className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <button type="submit" disabled={loading} className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 rounded-lg cursor-pointer">
                  Enregistrer les modifications
                </button>
              </form>
            </div>
          </div>
        )}

        {/* SÉLECTION DES 3 PROFILS */}
        <div className="bg-slate-900/50 border-b border-slate-800 px-8 py-3 flex flex-col md:flex-row items-center justify-between gap-3 no-print">
          <span className="text-xs font-semibold text-slate-400">Sélectionnez le Profil Métier :</span>
          <div className="flex gap-2 flex-wrap">
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
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
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

              {/* TÉLÉVERSEMENT DE FICHIERS / PREUVES */}
              <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Téléverser une pièce jointe ou un log brut (PDF, TXT, PCAP)</label>
                  <input type="file" onChange={handleFileUpload} className="text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-500 cursor-pointer" />
                </div>
                {uploadedFileName && <span className="text-xs text-emerald-400 font-semibold">✓ {uploadedFileName}</span>}
              </div>
            </div>

            {/* ================= PROFIL 1 : SOC + CTI ================= */}
            {reportType === "SOC_CTI" && (
              <div className="space-y-6 animate-fadeIn">
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-base font-bold flex items-center gap-2 text-red-400 border-b border-slate-800 pb-3">
                    <Activity className="w-5 h-5" /> Volet 1 : Investigation d'Incident SOC
                  </h2>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
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
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Threat Actor</label>
                      <input type="text" value={threatActor} onChange={(e) => setThreatActor(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Niveau de Confiance</label>
                      <input type="text" value={confidenceLevel} onChange={(e) => setConfidenceLevel(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                  </div>

                  {/* PARSEUR DE LOGS POUR IOCs */}
                  <div className="pt-2 border-t border-slate-800 space-y-2">
                    <label className="block text-xs text-slate-400">Extracteur automatique d'IPs depuis des logs bruts :</label>
                    <div className="flex gap-2">
                      <textarea rows={2} value={rawLogsText} onChange={(e) => setRawLogsText(e.target.value)} placeholder="Collez vos logs bruts ici (ex: Failed login from 192.168.1.15)..." className="flex-1 bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
                      <button type="button" onClick={handleParseLogs} className="bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded text-xs font-bold cursor-pointer">
                        Extraire IOCs
                      </button>
                    </div>
                  </div>

                  {/* AJOUT MANUEL IOC */}
                  <div className="pt-2 border-t border-slate-800 space-y-2">
                    <label className="block text-xs text-slate-400">Ajouter un Indicateur de Compromission (IOC) :</label>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                      <select value={newIocType} onChange={(e) => setNewIocType(e.target.value)} className="bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white">
                        <option value="IP Address">IP Address</option>
                        <option value="Domain">Domain</option>
                        <option value="File Hash (SHA256)">File Hash (SHA256)</option>
                        <option value="URL">URL</option>
                      </select>
                      <input type="text" value={newIocValue} onChange={(e) => setNewIocValue(e.target.value)} placeholder="Valeur (ex: 10.0.0.5)" className="bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
                      <div className="flex gap-2">
                        <input type="text" value={newIocDesc} onChange={(e) => setNewIocDesc(e.target.value)} placeholder="Description" className="flex-1 bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
                        <button type="button" onClick={handleAddManualIoc} className="bg-blue-600 hover:bg-blue-500 text-white px-3 py-2 rounded text-xs font-bold cursor-pointer">
                          +
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="flex justify-between items-center pt-2">
                    <span className="text-xs text-slate-400">{iocs.length} IOC(s) répertorié(s)</span>
                    <button type="button" onClick={handleExportSTIX} className="bg-purple-600 hover:bg-purple-500 text-white px-4 py-2 rounded text-xs font-bold flex items-center gap-1.5 cursor-pointer">
                      <Download className="w-4 h-4" /> Exporter Bundle STIX 2.1
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* ================= PROFIL 2 : AUDIT & PENTEST ================= */}
            {reportType === "Pentest" && (
              <div className="space-y-6 animate-fadeIn">
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-base font-bold flex items-center gap-2 text-amber-400 border-b border-slate-800 pb-3">
                    <Shield className="w-5 h-5" /> Volet 1 : Périmètre & Synthèse Exécutive
                  </h2>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Cible In-Scope</label>
                      <input type="text" value={inScopeTarget} onChange={(e) => setInScopeTarget(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Niveau de Risque Global</label>
                      <select value={overallRiskRating} onChange={(e) => setOverallRiskRating(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white">
                        <option value="Critique / Critical Risk">Critique / Critical Risk</option>
                        <option value="Élevé / High Risk">Élevé / High Risk</option>
                        <option value="Moyen / Medium Risk">Moyen / Medium Risk</option>
                        <option value="Faible / Low Risk">Faible / Low Risk</option>
                      </select>
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Résumé Exécutif</label>
                    <textarea rows={3} value={execSummary} onChange={(e) => setExecSummary(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
                  </div>
                </div>

                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-base font-bold flex items-center gap-2 text-red-400 border-b border-slate-800 pb-3">
                    <Calculator className="w-5 h-5" /> Volet 2 : Calculateur de Criticité CVSS v3.1 & PoC
                  </h2>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Titre de la Vulnérabilité</label>
                      <input type="text" value={vulnTitle} onChange={(e) => setVulnTitle(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Catégorie OWASP</label>
                      <input type="text" value={owaspCategory} onChange={(e) => setOwaspCategory(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Score CVSS Calculé</label>
                      <div className="bg-slate-950 border border-slate-800 rounded p-2 text-amber-400 font-bold text-center">
                        {computedCvssScore} / 10
                      </div>
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Étapes de la Preuve de Concept (PoC)</label>
                    <textarea rows={3} value={pocSteps} onChange={(e) => setPocSteps(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white font-mono" />
                  </div>
                </div>
              </div>
            )}

            {/* ================= PROFIL 3 : CONFORMITÉ ================= */}
            {reportType === "Compliance" && (
              <div className="space-y-6 animate-fadeIn">
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-base font-bold flex items-center gap-2 text-emerald-400 border-b border-slate-800 pb-3">
                    <Award className="w-5 h-5" /> Volet 1 : Matrice de Maturité ISO 27001:2022
                  </h2>
                  <div className="space-y-3 text-xs max-h-64 overflow-y-auto pr-2">
                    {ISO_DOMAINS_2022.map((domain) => (
                      <div key={domain.id} className="flex items-center justify-between bg-slate-950 p-2.5 rounded border border-slate-800">
                        <span className="text-slate-300 flex-1">{domain.label}</span>
                        <select
                          value={isoMaturityScores[domain.id] || 2}
                          onChange={(e) => setIsoMaturityScores({ ...isoMaturityScores, [domain.id]: Number(e.target.value) })}
                          className="bg-slate-900 border border-slate-700 rounded p-1 text-white font-bold"
                        >
                          <option value={0}>0 - Non implémenté</option>
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
                  <h2 className="text-base font-bold flex items-center gap-2 text-blue-400 border-b border-slate-800 pb-3">
                    <FileCheck2 className="w-5 h-5" /> Volet 2 : Exigences PCI DSS v4.0 & Plan d'Action
                  </h2>
                  <div className="space-y-3 text-xs max-h-64 overflow-y-auto pr-2">
                    {PCI_REQUIREMENTS_V4.map((req) => (
                      <div key={req.id} className="flex items-center justify-between bg-slate-950 p-2.5 rounded border border-slate-800">
                        <span className="text-slate-300 flex-1">{req.label}</span>
                        <select
                          value={pciMaturityScores[req.id] || 2}
                          onChange={(e) => setPciMaturityScores({ ...pciMaturityScores, [req.id]: Number(e.target.value) })}
                          className="bg-slate-900 border border-slate-700 rounded p-1 text-white font-bold"
                        >
                          <option value={0}>0 - Non conforme</option>
                          <option value={2}>2 - Partiel</option>
                          <option value={5}>5 - Conforme total</option>
                        </select>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

          </div>

          {/* APERÇU DU RAPPORT (SPAN 5) & LIENS DE PARTAGE */}
          <div className="lg:col-span-5 space-y-6">
            <div id="pdf-report" className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-6">
              
              <div className="flex justify-between items-start border-b border-slate-800 pb-4">
                <div>
                  <span className="text-[10px] uppercase tracking-widest text-blue-400 font-bold">Rapport d'Expertise Certifié</span>
                  <h3 className="text-lg font-extrabold text-white">{clientName}</h3>
                  <p className="text-xs text-slate-400">Analyste : {analystName}</p>
                </div>
                <div className="text-right">
                  <span className="text-xs text-slate-400 block">{date}</span>
                  <span className="bg-amber-500/20 text-amber-400 text-[10px] px-2 py-0.5 rounded border border-amber-500/30 font-bold">{tlpMarking}</span>
                </div>
              </div>

              {reportType === "SOC_CTI" && (
                <div className="space-y-3 text-xs">
                  <h4 className="font-bold text-red-400 flex items-center gap-1.5"><Activity className="w-4 h-4"/> Incident : {socTitle}</h4>
                  <p className="text-slate-300 bg-slate-950 p-3 rounded border border-slate-800">{socDescription}</p>
                  <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
                    <p className="font-semibold text-slate-200">Threat Actor : {threatActor}</p>
                    <p className="font-semibold text-slate-200">Tactique : {mitreTactic} ({mitreTechnique})</p>
                  </div>
                </div>
              )}

              {reportType === "Pentest" && (
                <div className="space-y-3 text-xs">
                  <h4 className="font-bold text-amber-400 flex items-center gap-1.5"><Shield className="w-4 h-4"/> Audit : {vulnTitle}</h4>
                  <div className="flex justify-between bg-slate-950 p-3 rounded border border-slate-800">
                    <span>Score CVSS : <strong className="text-amber-400">{computedCvssScore}/10</strong></span>
                    <span>Risque : <strong className="text-red-400">{overallRiskRating}</strong></span>
                  </div>
                  <p className="text-slate-300 bg-slate-950 p-3 rounded border border-slate-800 font-mono text-[11px] whitespace-pre-wrap">{pocSteps}</p>
                </div>
              )}

              {reportType === "Compliance" && (
                <div className="space-y-3 text-xs">
                  <h4 className="font-bold text-emerald-400 flex items-center gap-1.5"><Award className="w-4 h-4"/> Synthèse de Conformité</h4>
                  <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-2">
                    <p className="text-slate-300">Norme ISO 27001:2022 & PCI DSS v4.0 évaluées.</p>
                    <p className="text-slate-400">{gapSummary}</p>
                  </div>
                </div>
              )}

              {uploadedFileName && (
                <div className="text-[11px] text-slate-400 bg-slate-950 p-2 rounded border border-slate-800 flex items-center gap-2">
                  <FileText className="w-3.5 h-3.5 text-blue-400" /> Pièce jointe rattachée : {uploadedFileName}
                </div>
              )}

              {/* BOUTONS DE PARTAGE SOCIAL RAPIDE */}
              <div className="pt-4 border-t border-slate-800 no-print space-y-2">
                <span className="text-xs font-bold text-slate-400 flex items-center gap-1.5">
                  <Share2 className="w-3.5 h-3.5 text-blue-400" /> Partager ce rapport :
                </span>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <a href={shareLinks.linkedin} target="_blank" rel="noopener noreferrer" className="bg-[#0A66C2]/20 hover:bg-[#0A66C2]/30 text-[#0A66C2] border border-[#0A66C2]/40 py-2 px-3 rounded font-bold text-center">
                    LinkedIn
                  </a>
                  <a href={shareLinks.telegram} target="_blank" rel="noopener noreferrer" className="bg-[#24A1EE]/20 hover:bg-[#24A1EE]/30 text-[#24A1EE] border border-[#24A1EE]/40 py-2 px-3 rounded font-bold text-center">
                    Telegram
                  </a>
                  <a href={shareLinks.whatsapp} target="_blank" rel="noopener noreferrer" className="bg-[#25D366]/20 hover:bg-[#25D366]/30 text-[#25D366] border border-[#25D366]/40 py-2 px-3 rounded font-bold text-center">
                    WhatsApp
                  </a>
                  <a href={shareLinks.twitter} target="_blank" rel="noopener noreferrer" className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 py-2 px-3 rounded font-bold text-center">
                    X (Twitter)
                  </a>
                </div>
              </div>

            </div>
          </div>

        </div>

      </main>
    </>
  );
}