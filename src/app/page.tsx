"use client";

import React, { useState, useEffect } from "react";
import {
  Shield,
  Printer,
  Save,
  LogIn,
  LogOut,
  Languages,
  Activity,
  UserCog,
  LifeBuoy,
  Target,
  FileSearch,
  Terminal,
  Database,
  Wrench,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Server
} from "lucide-react";
import { supabase } from "@/lib/supabase";

interface IOCItem {
  id: string;
  type: string;
  value: string;
  description: string;
}

interface RemediationItem {
  id: string;
  action: string;
  priority: "Critique" | "Élevée" | "Moyenne" | "Faible";
  deadline: string;
  status: "À faire" | "En cours" | "Terminé";
}

const MITRE_TACTICS_SOC = [
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

  const [supportMessage, setSupportMessage] = useState("");
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [fullName, setFullName] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [jobTitle, setJobTitle] = useState("Junior SOC Analyst / QSA Assistant");

  const [lang, setLang] = useState<"fr" | "en">("fr");
  const [reportType, setReportType] = useState<"SOC_CTI" | "Pentest" | "Compliance">("Pentest");

  // Métadonnées générales
  const [clientName, setClientName] = useState("Entreprise Client SA");
  const [analystName, setAnalystName] = useState("Kossonou (Analyste Cyber)");
  const [date, setDate] = useState(new Date().toISOString().split("T")[0]);

  // PROFIL 1 : SOC & CTI
  const [socTitle, setSocTitle] = useState("Infiltration par Force Brute VPN & Exfiltration");
  const [socSystems, setSocSystems] = useState("Active Directory, Passerelle VPN, BDD Clients");
  const [socDescription, setSocDescription] = useState("Détection d'une authentification anormale suivie d'un mouvement latéral.");
  const [selectedMitreTactic, setSelectedMitreTactic] = useState("Initial Access");
  const [selectedMitreTechnique, setSelectedMitreTechnique] = useState("T1190 - Exploit Public-Facing Application");
  const [rawLogsText, setRawLogsText] = useState("");
  const [iocs, setIocs] = useState<IOCItem[]>([
    { id: "1", type: "IP Address", value: "192.168.1.105", description: "IP C2 Attaquant" }
  ]);
  const [socRemediations, setSocRemediations] = useState<RemediationItem[]>([
    { id: "1", action: "Isolation immédiate des hôtes compromis sur le périmètre réseau", priority: "Critique", deadline: "Immédiat (H+0)", status: "À faire" },
    { id: "2", action: "Réinitialisation générale des mots de passe des comptes administratifs impactés", priority: "Critique", deadline: "24 heures", status: "À faire" },
    { id: "3", action: "Activation du MFA (Multifactor Authentication) sur la passerelle VPN", priority: "Élevée", deadline: "48 heures", status: "À faire" }
  ]);
  const [newSocRemAction, setNewSocRemAction] = useState("");
  const [newSocRemPriority, setNewSocRemPriority] = useState<"Critique" | "Élevée" | "Moyenne" | "Faible">("Élevée");
  const [newSocRemDeadline, setNewSocRemDeadline] = useState("48 heures");

  // PROFIL 2 : PENTEST (8 ÉTAPES)
  const [ptStep1Scope, setPtStep1Scope] = useState("Périmètre : Application Web (https://app.client.com) et API REST v1.");
  const [ptStep2Recon, setPtStep2Recon] = useState("OSINT, énumération des sous-domaines, analyse des envergures DNS et bannières.");
  const [ptStep3Scan, setPtStep3Scan] = useState("Scans de vulnérabilités (Nmap, Nikto, Burp Scanner) et découverte des points d'entrée.");
  const [ptStep4Exploit, setPtStep4Exploit] = useState("Injection SQL (SQLi) confirmée sur le paramètre 'id_user' de l'API de recherche.");
  const [ptStep5PostExploit, setPtStep5PostExploit] = useState("Élévation de privilèges via compromission des jetons de session JWT et dump partiel de la base.");
  const [ptStep6RiskCVSS, setPtStep6RiskCVSS] = useState("CVSS v3.1 Score : 9.8 (Critique / High) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  const [ptStep8Conclusion, setPtStep8Conclusion] = useState("Niveau de risque global ÉLEVÉ nécessitant des actions correctives immédiates avant mise en production.");
  const [ptRemediations, setPtRemediations] = useState<RemediationItem[]>([
    { id: "1", action: "Corriger l'injection SQL en implémentant des requêtes préparées (Prepared Statements)", priority: "Critique", deadline: "J+2", status: "À faire" },
    { id: "2", action: "Sécuriser l'émission et la signature cryptographique des tokens d'authentification (JWT)", priority: "Élevée", deadline: "J+5", status: "À faire" },
    { id: "3", action: "Mettre en place un pare-feu applicatif web (WAF) pour filtrer les charges malicieuses", priority: "Moyenne", deadline: "J+15", status: "À faire" }
  ]);
  const [newPtRemAction, setNewPtRemAction] = useState("");
  const [newPtRemPriority, setNewPtRemPriority] = useState<"Critique" | "Élevée" | "Moyenne" | "Faible">("Critique");
  const [newPtRemDeadline, setNewPtRemDeadline] = useState("J+3");

  // PROFIL 3 : CONFORMITÉ (ISO 27001 & PCI DSS inchangé)
  const [isoMaturityScores, setIsoMaturityScores] = useState<Record<string, number>>(
    Object.fromEntries(ISO_DOMAINS_2022.map(d => [d.id, 2]))
  );
  const [pciMaturityScores, setPciMaturityScores] = useState<Record<string, number>>(
    Object.fromEntries(PCI_REQUIREMENTS_V4.map(r => [r.id, 2]))
  );
  const [gapSummary, setGapSummary] = useState("Alignement partiel sur ISO 27001:2022 et PCI DSS v4.0 (Maturité globale Niveau 2/5).");
  const [complianceRemediations, setComplianceRemediations] = useState<RemediationItem[]>([
    { id: "1", action: "Formaliser et faire valider par la direction la politique de sécurité de l'information (Clause 5 / Req 12)", priority: "Élevée", deadline: "30 jours", status: "À faire" },
    { id: "2", action: "Déployer la journalisation centralisée des accès aux données de cartes (PCI DSS Req 10)", priority: "Critique", deadline: "15 jours", status: "À faire" },
    { id: "3", action: "Réaliser une campagne de sensibilisation des employés à la sécurité (ISO Annexe A.6)", priority: "Moyenne", deadline: "45 jours", status: "À faire" }
  ]);
  const [newCompRemAction, setNewCompRemAction] = useState("");
  const [newCompRemPriority, setNewCompRemPriority] = useState<"Critique" | "Élevée" | "Moyenne" | "Faible">("Élevée");
  const [newCompRemDeadline, setNewCompRemDeadline] = useState("30 jours");

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
      const { error } = await supabase.auth.signUp({ email, password });
      if (error) setMessage(`Erreur d'inscription : ${error.message}`);
      else { setMessage("Compte créé avec succès !"); setShowAuthModal(false); }
    } else {
      const { error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) setMessage(`Erreur de connexion : ${error.message}`);
      else { setMessage("Connexion réussie !"); setShowAuthModal(false); }
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

    if (error) alert(`Erreur: ${error.message}`);
    else {
      alert("Profil mis à jour !");
      setAnalystName(`${fullName} (${jobTitle})`);
      setShowConfigModal(false);
    }
    setLoading(false);
  };

  const handleParseRegexLogs = () => {
    if (!rawLogsText) return;
    const extracted: IOCItem[] = [];
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const ips = Array.from(new Set(rawLogsText.match(ipRegex) || []));
    ips.forEach(ip => {
      if (ip !== "127.0.0.1" && ip !== "0.0.0.0") {
        extracted.push({ id: Math.random().toString(), type: "IP Address", value: ip, description: "Extrait auto via Regex" });
      }
    });

    if (extracted.length > 0) {
      setIocs([...iocs, ...extracted]);
      setRawLogsText("");
      alert(`${extracted.length} indicateur(s) extrait(s) avec succès !`);
    } else {
      alert("Aucune correspondance IP valide trouvée par Regex.");
    }
  };

  const handleSaveReport = async () => {
    if (!user) { alert("Veuillez vous connecter !"); setShowAuthModal(true); return; }
    setLoading(true);

    const currentRemediations = 
      reportType === "SOC_CTI" ? socRemediations :
      reportType === "Pentest" ? ptRemediations : complianceRemediations;

    const pentestDataPayload = reportType === "Pentest" ? {
      step1_scope: ptStep1Scope,
      step2_recon: ptStep2Recon,
      step3_scan: ptStep3Scan,
      step4_exploit: ptStep4Exploit,
      step5_post_exploit: ptStep5PostExploit,
      step6_cvss: ptStep6RiskCVSS,
      step8_conclusion: ptStep8Conclusion
    } : {};

    const { error } = await supabase.from("reports").insert([{
      user_id: user.id,
      client_name: clientName,
      analyst_name: analystName,
      incident_date: date,
      title: reportType === "Pentest" ? "Rapport d'Audit / Pentest (8 Étapes)" : reportType === "SOC_CTI" ? socTitle : "Audit de Maturité ISO / PCI DSS",
      severity: "Élevée",
      systems: socSystems,
      description: socDescription,
      report_type: reportType,
      iocs: iocs,
      remediations: currentRemediations,
      pentest_steps: pentestDataPayload,
      iso_scores: isoMaturityScores,
      pci_scores: pciMaturityScores
    }]);

    if (error) alert(`Erreur de sauvegarde: ${error.message}`);
    else alert("Rapport et données sauvegardés avec succès dans Supabase !");
    setLoading(false);
  };

  const currentTacticData = MITRE_TACTICS_SOC.find(t => t.name === selectedMitreTactic);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <header className="bg-slate-900/90 border-b border-slate-800 px-8 py-4 flex flex-col md:flex-row items-center justify-between gap-4 sticky top-0 z-50">
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
              <button onClick={async () => { await supabase.auth.signOut(); setUser(null); }} className="bg-red-600/20 text-red-400 p-1.5 rounded-lg border border-red-500/30 cursor-pointer" title="Déconnexion">
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <button onClick={() => { setIsSignUpMode(false); setShowAuthModal(true); }} className="bg-blue-600 hover:bg-blue-500 text-white px-3.5 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 cursor-pointer shadow-lg">
              <LogIn className="w-4 h-4" /> Connexion
            </button>
          )}

          <button onClick={handleSaveReport} disabled={loading} className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white px-3.5 py-1.5 rounded-lg text-xs font-bold cursor-pointer">
            <Save className="w-4 h-4" /> Sauvegarder
          </button>
          <button onClick={() => window.print()} className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white px-3.5 py-1.5 rounded-lg text-xs cursor-pointer shadow">
            <Printer className="w-4 h-4" /> Export PDF
          </button>
        </div>
      </header>

      {/* SÉLECTEUR DE PROFIL */}
      <div className="bg-slate-900/50 border-b border-slate-800 px-8 py-3 flex flex-col md:flex-row items-center justify-between gap-3">
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

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 p-8">
        <div className="lg:col-span-7 space-y-6">
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
            <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider border-b border-slate-800 pb-2">Informations Générales</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Client</label>
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

          {/* 1. MODULE SOC & CTI */}
          {reportType === "SOC_CTI" && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-base font-bold flex items-center gap-2 text-red-400 border-b border-slate-800 pb-3">
                <Activity className="w-5 h-5" /> Module SOC : Investigation, CTI & Remédiations
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">Titre de l'Incident</label>
                  <input type="text" value={socTitle} onChange={(e) => setSocTitle(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Systèmes/Actifs Impactés</label>
                  <input type="text" value={socSystems} onChange={(e) => setSocSystems(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
              </div>

              {/* Remédiations SOC */}
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3 text-xs">
                <span className="text-red-400 font-bold flex items-center gap-1.5">
                  <Wrench className="w-4 h-4" /> Plan de Remédiation & Actions Incident SOC
                </span>
                <div className="space-y-2">
                  {socRemediations.map((rem, idx) => (
                    <div key={rem.id} className="flex justify-between items-center bg-slate-900 p-2.5 rounded border border-slate-800">
                      <span>#{idx + 1} - {rem.action} ({rem.deadline})</span>
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400">{rem.priority}</span>
                        <button onClick={() => setSocRemediations(socRemediations.filter(r => r.id !== rem.id))} className="text-red-400 cursor-pointer">✕</button>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2 pt-2">
                  <input type="text" placeholder="Nouvelle action corrective..." value={newSocRemAction} onChange={(e) => setNewSocRemAction(e.target.value)} className="flex-1 bg-slate-900 border border-slate-800 rounded p-2 text-white" />
                  <button onClick={() => { if (newSocRemAction) { setSocRemediations([...socRemediations, { id: Math.random().toString(), action: newSocRemAction, priority: newSocRemPriority, deadline: newSocRemDeadline, status: "À faire" }]); setNewSocRemAction(""); }}} className="bg-red-600 hover:bg-red-500 px-3 py-2 rounded text-white font-bold cursor-pointer">Ajouter</button>
                </div>
              </div>
            </div>
          )}

          {/* 2. MODULE PENTEST (8 ÉTAPES) */}
          {reportType === "Pentest" && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4 text-xs">
              <h2 className="text-base font-bold flex items-center gap-2 text-amber-400 border-b border-slate-800 pb-3">
                <Shield className="w-5 h-5" /> Module Audit & Pentest (8 Étapes Détaillées)
              </h2>
              <div className="space-y-3">
                <div>
                  <label className="block text-amber-400 font-bold mb-1">Étape 1 : Périmètre & Cibles</label>
                  <textarea rows={2} value={ptStep1Scope} onChange={(e) => setPtStep1Scope(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-amber-400 font-bold mb-1">Étape 2 : Reconnaissance & OSINT</label>
                  <textarea rows={2} value={ptStep2Recon} onChange={(e) => setPtStep2Recon(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-amber-400 font-bold mb-1">Étape 3 : Scan de Vulnérabilités</label>
                  <textarea rows={2} value={ptStep3Scan} onChange={(e) => setPtStep3Scan(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-amber-400 font-bold mb-1">Étape 4 : Exploitation / Preuves de Concept</label>
                  <textarea rows={2} value={ptStep4Exploit} onChange={(e) => setPtStep4Exploit(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-amber-400 font-bold mb-1">Étape 5 : Post-Exploitation & Mouvement Latéral</label>
                  <textarea rows={2} value={ptStep5PostExploit} onChange={(e) => setPtStep5PostExploit(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-amber-400 font-bold mb-1">Étape 6 : Évaluation des Risques & CVSS</label>
                  <textarea rows={2} value={ptStep6RiskCVSS} onChange={(e) => setPtStep6RiskCVSS(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-amber-400 font-bold mb-1">Étape 8 : Conclusion & Synthèse Exécutive</label>
                  <textarea rows={2} value={ptStep8Conclusion} onChange={(e) => setPtStep8Conclusion(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
              </div>

              {/* Remédiations Pentest */}
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
                <span className="text-amber-400 font-bold flex items-center gap-1.5">
                  <Wrench className="w-4 h-4" /> Plan de Remédiation & Recommandations Pentest
                </span>
                <div className="space-y-2">
                  {ptRemediations.map((rem, idx) => (
                    <div key={rem.id} className="flex justify-between items-center bg-slate-900 p-2.5 rounded border border-slate-800">
                      <span>#{idx + 1} - {rem.action} ({rem.deadline})</span>
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400">{rem.priority}</span>
                        <button onClick={() => setPtRemediations(ptRemediations.filter(r => r.id !== rem.id))} className="text-red-400 cursor-pointer">✕</button>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2 pt-2">
                  <input type="text" placeholder="Nouvelle recommandation..." value={newPtRemAction} onChange={(e) => setNewPtRemAction(e.target.value)} className="flex-1 bg-slate-900 border border-slate-800 rounded p-2 text-white" />
                  <button onClick={() => { if (newPtRemAction) { setPtRemediations([...ptRemediations, { id: Math.random().toString(), action: newPtRemAction, priority: newPtRemPriority, deadline: newPtRemDeadline, status: "À faire" }]); setNewPtRemAction(""); }}} className="bg-amber-600 hover:bg-amber-500 px-3 py-2 rounded text-white font-bold cursor-pointer">Ajouter</button>
                </div>
              </div>
            </div>
          )}

          {/* 3. MODULE CONFORMITÉ ISO 27001 & PCI DSS INCHANGÉ */}
          {reportType === "Compliance" && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4 text-xs">
              <h2 className="text-base font-bold flex items-center gap-2 text-emerald-400 border-b border-slate-800 pb-3">
                <Database className="w-5 h-5" /> Module Conformité ISO 27001:2022 & PCI DSS v4.0
              </h2>
              <div>
                <label className="block text-slate-300 font-bold mb-1">Résumé de l'Écart (Gap Analysis)</label>
                <textarea rows={2} value={gapSummary} onChange={(e) => setGapSummary(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
              </div>

              <div className="space-y-4 pt-2">
                <h3 className="font-bold text-emerald-400">Évaluation des Domaines ISO 27001</h3>
                <div className="grid grid-cols-1 gap-2 max-h-60 overflow-y-auto pr-2">
                  {ISO_DOMAINS_2022.map((domain) => (
                    <div key={domain.id} className="flex justify-between items-center bg-slate-950 p-2.5 rounded border border-slate-800">
                      <span className="text-slate-300">{domain.label}</span>
                      <select 
                        value={isoMaturityScores[domain.id] || 2} 
                        onChange={(e) => setIsoMaturityScores({...isoMaturityScores, [domain.id]: Number(e.target.value)})}
                        className="bg-slate-900 border border-slate-700 text-emerald-400 p-1 rounded font-bold"
                      >
                        <option value={1}>Niveau 1 - Initial</option>
                        <option value={2}>Niveau 2 - Géré</option>
                        <option value={3}>Niveau 3 - Défini</option>
                        <option value={4}>Niveau 4 - Quantifié</option>
                        <option value={5}>Niveau 5 - Optimisé</option>
                      </select>
                    </div>
                  ))}
                </div>

                <h3 className="font-bold text-emerald-400 pt-2">Évaluation des Exigences PCI DSS v4.0</h3>
                <div className="grid grid-cols-1 gap-2 max-h-60 overflow-y-auto pr-2">
                  {PCI_REQUIREMENTS_V4.map((req) => (
                    <div key={req.id} className="flex justify-between items-center bg-slate-950 p-2.5 rounded border border-slate-800">
                      <span className="text-slate-300">{req.label}</span>
                      <select 
                        value={pciMaturityScores[req.id] || 2} 
                        onChange={(e) => setPciMaturityScores({...pciMaturityScores, [req.id]: Number(e.target.value)})}
                        className="bg-slate-900 border border-slate-700 text-emerald-400 p-1 rounded font-bold"
                      >
                        <option value={1}>Niveau 1 - Non Conforme</option>
                        <option value={2}>Niveau 2 - Partiel</option>
                        <option value={3}>Niveau 3 - Conforme</option>
                      </select>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* APERÇU RAPPORT ACTIF */}
        <div className="lg:col-span-5">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-6 sticky top-24">
            <h3 className="text-lg font-extrabold text-white">{clientName}</h3>
            <p className="text-xs text-slate-400">Profil sélectionné : <span className="text-blue-400 font-bold">{reportType}</span></p>
            <div className="border-t border-slate-800 pt-4 text-xs space-y-2 text-slate-300">
              <p><strong>Signataire :</strong> {analystName}</p>
              <p><strong>Date d'intervention :</strong> {date}</p>
              {reportType === "Pentest" && <p className="text-amber-400">✓ 8 Étapes du Pentest intégrées et prêtes pour sauvegarde.</p>}
              {reportType === "SOC_CTI" && <p className="text-red-400">✓ Module Incident & Remédiations SOC actif.</p>}
              {reportType === "Compliance" && <p className="text-emerald-400">✓ Modules ISO 27001 & PCI DSS actifs.</p>}
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}