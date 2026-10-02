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
  Clock,
  Image as ImageIcon,
  Plus,
  Crosshair,
  List,
  Globe,
  Radio,
  Download,
  Wand2,
  Calculator,
  Layers,
  History,
  CheckSquare,
  Award,
  Activity,
  Cpu,
  Sliders
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
  cvss_vector?: string;
  report_type?: string;
  iso_scores?: Record<string, boolean>;
  pci_scores?: Record<string, boolean>;
  iso_maturity_score?: number;
  pci_maturity_score?: number;
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

const ISO_CONTROLS = [
  { id: "A5.1", label: "Politiques de sécurité de l'information documentées" },
  { id: "A5.7", label: "Threat Intelligence intégrée et exploitée" },
  { id: "A5.15", label: "Gestion et contrôle strict des accès (RBAC)" },
  { id: "A8.8", label: "Gestion des vulnérabilités et correctifs (Patching)" },
  { id: "A8.12", label: "Prévention contre les fuites de données (DLP)" },
  { id: "A8.16", label: "Surveillance et journalisation continue (SIEM)" },
];

const PCI_CONTROLS = [
  { id: "Req1", label: "Pare-feu et microsegmentation du CDE configurés" },
  { id: "Req3", label: "Données de cartes (PAN) chiffrées au repos" },
  { id: "Req6", label: "Applications sécurisées et patchs appliqués sous 30j" },
  { id: "Req8", label: "Authentification multifacteur (MFA) obligatoire pour accès CDE" },
  { id: "Req10", label: "Journalisation active et conservation des logs 12 mois" },
  { id: "Req11", label: "Scans de vulnérabilités ASV et tests d'intrusion réguliers" },
];

export default function Home() {
  const [user, setUser] = useState<any>(null);
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [savedReports, setSavedReports] = useState<ReportItem[]>([]);

  // Gestion des Onglets
  const [activeTab, setActiveTab] = useState<"incident" | "cti" | "compliance" | "history">("incident");

  const [reportType, setReportType] = useState<string>("SOC Incident");
  const [logoBase64, setLogoBase64] = useState<string>("");
  const [mitreTactic, setMitreTactic] = useState<string>("Credential Access");
  const [mitreTechnique, setMitreTechnique] = useState<string>("T1110 - Brute Force");
  
  const [threatActor, setThreatActor] = useState<string>("Inconnu / Non Attribué");
  const [threatMotivation, setThreatMotivation] = useState<string>("Gain Financier (Ransomware / Extorsion)");
  const [threatSophistication, setThreatSophistication] = useState<string>("Moyenne (Cybercriminalité organisée)");
  const [confidenceLevel, setConfidenceLevel] = useState<string>("Moyenne");

  const [cvssAV, setCvssAV] = useState<number>(0.85);
  const [cvssAC, setCvssAC] = useState<number>(0.77);
  const [cvssPR, setCvssPR] = useState<number>(0.85);
  const [cvssUI, setCvssUI] = useState<number>(0.85);
  const [cvssImpactC, setCvssImpactC] = useState<number>(0.56);
  const [cvssImpactI, setCvssImpactI] = useState<number>(0.56);
  const [cvssImpactA, setCvssImpactA] = useState<number>(0.56);

  const [rawLogsText, setRawLogsText] = useState<string>("");

  const [isoChecks, setIsoChecks] = useState<Record<string, boolean>>({
    "A5.1": true, "A5.7": false, "A5.15": true, "A8.8": false, "A8.12": false, "A8.16": true,
  });

  const [pciChecks, setPciChecks] = useState<Record<string, boolean>>({
    "Req1": true, "Req3": false, "Req6": true, "Req8": false, "Req10": true, "Req11": false,
  });

  const [iocs, setIocs] = useState<IOCItem[]>([
    { id: "1", type: "IP Address", value: "192.168.1.105", description: "IP source force brute" },
    { id: "2", type: "Hash SHA256", value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", description: "Payload malveillant" }
  ]);
  const [newIoc, setNewIoc] = useState({ type: "IP Address", value: "", description: "" });

  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([
    { id: "1", time: "08:15:00", title: "Détection brute force", description: "Alerte SIEM VPN." },
    { id: "2", time: "08:22:30", title: "Accès compromis", description: "Connexion réussie depuis 192.168.1.105." }
  ]);
  const [newEvent, setNewEvent] = useState({ time: "", title: "", description: "" });

  const [formData, setFormData] = useState({
    clientName: "Entreprise Client SA",
    analystName: "Analyste Cyber",
    date: new Date().toISOString().split("T")[0],
    title: "Suspicion d'intrusion et activité anormale",
    severity: "Élevée",
    systems: "Serveur Principal, Pare-feu de bordure",
    description: "Détection de multiples tentatives d'authentification échouées suivies d'une élévation de privilèges non autorisée.",
    rootCause: "Compromission de mot de passe via une attaque de force brute sur un accès VPN sans MFA.",
    recommendations: "1. Activer le MFA obligatoire.\n2. Isoler la machine impactée.\n3. Mettre à jour les règles du pare-feu.",
  });

  useEffect(() => {
    const initAuth = async () => {
      const { data } = await supabase.auth.getUser();
      setUser(data.user);
      if (data.user) fetchReports();
    };

    initAuth();

    const { data: authListener } = supabase.auth.onAuthStateChange((_, session) => {
      const currentUser = session?.user ?? null;
      setUser(currentUser);
      if (currentUser) fetchReports();
      else setSavedReports([]);
    });

    return () => {
      authListener.subscription.unsubscribe();
    };
  }, []);

  const fetchReports = async () => {
    const { data, error } = await supabase
      .from("reports")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Erreur chargement rapports:", error.message);
    } else if (data) {
      setSavedReports(data as ReportItem[]);
    }
  };

  const isoMaturityPercent = Math.round(
    (Object.values(isoChecks).filter(Boolean).length / ISO_CONTROLS.length) * 100
  );

  const pciMaturityPercent = Math.round(
    (Object.values(pciChecks).filter(Boolean).length / PCI_CONTROLS.length) * 100
  );

  const calculateCVSSScore = (): number => {
    const iss = 1 - (1 - cvssImpactC) * (1 - cvssImpactI) * (1 - cvssImpactA);
    const impact = 6.42 * iss;
    const exploitability = 8.22 * cvssAV * cvssAC * cvssPR * cvssUI;

    if (impact <= 0) return 0;
    return Math.min(10, Math.ceil((impact + exploitability) * 10) / 10);
  };

  const computedCvssScore = calculateCVSSScore();
  const cvssVectorString = `CVSS:3.1/AV:${cvssAV === 0.85 ? 'N' : 'L'}/AC:${cvssAC === 0.77 ? 'L' : 'H'}/PR:${cvssPR === 0.85 ? 'N' : 'L'}/UI:${cvssUI === 0.85 ? 'N' : 'R'}/C:${cvssImpactC === 0.56 ? 'H' : 'L'}/I:${cvssImpactI === 0.56 ? 'H' : 'L'}/A:${cvssImpactA === 0.56 ? 'H' : 'L'}`;

  const handleParseLogs = () => {
    if (!rawLogsText) return;
    const extracted: IOCItem[] = [];
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const ips = Array.from(new Set(rawLogsText.match(ipRegex) || []));
    ips.forEach(ip => {
      if (ip !== "127.0.0.1") extracted.push({ id: Math.random().toString(), type: "IP Address", value: ip, description: "Extrait automatiquement des logs" });
    });

    if (extracted.length > 0) {
      setIocs([...iocs, ...extracted]);
      setRawLogsText("");
      alert(`${extracted.length} IOC(s) extrait(s) !`);
    } else {
      alert("Aucun IOC trouvé.");
    }
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
    link.download = `STIX2.1_Report_${formData.clientName}.json`;
    link.click();
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleLogoUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => setLogoBase64(reader.result as string);
      reader.readAsDataURL(file);
    }
  };

  const handleSaveReport = async () => {
    if (!user) {
      alert("Veuillez vous connecter pour sauvegarder ce rapport.");
      return;
    }

    setLoading(true);
    const { error } = await supabase.from("reports").insert([
      {
        user_id: user.id,
        client_name: formData.clientName,
        analyst_name: formData.analystName,
        incident_date: formData.date,
        title: formData.title,
        severity: formData.severity,
        systems: formData.systems,
        description: formData.description,
        root_cause: formData.rootCause,
        recommendations: formData.recommendations,
        mitre_tactic: mitreTactic,
        mitre_technique: mitreTechnique,
        iocs: iocs,
        timeline_events: timelineEvents,
        logo_url: logoBase64,
        threat_actor: threatActor,
        threat_motivation: threatMotivation,
        threat_sophistication: threatSophistication,
        confidence_level: confidenceLevel,
        cvss_score: computedCvssScore,
        cvss_vector: cvssVectorString,
        report_type: reportType,
        iso_scores: isoChecks,
        pci_scores: pciChecks,
        iso_maturity_score: isoMaturityPercent,
        pci_maturity_score: pciMaturityPercent
      },
    ]);

    if (error) {
      alert(`Erreur lors de la sauvegarde : ${error.message}`);
    } else {
      alert("Rapport sauvegardé avec succès !");
      fetchReports();
    }
    setLoading(false);
  };

  const loadReport = (report: ReportItem) => {
    setFormData({
      clientName: report.client_name,
      analystName: report.analyst_name,
      date: report.incident_date,
      title: report.title,
      severity: report.severity,
      systems: report.systems || "",
      description: report.description || "",
      rootCause: report.root_cause || "",
      recommendations: report.recommendations || "",
    });
    setMitreTactic(report.mitre_tactic || "Credential Access");
    setMitreTechnique(report.mitre_technique || "T1110 - Brute Force");
    setIocs(report.iocs || []);
    setTimelineEvents(report.timeline_events || []);
    setLogoBase64(report.logo_url || "");
    setIsoChecks(report.iso_scores || {});
    setPciChecks(report.pci_scores || {});
    setReportType(report.report_type || "SOC Incident");
  };

  const deleteReport = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm("Voulez-vous vraiment supprimer ce rapport ?")) return;

    const { error } = await supabase.from("reports").delete().eq("id", id);
    if (error) alert(`Erreur : ${error.message}`);
    else fetchReports();
  };

  const selectedTacticObj = MITRE_TACTICS.find(t => t.name === mitreTactic);

  return (
    <>
      <style jsx global>{`
        @media print {
          body * { visibility: hidden; }
          #pdf-report, #pdf-report * { visibility: visible; }
          #pdf-report {
            position: absolute; left: 0; top: 0; width: 100%; margin: 0; padding: 20px;
            box-shadow: none !important; border: none !important;
          }
          .no-print { display: none !important; }
        }
      `}</style>

      <main className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
        
        {/* EN-TÊTE PANORAMIQUE DYNAMIQUE */}
        <header className="bg-slate-900/80 backdrop-blur border-b border-slate-800 px-8 py-4 flex flex-col md:flex-row items-center justify-between gap-4 sticky top-0 z-50 no-print">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-600/20 border border-blue-500/40 rounded-xl animate-pulse">
              <Shield className="w-7 h-7 text-blue-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                ReportShield <span className="text-[10px] bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded-full border border-blue-500/30">Pro SaaS</span>
              </h1>
              <p className="text-xs text-slate-400">Plateforme SOC, Threat Intelligence & Conformité</p>
            </div>
          </div>

          {/* BARRE DE NAVIGATION ANIMÉE */}
          <nav className="flex items-center gap-1 bg-slate-950/80 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => setActiveTab("incident")}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                activeTab === "incident" ? "bg-blue-600 text-white shadow-lg shadow-blue-600/30 scale-105" : "text-slate-400 hover:text-white"
              }`}
            >
              <Activity className="w-4 h-4" /> Incident & SOC
            </button>
            <button
              onClick={() => setActiveTab("cti")}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                activeTab === "cti" ? "bg-cyan-600 text-white shadow-lg shadow-cyan-600/30 scale-105" : "text-slate-400 hover:text-white"
              }`}
            >
              <Globe className="w-4 h-4" /> Threat Intel (CTI)
            </button>
            <button
              onClick={() => setActiveTab("compliance")}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                activeTab === "compliance" ? "bg-emerald-600 text-white shadow-lg shadow-emerald-600/30 scale-105" : "text-slate-400 hover:text-white"
              }`}
            >
              <Award className="w-4 h-4" /> Conformité ISO & PCI
            </button>
            <button
              onClick={() => setActiveTab("history")}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                activeTab === "history" ? "bg-purple-600 text-white shadow-lg shadow-purple-600/30 scale-105" : "text-slate-400 hover:text-white"
              }`}
            >
              <FolderOpen className="w-4 h-4" /> Rapports ({savedReports.length})
            </button>
          </nav>

          {/* ACTIONS & AUTH */}
          <div className="flex items-center gap-3">
            {user ? (
              <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg">
                <span className="text-xs text-slate-300">{user.email}</span>
                <button onClick={() => supabase.auth.signOut()} className="text-xs text-red-400 hover:text-red-300 p-1">
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <form onSubmit={async (e) => { e.preventDefault(); await supabase.auth.signInWithOtp({ email }); setMessage("Lien envoyé par email !"); }} className="flex items-center gap-2">
                <input type="email" placeholder="votre@email.com" value={email} onChange={(e) => setEmail(e.target.value)} required className="bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-xs text-white" />
                <button type="submit" className="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1 rounded text-xs flex items-center gap-1 cursor-pointer">
                  <LogIn className="w-3 h-3" />
                </button>
              </form>
            )}

            <button onClick={handleSaveReport} disabled={loading} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-4 py-2 rounded-lg text-xs cursor-pointer shadow-lg shadow-emerald-600/20">
              <Save className="w-4 h-4" /> Sauvegarder
            </button>

            <button onClick={() => window.print()} className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white font-medium px-4 py-2 rounded-lg text-xs cursor-pointer shadow-lg shadow-blue-600/20">
              <Printer className="w-4 h-4" /> Export PDF
            </button>
          </div>
        </header>

        {message && (
          <div className="mx-8 mt-4 p-3 bg-blue-950/60 border border-blue-500/50 rounded-lg text-xs text-blue-200 no-print flex items-center gap-2 animate-bounce">
            <CheckCircle className="w-4 h-4 text-blue-400" /> {message}
          </div>
        )}

        {/* CONTENU PANORAMIQUE EN 2 COLONNES (LARGEUR TOTALE) */}
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 p-8">
          
          {/* COLONNE GAUCHE (MODULES ANIMÉS) - SPAN 7 */}
          <div className="lg:col-span-7 space-y-6 no-print">

            {/* SÉLECTEUR DE TEMPLATE RAPIDE */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 flex items-center gap-2">
                <Sliders className="w-4 h-4 text-blue-400" /> Profil de Rapport :
              </span>
              <div className="flex gap-2">
                {["SOC Incident", "Audit / Pentest", "Bulletin CTI"].map((type) => (
                  <button
                    key={type}
                    onClick={() => setReportType(type)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-all ${
                      reportType === type ? "bg-slate-800 text-blue-400 border border-blue-500/40" : "text-slate-500 hover:text-slate-300"
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>

            {/* ONGLET 1 : INCIDENT & LOGIQUE SOC */}
            {activeTab === "incident" && (
              <div className="space-y-6 transition-all duration-300 animate-fadeIn">
                {/* INFORMATIONS DE L'INCIDENT */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-slate-800 pb-3 text-blue-400">
                    <FileText className="w-5 h-5" /> Fiche d'Incident Cyber
                  </h2>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">Logo Client (Optionnel)</label>
                      <input type="file" accept="image/*" onChange={handleLogoUpload} className="w-full text-xs text-slate-400 bg-slate-950 border border-slate-800 rounded-lg p-2 cursor-pointer" />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">Client / Organisation</label>
                      <input type="text" name="clientName" value={formData.clientName} onChange={handleChange} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">Analyste</label>
                      <input type="text" name="analystName" value={formData.analystName} onChange={handleChange} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">Date</label>
                      <input type="date" name="date" value={formData.date} onChange={handleChange} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">Sévérité</label>
                      <select name="severity" value={formData.severity} onChange={handleChange} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white">
                        <option value="Faible">Faible</option>
                        <option value="Moyenne">Moyenne</option>
                        <option value="Élevée">Élevée</option>
                        <option value="Critique">Critique</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">Titre de l'Incident</label>
                    <input type="text" name="title" value={formData.title} onChange={handleChange} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">Systèmes & Périmètre Impacté</label>
                    <input type="text" name="systems" value={formData.systems} onChange={handleChange} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">Description & Chronologie</label>
                    <textarea name="description" rows={3} value={formData.description} onChange={handleChange} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">Cause Racine (Root Cause)</label>
                    <textarea name="rootCause" rows={2} value={formData.rootCause} onChange={handleChange} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">Recommandations</label>
                    <textarea name="recommendations" rows={3} value={formData.recommendations} onChange={handleChange} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                  </div>
                </div>

                {/* PARSEUR & IOCS */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h2 className="text-lg font-semibold flex items-center gap-2 text-red-400">
                      <List className="w-5 h-5" /> Indicateurs de Compromission (IOCs)
                    </h2>
                    <button type="button" onClick={handleExportSTIX} className="bg-slate-800 hover:bg-slate-700 text-xs text-white px-3 py-1.5 rounded-lg flex items-center gap-1 cursor-pointer border border-slate-700">
                      <Download className="w-3.5 h-3.5 text-cyan-400" /> Export STIX 2.1
                    </button>
                  </div>

                  <div className="space-y-2 bg-slate-950/60 p-3 border border-slate-800 rounded-xl">
                    <label className="block text-xs font-semibold text-slate-300 flex items-center gap-1">
                      <Wand2 className="w-3.5 h-3.5 text-yellow-400" /> Extracteur Automatique de Logs
                    </label>
                    <textarea rows={2} placeholder="Collez vos logs bruts ici..." value={rawLogsText} onChange={(e) => setRawLogsText(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                    <button type="button" onClick={handleParseLogs} className="w-full bg-yellow-600 hover:bg-yellow-500 text-xs font-semibold text-slate-950 py-1.5 rounded-lg cursor-pointer">
                      Parser les logs & Extraire IOCs
                    </button>
                  </div>

                  {iocs.length > 0 && (
                    <div className="space-y-2">
                      {iocs.map((ioc) => (
                        <div key={ioc.id} className="flex items-center justify-between bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-xs">
                          <div>
                            <span className="font-bold text-red-400 mr-2">[{ioc.type}]</span>
                            <span className="font-mono text-slate-200">{ioc.value}</span>
                          </div>
                          <button onClick={() => setIocs(iocs.filter(i => i.id !== ioc.id))} className="text-slate-500 hover:text-red-400 p-1">
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ONGLET 2 : THREAT INTEL (CTI) & MITRE ATT&CK */}
            {activeTab === "cti" && (
              <div className="space-y-6 transition-all duration-300 animate-fadeIn">
                {/* CALCULATEUR CVSS */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h2 className="text-lg font-semibold flex items-center gap-2 text-amber-400">
                      <Calculator className="w-5 h-5" /> Score CVSS v3.1
                    </h2>
                    <span className="text-xs font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-700/60 px-3 py-1 rounded-lg">
                      Score : {computedCvssScore} / 10
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <label className="block text-[10px] text-slate-400 mb-1">Vecteur d'Attaque (AV)</label>
                      <select value={cvssAV} onChange={(e) => setCvssAV(parseFloat(e.target.value))} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-white">
                        <option value={0.85}>Réseau (Network)</option>
                        <option value={0.62}>Adjacent</option>
                        <option value={0.55}>Local</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400 mb-1">Complexité (AC)</label>
                      <select value={cvssAC} onChange={(e) => setCvssAC(parseFloat(e.target.value))} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-white">
                        <option value={0.77}>Basse (Low)</option>
                        <option value={0.44}>Haute (High)</option>
                      </select>
                    </div>
                  </div>
                </div>

                {/* THREAT INTEL CTI */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-slate-800 pb-3 text-cyan-400">
                    <Globe className="w-5 h-5" /> Threat Intelligence & Attribution
                  </h2>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">Acteur Suspecté / Groupe</label>
                      <input type="text" value={threatActor} onChange={(e) => setThreatActor(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">Indice de Confiance</label>
                      <select value={confidenceLevel} onChange={(e) => setConfidenceLevel(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white">
                        <option value="Faible">Faible</option>
                        <option value="Moyenne">Moyenne</option>
                        <option value="Élevée">Élevée</option>
                      </select>
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-slate-800 pb-3 text-purple-400">
                    <Crosshair className="w-5 h-5" /> Framework MITRE ATT&CK
                  </h2>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">Tactique</label>
                      <select value={mitreTactic} onChange={(e) => setMitreTactic(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white">
                        {MITRE_TACTICS.map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">Technique</label>
                      <select value={mitreTechnique} onChange={(e) => setMitreTechnique(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white">
                        {selectedTacticObj?.techniques.map((tech) => <option key={tech} value={tech}>{tech}</option>)}
                      </select>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* ONGLET 3 : CONFORMITÉ ISO 27001 & PCI DSS */}
            {activeTab === "compliance" && (
              <div className="space-y-6 transition-all duration-300 animate-fadeIn">
                {/* ISO 27001 */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h2 className="text-lg font-semibold flex items-center gap-2 text-emerald-400">
                      <Award className="w-5 h-5" /> Auto-Évaluation ISO 27001:2022
                    </h2>
                    <span className="text-xs font-bold text-emerald-400 bg-emerald-950 border border-emerald-800 px-3 py-1 rounded-lg">
                      Maturité : {isoMaturityPercent}%
                    </span>
                  </div>

                  <div className="space-y-2">
                    {ISO_CONTROLS.map((ctrl) => (
                      <label key={ctrl.id} className="flex items-center gap-3 p-2.5 bg-slate-950/80 rounded-xl border border-slate-800/80 cursor-pointer hover:border-emerald-500/40 transition">
                        <input type="checkbox" checked={!!isoChecks[ctrl.id]} onChange={(e) => setIsoChecks({ ...isoChecks, [ctrl.id]: e.target.checked })} className="w-4 h-4 accent-emerald-500 rounded cursor-pointer" />
                        <span className="text-xs text-slate-200"><strong className="text-emerald-400">[{ctrl.id}]</strong> {ctrl.label}</span>
                      </label>
                    ))}
                  </div>
                </div>

                {/* PCI DSS v4.0 */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h2 className="text-lg font-semibold flex items-center gap-2 text-blue-400">
                      <CheckSquare className="w-5 h-5" /> Auto-Évaluation PCI DSS v4.0
                    </h2>
                    <span className="text-xs font-bold text-blue-400 bg-blue-950 border border-blue-800 px-3 py-1 rounded-lg">
                      Maturité : {pciMaturityPercent}%
                    </span>
                  </div>

                  <div className="space-y-2">
                    {PCI_CONTROLS.map((ctrl) => (
                      <label key={ctrl.id} className="flex items-center gap-3 p-2.5 bg-slate-950/80 rounded-xl border border-slate-800/80 cursor-pointer hover:border-blue-500/40 transition">
                        <input type="checkbox" checked={!!pciChecks[ctrl.id]} onChange={(e) => setPciChecks({ ...pciChecks, [ctrl.id]: e.target.checked })} className="w-4 h-4 accent-blue-500 rounded cursor-pointer" />
                        <span className="text-xs text-slate-200"><strong className="text-blue-400">[{ctrl.id}]</strong> {ctrl.label}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ONGLET 4 : HISTORIQUE RAPPORTS */}
            {activeTab === "history" && (
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4 transition-all duration-300 animate-fadeIn">
                <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-slate-800 pb-3">
                  <FolderOpen className="w-5 h-5 text-purple-400" /> Mes Rapports Sauvegardés ({savedReports.length})
                </h2>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-96 overflow-y-auto pr-1">
                  {savedReports.map((report) => (
                    <div key={report.id} onClick={() => loadReport(report)} className="p-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-xl cursor-pointer transition flex items-center justify-between group">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-semibold text-xs text-white">{report.client_name}</span>
                          <span className="px-2 py-0.5 rounded text-[10px] bg-blue-600 text-white font-bold">{report.severity}</span>
                        </div>
                        <p className="text-xs text-slate-300 line-clamp-1">{report.title}</p>
                      </div>
                      <button onClick={(e) => deleteReport(report.id, e)} className="p-1 text-slate-500 hover:text-red-400">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* COLONNE DROITE (APERÇU DU DOCUMENT PDF FIXE & INTERACTIF) - SPAN 5 */}
          <div className="lg:col-span-5 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-2xl flex flex-col items-center h-fit sticky top-24">
            <div className="w-full flex items-center justify-between mb-3 no-print">
              <span className="text-xs font-semibold text-slate-400 flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-400" /> Rendus PDF Dynamique
              </span>
              <span className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded-full">
                Mise à jour en direct
              </span>
            </div>
            
            {/* DOCUMENT CANONIQUE D'IMPRESSION */}
            <div id="pdf-report" className="w-full bg-white text-slate-900 p-8 rounded-xl shadow-2xl border border-slate-200 text-sm space-y-5">
              
              {/* LOGO & TITRE */}
              <div className="flex justify-between items-start border-b-2 border-slate-900 pb-4">
                <div className="flex items-center gap-3">
                  {logoBase64 && <img src={logoBase64} alt="Logo Client" className="h-10 w-auto max-w-[100px] object-contain" />}
                  <div>
                    <h1 className="text-lg font-bold uppercase tracking-wide text-slate-900">Rapport Cyber : {reportType}</h1>
                    <p className="text-[10px] text-slate-500">Document Officiel d'Audit & Investigation</p>
                  </div>
                </div>
                <div className="text-right text-[10px] text-slate-600">
                  <p><strong>Client :</strong> {formData.clientName}</p>
                  <p><strong>Date :</strong> {formData.date}</p>
                </div>
              </div>

              {/* JOUGES DE MATURITÉ PME SUR RAPPORT */}
              <div className="grid grid-cols-2 gap-3 border p-2.5 rounded-lg bg-slate-50 border-slate-200 text-xs">
                <div>
                  <div className="flex justify-between font-bold mb-1 text-[10px]">
                    <span className="text-emerald-800">ISO 27001</span>
                    <span className="text-emerald-900">{isoMaturityPercent}%</span>
                  </div>
                  <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-emerald-600 h-full transition-all duration-500" style={{ width: `${isoMaturityPercent}%` }}></div>
                  </div>
                </div>

                <div>
                  <div className="flex justify-between font-bold mb-1 text-[10px]">
                    <span className="text-blue-800">PCI DSS v4.0</span>
                    <span className="text-blue-900">{pciMaturityPercent}%</span>
                  </div>
                  <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-blue-600 h-full transition-all duration-500" style={{ width: `${pciMaturityPercent}%` }}></div>
                  </div>
                </div>
              </div>

              {/* SÉVÉRITÉ ET INCIDENT */}
              <div className="bg-slate-100 p-3 rounded-lg border border-slate-200 flex justify-between items-center">
                <div>
                  <span className="text-[10px] text-slate-500 block uppercase font-semibold">Objet</span>
                  <h2 className="text-sm font-bold text-slate-900">{formData.title}</h2>
                </div>
                <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold text-white ${
                  formData.severity === "Critique" ? "bg-red-600" :
                  formData.severity === "Élevée" ? "bg-orange-500" : "bg-green-600"
                }`}>
                  {formData.severity}
                </span>
              </div>

              {/* PÉRIMÈTRE */}
              <div>
                <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">Périmètre Impacté</h3>
                <p className="text-xs text-slate-800 bg-slate-100 p-2 rounded">{formData.systems}</p>
              </div>

              {/* RECOMMANDATIONS */}
              <div>
                <h3 className="text-[10px] font-bold uppercase text-slate-700 border-b pb-1 mb-1">Recommandations & Plan d'Action</h3>
                <p className="text-xs text-slate-800 whitespace-pre-line bg-green-50 text-green-900 p-2.5 rounded border border-green-200 font-mono">
                  {formData.recommendations}
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>
    </>
  );
}