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
  History
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
  created_at: string;
}

// Référence MITRE ATT&CK
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

export default function Home() {
  const [user, setUser] = useState<any>(null);
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [savedReports, setSavedReports] = useState<ReportItem[]>([]);

  // Modèle de rapport (SOC, Pentest, CTI)
  const [reportType, setReportType] = useState<string>("SOC Incident");

  // États du formulaire principal
  const [logoBase64, setLogoBase64] = useState<string>("");
  const [mitreTactic, setMitreTactic] = useState<string>("Credential Access");
  const [mitreTechnique, setMitreTechnique] = useState<string>("T1110 - Brute Force");
  
  // États Threat Intelligence (CTI)
  const [threatActor, setThreatActor] = useState<string>("Inconnu / Non Attribué");
  const [threatMotivation, setThreatMotivation] = useState<string>("Gain Financier (Ransomware / Extorsion)");
  const [threatSophistication, setThreatSophistication] = useState<string>("Moyenne (Cybercriminalité organisée)");
  const [confidenceLevel, setConfidenceLevel] = useState<string>("Moyenne");

  // Calculateur CVSS v3.1 Métriques de base
  const [cvssAV, setCvssAV] = useState<number>(0.85); // Network
  const [cvssAC, setCvssAC] = useState<number>(0.77); // Low
  const [cvssPR, setCvssPR] = useState<number>(0.85); // None
  const [cvssUI, setCvssUI] = useState<number>(0.85); // None
  const [cvssImpactC, setCvssImpactC] = useState<number>(0.56); // High
  const [cvssImpactI, setCvssImpactI] = useState<number>(0.56); // High
  const [cvssImpactA, setCvssImpactA] = useState<number>(0.56); // High

  // Parseur de logs bruts pour extraction IOC
  const [rawLogsText, setRawLogsText] = useState<string>("");

  const [iocs, setIocs] = useState<IOCItem[]>([
    { id: "1", type: "IP Address", value: "192.168.1.105", description: "IP source de l'attaque force brute" },
    { id: "2", type: "Hash SHA256", value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", description: "Payload malveillant isolé" }
  ]);
  const [newIoc, setNewIoc] = useState({ type: "IP Address", value: "", description: "" });

  // Événements de la chronologie (Timeline)
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([
    { id: "1", time: "08:15:00", title: "Détection brute force", description: "Alerte SIEM générée suite à 500 tentatives d'authentification échouées sur le VPN." },
    { id: "2", time: "08:22:30", title: "Accès compromis", description: "Connexion réussie depuis l'IP distante 192.168.1.105." },
    { id: "3", time: "08:35:10", title: "Élévation de privilèges", description: "Exécution du binaire malveillant et création d'un compte administrateur local." }
  ]);
  const [newEvent, setNewEvent] = useState({ time: "", title: "", description: "" });

  const [formData, setFormData] = useState({
    clientName: "Entreprise Client SA",
    analystName: "Analyste Cyber",
    date: new Date().toISOString().split("T")[0],
    title: "Suspicion d'intrusion et activité anormale",
    severity: "Élevée",
    systems: "Serveur Principal, Pare-feu de bordure",
    description: "Détection de multiples tentatives d'authentification échouées suivies d'une élévation de privilèges non autorisée sur le serveur de fichiers.",
    rootCause: "Compromission de mot de passe via une attaque de force brute sur un accès VPN non protégé par MFA.",
    recommendations: "1. Activer l'authentification multifacteur (MFA) obligatoire.\n2. Isoler la machine impactée et réinitialiser les identifiants.\n3. Mettre à jour les règles du pare-feu.",
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

  // Calcul du score CVSS simplifié
  const calculateCVSSScore = (): number => {
    const iss = 1 - (1 - cvssImpactC) * (1 - cvssImpactI) * (1 - cvssImpactA);
    const impact = 6.42 * iss;
    const exploitability = 8.22 * cvssAV * cvssAC * cvssPR * cvssUI;

    if (impact <= 0) return 0;
    const score = Math.min(10, Math.ceil((impact + exploitability) * 10) / 10);
    return score;
  };

  const computedCvssScore = calculateCVSSScore();
  const cvssVectorString = `CVSS:3.1/AV:${cvssAV === 0.85 ? 'N' : cvssAV === 0.62 ? 'A' : cvssAV === 0.55 ? 'L' : 'P'}/AC:${cvssAC === 0.77 ? 'L' : 'H'}/PR:${cvssPR === 0.85 ? 'N' : cvssPR === 0.62 ? 'L' : 'H'}/UI:${cvssUI === 0.85 ? 'N' : 'R'}/C:${cvssImpactC === 0.56 ? 'H' : cvssImpactC === 0.22 ? 'L' : 'N'}/I:${cvssImpactI === 0.56 ? 'H' : cvssImpactI === 0.22 ? 'L' : 'N'}/A:${cvssImpactA === 0.56 ? 'H' : cvssImpactA === 0.22 ? 'L' : 'N'}`;

  // Extraction automatique d'IOCs par Regex
  const handleParseLogs = () => {
    if (!rawLogsText) return;

    const extracted: IOCItem[] = [];
    
    // Regex IPs
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const ips = Array.from(new Set(rawLogsText.match(ipRegex) || []));
    ips.forEach(ip => {
      if (ip !== "127.0.0.1" && ip !== "0.0.0.0") {
        extracted.push({ id: Math.random().toString(), type: "IP Address", value: ip, description: "Extrait automatiquement des logs" });
      }
    });

    // Regex Hashes SHA256
    const sha256Regex = /\b[A-Fa-f0-9]{64}\b/g;
    const hashes = Array.from(new Set(rawLogsText.match(sha256Regex) || []));
    hashes.forEach(hash => {
      extracted.push({ id: Math.random().toString(), type: "Hash SHA256", value: hash, description: "Extrait automatiquement des logs" });
    });

    // Regex URLs / Domaines
    const domainRegex = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;
    const domains = Array.from(new Set(rawLogsText.match(domainRegex) || []));
    domains.forEach(domain => {
      if (!domain.endsWith(".local") && !domain.endsWith(".internal")) {
        extracted.push({ id: Math.random().toString(), type: "Domain / URL", value: domain, description: "Extrait automatiquement des logs" });
      }
    });

    if (extracted.length > 0) {
      setIocs([...iocs, ...extracted]);
      setRawLogsText("");
      alert(`${extracted.length} IOC(s) extrait(s) avec succès !`);
    } else {
      alert("Aucun IOC pertinent trouvé dans le texte fourni.");
    }
  };

  // Exportation STIX 2.1 JSON
  const handleExportSTIX = () => {
    const stixBundle = {
      type: "bundle",
      id: `bundle--${crypto.randomUUID()}`,
      objects: [
        {
          type: "report",
          spec_version: "2.1",
          id: `report--${crypto.randomUUID()}`,
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          name: formData.title,
          description: formData.description,
          published: new Date().toISOString(),
          object_refs: iocs.map(ioc => `indicator--${ioc.id}`)
        },
        ...iocs.map(ioc => ({
          type: "indicator",
          spec_version: "2.1",
          id: `indicator--${ioc.id}`,
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          pattern: `[${ioc.type === 'IP Address' ? 'ipv4-addr:value' : ioc.type === 'Hash SHA256' ? 'file:hashes.\'SHA-256\'' : 'domain-name:value'} = '${ioc.value}']`,
          pattern_type: "stix",
          valid_from: new Date().toISOString(),
          description: ioc.description
        }))
      ]
    };

    const blob = new Blob([JSON.stringify(stixBundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `STIX2.1_Report_${formData.clientName.replace(/\s+/g, "_")}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleLogoUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setLogoBase64(reader.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleAddIoc = () => {
    if (!newIoc.value) return;
    setIocs([...iocs, { id: Date.now().toString(), ...newIoc }]);
    setNewIoc({ type: "IP Address", value: "", description: "" });
  };

  const handleRemoveIoc = (id: string) => {
    setIocs(iocs.filter(ioc => ioc.id !== id));
  };

  const handleAddTimelineEvent = () => {
    if (!newEvent.title || !newEvent.time) return;
    setTimelineEvents([...timelineEvents, { id: Date.now().toString(), ...newEvent }]);
    setNewEvent({ time: "", title: "", description: "" });
  };

  const handleRemoveTimelineEvent = (id: string) => {
    setTimelineEvents(timelineEvents.filter(e => e.id !== id));
  };

  const handlePrint = () => {
    window.print();
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage("");

    const { error } = await supabase.auth.signInWithOtp({ email });

    if (error) {
      setMessage(`Erreur: ${error.message}`);
    } else {
      setMessage("Un lien de connexion vous a été envoyé par email !");
    }
    setLoading(false);
  };

  const handleLogout = async () => {
    await supabase.auth.signOut();
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
        report_type: reportType
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
    setThreatActor(report.threat_actor || "Inconnu / Non Attribué");
    setThreatMotivation(report.threat_motivation || "Gain Financier (Ransomware / Extorsion)");
    setThreatSophistication(report.threat_sophistication || "Moyenne (Cybercriminalité organisée)");
    setConfidenceLevel(report.confidence_level || "Moyenne");
    setReportType(report.report_type || "SOC Incident");
  };

  const deleteReport = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm("Voulez-vous vraiment supprimer ce rapport ?")) return;

    const { error } = await supabase.from("reports").delete().eq("id", id);
    if (error) {
      alert(`Erreur lors de la suppression : ${error.message}`);
    } else {
      fetchReports();
    }
  };

  const selectedTacticObj = MITRE_TACTICS.find(t => t.name === mitreTactic);

  return (
    <>
      <style jsx global>{`
        @media print {
          body * {
            visibility: hidden;
          }
          #pdf-report, #pdf-report * {
            visibility: visible;
          }
          #pdf-report {
            position: absolute;
            left: 0;
            top: 0;
            width: 100%;
            margin: 0;
            padding: 20px;
            box-shadow: none !important;
            border: none !important;
          }
          .no-print {
            display: none !important;
          }
        }
      `}</style>

      <main className="min-h-screen bg-slate-900 text-slate-100 p-6 md:p-12">
        {/* EN-TÊTE */}
        <header className="max-w-6xl mx-auto mb-8 flex flex-col md:flex-row items-center justify-between border-b border-slate-800 pb-6 gap-4 no-print">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-500" />
            <div>
              <h1 className="text-2xl font-bold text-white">ReportShield</h1>
              <p className="text-xs text-slate-400">Plateforme de Gestion & Structuration d'Incidents Cyber</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {user ? (
              <div className="flex items-center gap-3 bg-slate-800 border border-slate-700 px-4 py-2 rounded-lg">
                <span className="text-xs text-slate-300">{user.email}</span>
                <button
                  onClick={handleLogout}
                  className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1 cursor-pointer"
                >
                  <LogOut className="w-3 h-3" /> Déconnexion
                </button>
              </div>
            ) : (
              <form onSubmit={handleLogin} className="flex items-center gap-2">
                <input
                  type="email"
                  placeholder="votre@email.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-blue-500"
                />
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-blue-600 hover:bg-blue-500 text-white font-medium px-3 py-1.5 rounded text-xs flex items-center gap-1 cursor-pointer"
                >
                  <LogIn className="w-3 h-3" /> Connexion
                </button>
              </form>
            )}

            <button
              onClick={handleSaveReport}
              disabled={loading}
              className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-4 py-2 rounded-lg text-sm transition cursor-pointer"
            >
              <Save className="w-4 h-4" /> Sauvegarder
            </button>

            <button
              onClick={handlePrint}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white font-medium px-4 py-2 rounded-lg text-sm transition cursor-pointer"
            >
              <Printer className="w-4 h-4" /> Export PDF
            </button>
          </div>
        </header>

        {message && (
          <div className="max-w-6xl mx-auto mb-6 p-3 bg-blue-900/50 border border-blue-500 rounded-lg text-xs text-blue-200 no-print flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-blue-400" /> {message}
          </div>
        )}

        <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* COLONNE GAUCHE : FORMULAIRES ETOUTILS */}
          <div className="space-y-6 no-print">

            {/* SÉLECTEUR DE TEMPLATE / MODÈLE */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 shadow-xl flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-2">
                <Layers className="w-4 h-4 text-blue-400" /> Modèle de Rapport :
              </span>
              <div className="flex gap-2">
                {["SOC Incident", "Audit / Pentest", "Bulletin CTI"].map((type) => (
                  <button
                    key={type}
                    onClick={() => setReportType(type)}
                    className={`px-3 py-1.5 rounded text-xs font-medium cursor-pointer transition ${
                      reportType === type
                        ? "bg-blue-600 text-white"
                        : "bg-slate-900 text-slate-400 hover:bg-slate-700"
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>
            
            {/* 1. INFORMATIONS GÉNÉRALES & LOGO */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4">
              <h2 className="text-xl font-semibold mb-4 flex items-center gap-2 border-b border-slate-700 pb-2">
                <FileText className="w-5 h-5 text-blue-400" /> Informations Générales
              </h2>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1 flex items-center gap-1">
                  <ImageIcon className="w-3.5 h-3.5" /> Logo de l'Entreprise / Client
                </label>
                <input
                  type="file"
                  accept="image/*"
                  onChange={handleLogoUpload}
                  className="w-full text-xs text-slate-400 bg-slate-900 border border-slate-700 rounded p-2 cursor-pointer"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Nom du Client / Entreprise</label>
                  <input
                    type="text"
                    name="clientName"
                    value={formData.clientName}
                    onChange={handleChange}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Analyste / Intervenant</label>
                  <input
                    type="text"
                    name="analystName"
                    value={formData.analystName}
                    onChange={handleChange}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Date</label>
                  <input
                    type="date"
                    name="date"
                    value={formData.date}
                    onChange={handleChange}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Niveau de Sévérité</label>
                  <select
                    name="severity"
                    value={formData.severity}
                    onChange={handleChange}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="Faible">Faible</option>
                    <option value="Moyenne">Moyenne</option>
                    <option value="Élevée">Élevée</option>
                    <option value="Critique">Critique</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Titre de l'Incident / Vulnérabilité</label>
                <input
                  type="text"
                  name="title"
                  value={formData.title}
                  onChange={handleChange}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Systèmes Impactés</label>
                <input
                  type="text"
                  name="systems"
                  value={formData.systems}
                  onChange={handleChange}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Description Détaillée</label>
                <textarea
                  name="description"
                  rows={3}
                  value={formData.description}
                  onChange={handleChange}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Cause Racine (Root Cause)</label>
                <textarea
                  name="rootCause"
                  rows={2}
                  value={formData.rootCause}
                  onChange={handleChange}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Recommandations</label>
                <textarea
                  name="recommendations"
                  rows={3}
                  value={formData.recommendations}
                  onChange={handleChange}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            {/* 2. CALCULATEUR CVSS v3.1 */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-700 pb-2">
                <h2 className="text-lg font-semibold flex items-center gap-2 text-amber-400">
                  <Calculator className="w-5 h-5" /> Score CVSS v3.1
                </h2>
                <span className="text-xs font-mono font-bold bg-amber-950 text-amber-400 border border-amber-700 px-2 py-1 rounded">
                  Score : {computedCvssScore} / 10
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <label className="block text-[10px] text-slate-400 mb-1">Vecteur d'Attaque (AV)</label>
                  <select value={cvssAV} onChange={(e) => setCvssAV(parseFloat(e.target.value))} className="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-white">
                    <option value={0.85}>Réseau (Network)</option>
                    <option value={0.62}>Adjacent</option>
                    <option value={0.55}>Local</option>
                    <option value={0.20}>Physique</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[10px] text-slate-400 mb-1">Complexité (AC)</label>
                  <select value={cvssAC} onChange={(e) => setCvssAC(parseFloat(e.target.value))} className="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-white">
                    <option value={0.77}>Basse (Low)</option>
                    <option value={0.44}>Haute (High)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[10px] text-slate-400 mb-1">Privilèges Requis (PR)</label>
                  <select value={cvssPR} onChange={(e) => setCvssPR(parseFloat(e.target.value))} className="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-white">
                    <option value={0.85}>Aucun (None)</option>
                    <option value={0.62}>Bas (Low)</option>
                    <option value={0.27}>Haut (High)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[10px] text-slate-400 mb-1">Interaction Utilisateur (UI)</label>
                  <select value={cvssUI} onChange={(e) => setCvssUI(parseFloat(e.target.value))} className="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-white">
                    <option value={0.85}>Aucune (None)</option>
                    <option value={0.62}>Requise (Required)</option>
                  </select>
                </div>
              </div>

              <div className="p-2 bg-slate-900 border border-slate-700 rounded font-mono text-[10px] text-slate-400 break-all">
                {cvssVectorString}
              </div>
            </div>

            {/* 3. PARSEUR AUTOMATIQUE ET EXPORT STIX DES IOCs */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-700 pb-2">
                <h2 className="text-lg font-semibold flex items-center gap-2 text-red-400">
                  <List className="w-5 h-5" /> Indicateurs de Compromission (IOCs)
                </h2>
                <button
                  type="button"
                  onClick={handleExportSTIX}
                  className="bg-slate-700 hover:bg-slate-600 text-xs text-white px-2.5 py-1 rounded flex items-center gap-1 cursor-pointer"
                >
                  <Download className="w-3 h-3 text-cyan-400" /> Export STIX 2.1
                </button>
              </div>

              {/* Extraction par Regex */}
              <div className="space-y-2 bg-slate-900/50 p-3 border border-slate-700 rounded-lg">
                <label className="block text-xs font-semibold text-slate-300 flex items-center gap-1">
                  <Wand2 className="w-3.5 h-3.5 text-yellow-400" /> Extracteur Automatique de Logs
                </label>
                <textarea
                  rows={2}
                  placeholder="Collez des logs bruts, en-têtes d'emails, ou commandes ici..."
                  value={rawLogsText}
                  onChange={(e) => setRawLogsText(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-white"
                />
                <button
                  type="button"
                  onClick={handleParseLogs}
                  className="w-full bg-yellow-600 hover:bg-yellow-500 text-xs font-medium text-slate-950 py-1.5 rounded cursor-pointer"
                >
                  Parser les logs & Extraire les IOCs
                </button>
              </div>

              {/* Formulaire Manuel */}
              <div className="space-y-2">
                <div className="grid grid-cols-3 gap-2">
                  <select
                    value={newIoc.type}
                    onChange={(e) => setNewIoc({ ...newIoc, type: e.target.value })}
                    className="bg-slate-900 border border-slate-700 rounded p-1.5 text-xs text-white"
                  >
                    <option value="IP Address">Adresse IP</option>
                    <option value="Domain / URL">Domaine / URL</option>
                    <option value="Hash SHA256">Hash SHA256</option>
                    <option value="Hash MD5">Hash MD5</option>
                    <option value="File / Registry">Fichier / Registre</option>
                  </select>

                  <input
                    type="text"
                    placeholder="Valeur"
                    value={newIoc.value}
                    onChange={(e) => setNewIoc({ ...newIoc, value: e.target.value })}
                    className="bg-slate-900 border border-slate-700 rounded p-1.5 text-xs text-white"
                  />

                  <input
                    type="text"
                    placeholder="Description"
                    value={newIoc.description}
                    onChange={(e) => setNewIoc({ ...newIoc, description: e.target.value })}
                    className="bg-slate-900 border border-slate-700 rounded p-1.5 text-xs text-white"
                  />
                </div>

                <button
                  type="button"
                  onClick={handleAddIoc}
                  className="w-full bg-slate-700 hover:bg-slate-600 text-xs text-white py-1.5 rounded flex items-center justify-center gap-1 cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" /> Ajouter l'IOC
                </button>
              </div>

              {iocs.length > 0 && (
                <div className="space-y-1.5 pt-2">
                  {iocs.map((ioc) => (
                    <div key={ioc.id} className="flex items-center justify-between bg-slate-900 p-2 rounded text-xs border border-slate-700">
                      <div>
                        <span className="font-bold text-red-400 mr-2">[{ioc.type}]</span>
                        <span className="font-mono text-slate-200">{ioc.value}</span>
                        {ioc.description && <span className="text-slate-400 block text-[10px]">{ioc.description}</span>}
                      </div>
                      <button
                        type="button"
                        onClick={() => handleRemoveIoc(ioc.id)}
                        className="text-slate-500 hover:text-red-400 p-1"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* 4. CHRONOLOGIE DE L'INCIDENT (TIMELINE) */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4">
              <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-slate-700 pb-2 text-indigo-400">
                <History className="w-5 h-5" /> Chronologie de l'Incident
              </h2>

              <div className="grid grid-cols-3 gap-2">
                <input
                  type="text"
                  placeholder="Heure (ex: 14:30)"
                  value={newEvent.time}
                  onChange={(e) => setNewEvent({ ...newEvent, time: e.target.value })}
                  className="bg-slate-900 border border-slate-700 rounded p-1.5 text-xs text-white"
                />
                <input
                  type="text"
                  placeholder="Événement"
                  value={newEvent.title}
                  onChange={(e) => setNewEvent({ ...newEvent, title: e.target.value })}
                  className="col-span-2 bg-slate-900 border border-slate-700 rounded p-1.5 text-xs text-white"
                />
              </div>

              <textarea
                placeholder="Description détaillée de l'événement..."
                value={newEvent.description}
                onChange={(e) => setNewEvent({ ...newEvent, description: e.target.value })}
                className="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-xs text-white"
              />

              <button
                type="button"
                onClick={handleAddTimelineEvent}
                className="w-full bg-indigo-600 hover:bg-indigo-500 text-xs text-white py-1.5 rounded flex items-center justify-center gap-1 cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" /> Ajouter un Événement
              </button>

              {timelineEvents.length > 0 && (
                <div className="space-y-2 pt-2">
                  {timelineEvents.map((item) => (
                    <div key={item.id} className="flex items-start justify-between bg-slate-900 p-2.5 rounded text-xs border border-slate-700">
                      <div>
                        <span className="font-bold text-indigo-400 mr-2">[{item.time}]</span>
                        <span className="font-semibold text-white">{item.title}</span>
                        <p className="text-slate-400 text-[11px] mt-0.5">{item.description}</p>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleRemoveTimelineEvent(item.id)}
                        className="text-slate-500 hover:text-red-400 p-1"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* 5. THREAT INTELLIGENCE (CTI) */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4">
              <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-slate-700 pb-2 text-cyan-400">
                <Globe className="w-5 h-5" /> Threat Intelligence (CTI)
              </h2>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Acteur de la Menace / Groupe</label>
                  <input
                    type="text"
                    value={threatActor}
                    onChange={(e) => setThreatActor(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Indice de Confiance</label>
                  <select
                    value={confidenceLevel}
                    onChange={(e) => setConfidenceLevel(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Faible">Faible</option>
                    <option value="Moyenne">Moyenne</option>
                    <option value="Élevée">Élevée</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Motivation</label>
                  <select
                    value={threatMotivation}
                    onChange={(e) => setThreatMotivation(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Gain Financier (Ransomware / Extorsion)">Gain Financier</option>
                    <option value="Espionnage Industriel / Étatique">Espionnage</option>
                    <option value="Sabotage / Destructif">Sabotage</option>
                    <option value="Hacktivisme">Hacktivisme</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Sophistication</label>
                  <select
                    value={threatSophistication}
                    onChange={(e) => setThreatSophistication(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Faible (Attaque basique automatisée)">Faible</option>
                    <option value="Moyenne (Cybercriminalité organisée)">Moyenne</option>
                    <option value="Élevée (APT / Groupe Étatique)">Élevée (APT)</option>
                  </select>
                </div>
              </div>
            </div>

            {/* 6. FRAMEWORK MITRE ATT&CK */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4">
              <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-slate-700 pb-2 text-purple-400">
                <Crosshair className="w-5 h-5" /> Framework MITRE ATT&CK
              </h2>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Tactique</label>
                  <select
                    value={mitreTactic}
                    onChange={(e) => {
                      setMitreTactic(e.target.value);
                      const tactic = MITRE_TACTICS.find(t => t.name === e.target.value);
                      if (tactic) setMitreTechnique(tactic.techniques[0]);
                    }}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-white focus:outline-none focus:border-purple-500"
                  >
                    {MITRE_TACTICS.map((t) => (
                      <option key={t.name} value={t.name}>{t.name}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Technique</label>
                  <select
                    value={mitreTechnique}
                    onChange={(e) => setMitreTechnique(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-white focus:outline-none focus:border-purple-500"
                  >
                    {selectedTacticObj?.techniques.map((tech) => (
                      <option key={tech} value={tech}>{tech}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {/* HISTORIQUE */}
            {user && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4">
                <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-slate-700 pb-2">
                  <FolderOpen className="w-5 h-5 text-emerald-400" /> Mes Rapports Sauvegardés ({savedReports.length})
                </h2>

                {savedReports.length === 0 ? (
                  <p className="text-xs text-slate-400 italic">Aucun rapport sauvegardé.</p>
                ) : (
                  <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                    {savedReports.map((report) => (
                      <div
                        key={report.id}
                        onClick={() => loadReport(report)}
                        className="p-3 bg-slate-900/80 hover:bg-slate-700/60 border border-slate-700/80 rounded-lg cursor-pointer transition flex items-center justify-between group"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-xs text-white">{report.client_name}</span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold text-white ${
                              report.severity === "Critique" ? "bg-red-600" :
                              report.severity === "Élevée" ? "bg-orange-500" :
                              report.severity === "Moyenne" ? "bg-yellow-600" : "bg-green-600"
                            }`}>
                              {report.severity}
                            </span>
                          </div>
                          <p className="text-xs text-slate-300 line-clamp-1">{report.title}</p>
                          <p className="text-[10px] text-slate-500 flex items-center gap-1">
                            <Clock className="w-3 h-3" /> {new Date(report.created_at).toLocaleDateString("fr-FR")}
                          </p>
                        </div>

                        <button
                          onClick={(e) => deleteReport(report.id, e)}
                          className="p-1 text-slate-500 hover:text-red-400 opacity-0 group-hover:opacity-100 transition"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* COLONNE DROITE : APERÇU PDF DYNAMIQUE */}
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl flex flex-col items-center h-fit">
            <span className="text-xs text-slate-400 mb-2 no-print">Aperçu du document PDF [{reportType}]</span>
            
            <div
              id="pdf-report"
              className="w-full bg-white text-slate-900 p-8 rounded shadow border border-slate-200 text-sm space-y-6"
            >
              {/* EN-TÊTE PDF */}
              <div className="flex justify-between items-start border-b-2 border-slate-900 pb-4">
                <div className="flex items-center gap-4">
                  {logoBase64 && (
                    <img src={logoBase64} alt="Logo Client" className="h-12 w-auto max-w-[120px] object-contain" />
                  )}
                  <div>
                    <h1 className="text-xl font-bold uppercase tracking-wide text-slate-900">Rapport Cyber : {reportType}</h1>
                    <p className="text-xs text-slate-500">Document Officiel de Securité & Investigation</p>
                  </div>
                </div>
                <div className="text-right text-xs text-slate-600">
                  <p><strong>Client :</strong> {formData.clientName}</p>
                  <p><strong>Date :</strong> {formData.date}</p>
                  <p><strong>Analyste :</strong> {formData.analystName}</p>
                </div>
              </div>

              {/* DÉTAILS, SÉVÉRITÉ ET SCORE CVSS */}
              <div className="bg-slate-100 p-4 rounded border border-slate-200 flex justify-between items-center">
                <div>
                  <span className="text-xs text-slate-500 block uppercase font-semibold">Objet</span>
                  <h2 className="text-base font-bold text-slate-900">{formData.title}</h2>
                </div>
                <div className="flex items-center gap-2">
                  <span className="bg-amber-100 text-amber-900 border border-amber-300 px-3 py-1 rounded text-xs font-bold">
                    CVSS : {computedCvssScore}
                  </span>
                  <span className={`px-3 py-1 rounded text-xs font-bold text-white ${
                    formData.severity === "Critique" ? "bg-red-600" :
                    formData.severity === "Élevée" ? "bg-orange-500" :
                    formData.severity === "Moyenne" ? "bg-yellow-600" : "bg-green-600"
                  }`}>
                    {formData.severity}
                  </span>
                </div>
              </div>

              {/* SECTION CTI */}
              <div className="border border-cyan-200 bg-cyan-50 p-3 rounded space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-800 flex items-center gap-1">
                    <Radio className="w-3 h-3 text-cyan-600" /> Profil de la Menace (CTI)
                  </span>
                  <span className="text-[10px] font-semibold text-cyan-700 bg-cyan-100 px-2 py-0.5 rounded">
                    Confiance : {confidenceLevel}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <p className="text-[10px] text-cyan-600 font-medium">Acteur Suspecté :</p>
                    <p className="font-bold text-cyan-950">{threatActor}</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-cyan-600 font-medium">Motivation :</p>
                    <p className="font-medium text-cyan-900">{threatMotivation}</p>
                  </div>
                </div>
              </div>

              {/* BADGES MITRE ATT&CK */}
              <div className="border border-purple-200 bg-purple-50 p-3 rounded space-y-1">
                <span className="text-[10px] font-bold uppercase tracking-wider text-purple-700 block">Classification MITRE ATT&CK</span>
                <div className="flex items-center gap-2">
                  <span className="bg-purple-200 text-purple-900 px-2 py-0.5 rounded text-xs font-semibold">
                    Tactique : {mitreTactic}
                  </span>
                  <span className="bg-purple-900 text-white px-2 py-0.5 rounded text-xs font-semibold">
                    Technique : {mitreTechnique}
                  </span>
                </div>
              </div>

              {/* CHRONOLOGIE DE L'INCIDENT */}
              {timelineEvents.length > 0 && (
                <div>
                  <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Chronologie des Événements</h3>
                  <div className="border-l-2 border-indigo-400 ml-2 pl-3 space-y-2">
                    {timelineEvents.map((event, idx) => (
                      <div key={idx} className="text-xs">
                        <span className="font-bold text-indigo-700 mr-2">[{event.time}]</span>
                        <span className="font-semibold text-slate-900">{event.title}</span>
                        {event.description && <p className="text-slate-600 text-[11px]">{event.description}</p>}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* PÉRIMÈTRE */}
              <div>
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Périmètre & Équipements</h3>
                <p className="text-xs text-slate-800 bg-slate-100 p-2 rounded">{formData.systems}</p>
              </div>

              {/* DESCRIPTION */}
              <div>
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Analyse Détaillée</h3>
                <p className="text-xs text-slate-800 whitespace-pre-line">{formData.description}</p>
              </div>

              {/* CAUSE RACINE */}
              <div>
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Cause Racine Identifiée</h3>
                <p className="text-xs text-slate-800 bg-red-50 text-red-900 p-2 rounded border border-red-200">{formData.rootCause}</p>
              </div>

              {/* TABLEAU DES IOCs */}
              {iocs.length > 0 && (
                <div>
                  <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Indicateurs de Compromission (IOCs)</h3>
                  <div className="border rounded overflow-hidden">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="bg-slate-100 border-b text-slate-600">
                          <th className="p-1.5 font-semibold">Type</th>
                          <th className="p-1.5 font-semibold">Indicateur (Valeur)</th>
                          <th className="p-1.5 font-semibold">Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {iocs.map((ioc, idx) => (
                          <tr key={idx} className="border-b last:border-0 hover:bg-slate-50">
                            <td className="p-1.5 font-bold text-red-600">{ioc.type}</td>
                            <td className="p-1.5 font-mono text-slate-900">{ioc.value}</td>
                            <td className="p-1.5 text-slate-600">{ioc.description || "-"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* RECOMMANDATIONS */}
              <div>
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Recommandations & Mesures Correctives</h3>
                <p className="text-xs text-slate-800 whitespace-pre-line bg-green-50 text-green-900 p-3 rounded border border-green-200 font-mono">
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