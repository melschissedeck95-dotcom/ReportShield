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
  Radio
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
  logo_url?: string;
  threat_actor?: string;
  threat_motivation?: string;
  threat_sophistication?: string;
  confidence_level?: string;
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

  // États du formulaire
  const [logoBase64, setLogoBase64] = useState<string>("");
  const [mitreTactic, setMitreTactic] = useState<string>("Credential Access");
  const [mitreTechnique, setMitreTechnique] = useState<string>("T1110 - Brute Force");
  
  // États Threat Intelligence
  const [threatActor, setThreatActor] = useState<string>("Inconnu / Non Attribué");
  const [threatMotivation, setThreatMotivation] = useState<string>("Gain Financier (Ransomware / Extorsion)");
  const [threatSophistication, setThreatSophistication] = useState<string>("Moyenne (Cybercriminalité organisée)");
  const [confidenceLevel, setConfidenceLevel] = useState<string>("Moyenne");

  const [iocs, setIocs] = useState<IOCItem[]>([
    { id: "1", type: "IP Address", value: "192.168.1.105", description: "IP source de l'attaque force brute" },
    { id: "2", type: "Hash SHA256", value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", description: "Payload malveillant isolé" }
  ]);

  const [newIoc, setNewIoc] = useState({ type: "IP Address", value: "", description: "" });

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
        logo_url: logoBase64,
        threat_actor: threatActor,
        threat_motivation: threatMotivation,
        threat_sophistication: threatSophistication,
        confidence_level: confidenceLevel
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
    setLogoBase64(report.logo_url || "");
    setThreatActor(report.threat_actor || "Inconnu / Non Attribué");
    setThreatMotivation(report.threat_motivation || "Gain Financier (Ransomware / Extorsion)");
    setThreatSophistication(report.threat_sophistication || "Moyenne (Cybercriminalité organisée)");
    setConfidenceLevel(report.confidence_level || "Moyenne");
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
            <h1 className="text-2xl font-bold text-white">ReportShield</h1>
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
              <Printer className="w-4 h-4" /> PDF
            </button>
          </div>
        </header>

        {message && (
          <div className="max-w-6xl mx-auto mb-6 p-3 bg-blue-900/50 border border-blue-500 rounded-lg text-xs text-blue-200 no-print flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-blue-400" /> {message}
          </div>
        )}

        <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* COLONNE GAUCHE : FORMULAIRES */}
          <div className="space-y-6 no-print">
            
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
                <label className="block text-xs font-medium text-slate-400 mb-1">Titre de l'Incident</label>
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
                <label className="block text-xs font-medium text-slate-400 mb-1">Description & Chronologie</label>
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

            {/* 2. MODULE THREAT INTELLIGENCE (CTI) */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4">
              <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-slate-700 pb-2 text-cyan-400">
                <Globe className="w-5 h-5" /> Threat Intelligence (CTI)
              </h2>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Acteur de la Menace / Groupe</label>
                  <input
                    type="text"
                    placeholder="ex: LockBit 3.0, APT29, Opportuniste"
                    value={threatActor}
                    onChange={(e) => setThreatActor(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Indice de Confiance (Attribution)</label>
                  <select
                    value={confidenceLevel}
                    onChange={(e) => setConfidenceLevel(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Faible">Faible (Hypothèse)</option>
                    <option value="Moyenne">Moyenne (Indices concordants)</option>
                    <option value="Élevée">Élevée (Attribution confirmée)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Motivation Principale</label>
                  <select
                    value={threatMotivation}
                    onChange={(e) => setThreatMotivation(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Gain Financier (Ransomware / Extorsion)">Gain Financier (Extorsion)</option>
                    <option value="Espionnage Industriel / Étatique">Espionnage</option>
                    <option value="Sabotage / Destructif">Sabotage / Destructif</option>
                    <option value="Hacktivisme">Hacktivisme</option>
                    <option value="Opportuniste (Script Kiddie)">Opportuniste</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Sophistication de la Menace</label>
                  <select
                    value={threatSophistication}
                    onChange={(e) => setThreatSophistication(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Faible (Attaque basique automatise)">Faible (Basique)</option>
                    <option value="Moyenne (Cybercriminalité organisée)">Moyenne (Organisée)</option>
                    <option value="Élevée (APT / Groupe Étatique)">Élevée (APT / Étatique)</option>
                  </select>
                </div>
              </div>
            </div>

            {/* 3. MODULE MITRE ATT&CK */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4">
              <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-slate-700 pb-2 text-purple-400">
                <Crosshair className="w-5 h-5" /> Framework MITRE ATT&CK
              </h2>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Tactique (Tactic)</label>
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

            {/* 4. MODULE IOCs */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4">
              <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-slate-700 pb-2 text-red-400">
                <List className="w-5 h-5" /> Indicateurs de Compromission (IOCs)
              </h2>

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
                    placeholder="Valeur (ex: 192.168.1.1)"
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

            {/* HISTORIQUE */}
            {user && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4">
                <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-slate-700 pb-2">
                  <FolderOpen className="w-5 h-5 text-emerald-400" /> Mes Rapports Sauvegardés ({savedReports.length})
                </h2>

                {savedReports.length === 0 ? (
                  <p className="text-xs text-slate-400 italic">Aucun rapport sauvegardé pour le moment.</p>
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
                          title="Supprimer le rapport"
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
            <span className="text-xs text-slate-400 mb-2 no-print">Aperçu du document PDF</span>
            
            <div
              id="pdf-report"
              className="w-full bg-white text-slate-900 p-8 rounded shadow border border-slate-200 text-sm space-y-6"
            >
              {/* EN-TÊTE PDF AVEC LOGO */}
              <div className="flex justify-between items-start border-b-2 border-slate-900 pb-4">
                <div className="flex items-center gap-4">
                  {logoBase64 && (
                    <img src={logoBase64} alt="Logo Client" className="h-12 w-auto max-w-[120px] object-contain" />
                  )}
                  <div>
                    <h1 className="text-xl font-bold uppercase tracking-wide text-slate-900">Rapport d'Incident IT & Cyber</h1>
                    <p className="text-xs text-slate-500">Document de Synthèse Exécutive</p>
                  </div>
                </div>
                <div className="text-right text-xs text-slate-600">
                  <p><strong>Client :</strong> {formData.clientName}</p>
                  <p><strong>Date :</strong> {formData.date}</p>
                  <p><strong>Analyste :</strong> {formData.analystName}</p>
                </div>
              </div>

              {/* DÉTAILS ET SÉVÉRITÉ */}
              <div className="bg-slate-100 p-4 rounded border border-slate-200 flex justify-between items-center">
                <div>
                  <span className="text-xs text-slate-500 block uppercase font-semibold">Incident</span>
                  <h2 className="text-base font-bold text-slate-900">{formData.title}</h2>
                </div>
                <span className={`px-3 py-1 rounded text-xs font-bold text-white ${
                  formData.severity === "Critique" ? "bg-red-600" :
                  formData.severity === "Élevée" ? "bg-orange-500" :
                  formData.severity === "Moyenne" ? "bg-yellow-600" : "bg-green-600"
                }`}>
                  {formData.severity}
                </span>
              </div>

              {/* SECTION THREAT INTELLIGENCE (CTI) */}
              <div className="border border-cyan-200 bg-cyan-50 p-3 rounded space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-800 flex items-center gap-1">
                    <Radio className="w-3 h-3 text-cyan-600" /> Profil de la Menace & Attribution CTI
                  </span>
                  <span className="text-[10px] font-semibold text-cyan-700 bg-cyan-100 px-2 py-0.5 rounded">
                    Confiance : {confidenceLevel}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <p className="text-[10px] text-cyan-600 font-medium">Acteur Suspecté / Attribué :</p>
                    <p className="font-bold text-cyan-950">{threatActor}</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-cyan-600 font-medium">Motivation :</p>
                    <p className="font-medium text-cyan-900">{threatMotivation}</p>
                  </div>
                </div>

                <div className="text-xs pt-1 border-t border-cyan-200/60">
                  <span className="text-[10px] text-cyan-600 font-medium">Niveau de Sophistication : </span>
                  <span className="font-medium text-cyan-900">{threatSophistication}</span>
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

              {/* PÉRIMÈTRE */}
              <div>
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Périmètre / Équipements Impactés</h3>
                <p className="text-xs text-slate-800 bg-slate-100 p-2 rounded">{formData.systems}</p>
              </div>

              {/* CHRONOLOGIE */}
              <div>
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Description & Chronologie</h3>
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
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Recommandations & Plan d'Action</h3>
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