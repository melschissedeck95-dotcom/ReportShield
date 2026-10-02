"use client";

import React, { useState, useEffect } from "react";
import { Shield, FileText, Printer, Save, LogIn, LogOut, CheckCircle, FolderOpen, Trash2, Clock } from "lucide-react";
import { supabase } from "@/lib/supabase";

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
  created_at: string;
}

export default function Home() {
  const [user, setUser] = useState<any>(null);
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [savedReports, setSavedReports] = useState<ReportItem[]>([]);

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

  // Charger l'utilisateur et ses rapports au montage du composant
  useEffect(() => {
    const initAuth = async () => {
      const { data } = await supabase.auth.getUser();
      setUser(data.user);
      if (data.user) {
        fetchReports();
      }
    };

    initAuth();

    const { data: authListener } = supabase.auth.onAuthStateChange((_, session) => {
      const currentUser = session?.user ?? null;
      setUser(currentUser);
      if (currentUser) {
        fetchReports();
      } else {
        setSavedReports([]);
      }
    });

    return () => {
      authListener.subscription.unsubscribe();
    };
  }, []);

  // Récupérer les rapports depuis Supabase
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

  const handlePrint = () => {
    window.print();
  };

  // Authentification Magic Link
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

  // Sauvegarder un rapport
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

  // Recharger un rapport sélectionné
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
  };

  // Supprimer un rapport
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
          {/* GAUCHE : FORMULAIRE ET HISTORIQUE */}
          <div className="space-y-6 no-print">
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4">
              <h2 className="text-xl font-semibold mb-4 flex items-center gap-2 border-b border-slate-700 pb-2">
                <FileText className="w-5 h-5 text-blue-400" /> Informations de l'Incident
              </h2>

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

          {/* DROITE : APERÇU RAPPORT */}
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl flex flex-col items-center h-fit">
            <span className="text-xs text-slate-400 mb-2 no-print">Aperçu du document PDF</span>
            
            <div
              id="pdf-report"
              className="w-full bg-white text-slate-900 p-8 rounded shadow border border-slate-200 text-sm space-y-6"
            >
              <div className="flex justify-between items-start border-b-2 border-slate-900 pb-4">
                <div>
                  <h1 className="text-xl font-bold uppercase tracking-wide text-slate-900">Rapport d'Incident IT & Cyber</h1>
                  <p className="text-xs text-slate-500">Document de Synthèse Exécutive</p>
                </div>
                <div className="text-right text-xs text-slate-600">
                  <p><strong>Client :</strong> {formData.clientName}</p>
                  <p><strong>Date :</strong> {formData.date}</p>
                  <p><strong>Analyste :</strong> {formData.analystName}</p>
                </div>
              </div>

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

              <div>
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Périmètre / Équipements Impactés</h3>
                <p className="text-xs text-slate-800 bg-slate-100 p-2 rounded">{formData.systems}</p>
              </div>

              <div>
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Description & Chronologie</h3>
                <p className="text-xs text-slate-800 whitespace-pre-line">{formData.description}</p>
              </div>

              <div>
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Cause Racine Identifiée</h3>
                <p className="text-xs text-slate-800 bg-red-50 text-red-900 p-2 rounded border border-red-200">{formData.rootCause}</p>
              </div>

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