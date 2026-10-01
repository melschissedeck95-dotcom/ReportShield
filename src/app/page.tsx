"use client";

import React, { useState } from "react";
import { Shield, FileText, Printer } from "lucide-react";

export default function Home() {
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

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <>
      {/* Styles CSS pour forcer l'impression uniquement du rapport */}
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
        <header className="max-w-6xl mx-auto mb-10 flex items-center justify-between border-b border-slate-800 pb-6 no-print">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-500" />
            <h1 className="text-2xl font-bold text-white">ReportShield</h1>
          </div>
          <button
            onClick={handlePrint}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white font-medium px-5 py-2.5 rounded-lg transition cursor-pointer"
          >
            <Printer className="w-4 h-4" /> Imprimer / Enregistrer en PDF
          </button>
        </header>

        <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* FORMULAIRE (MASQUÉ À L'IMPRESSION) */}
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl space-y-4 no-print">
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

          {/* APERÇU DU RAPPORT (CE QUI SERA IMPRIMÉ / SAUVEGARDÉ EN PDF) */}
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-xl flex flex-col items-center">
            <span className="text-xs text-slate-400 mb-2 no-print">Aperçu du document PDF</span>
            
            <div
              id="pdf-report"
              className="w-full bg-white text-slate-900 p-8 rounded shadow border border-slate-200 text-sm space-y-6"
            >
              {/* Entête du PDF */}
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

              {/* Titre & Sévérité */}
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

              {/* Perimètre */}
              <div>
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Périmètre / Équipements Impactés</h3>
                <p className="text-xs text-slate-800 bg-slate-100 p-2 rounded">{formData.systems}</p>
              </div>

              {/* Description */}
              <div>
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Description & Chronologie</h3>
                <p className="text-xs text-slate-800 whitespace-pre-line">{formData.description}</p>
              </div>

              {/* Cause Racine */}
              <div>
                <h3 className="text-xs font-bold uppercase text-slate-700 border-b pb-1 mb-2">Cause Racine Identifiée</h3>
                <p className="text-xs text-slate-800 bg-red-50 text-red-900 p-2 rounded border border-red-200">{formData.rootCause}</p>
              </div>

              {/* Recommandations */}
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