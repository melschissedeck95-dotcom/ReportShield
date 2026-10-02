'use client';

import React, { useState } from 'react';
import { 
  Shield, User, Lock, Mail, Phone, ExternalLink, 
  Share2, AlertTriangle, HelpCircle, ArrowLeft, LogOut
} from 'lucide-react';

// Définition des types pour TypeScript
interface Report {
  id: number;
  title: string;
  date: string;
  status: string;
  severity: string;
}

interface ProfileInfo {
  title: string;
  department: string;
  badge: string;
  stats: Record<string, string | number>;
  reports: Report[];
}

type ProfileKey = 'soc' | 'pentester' | 'admin';

export default function ReportShieldProApp() {
  const [currentView, setCurrentView] = useState('login');
  const [selectedRole, setSelectedRole] = useState<ProfileKey>('soc');
  const [emailInput, setEmailInput] = useState('');
  const [resetSent, setResetSent] = useState(false);
  const [shareOpen, setShareOpen] = useState(false);

  // Données typées des profils
  const profilesData: Record<ProfileKey, ProfileInfo> = {
    soc: {
      title: "Analyste SOC Junior",
      department: "Cybersécurité & Surveillance",
      badge: "Niveau 1",
      stats: { alertsProcessed: 142, falsePositives: "18%", criticalIncidents: 3 },
      reports: [
        { id: 1, title: "Analyse des logs Brute-Force SSH", date: "02/10/2026", status: "Résolu", severity: "Moyenne" },
        { id: 2, title: "Tentative d'exfiltration de données - IP suspecte", date: "01/10/2026", status: "Escaladé", severity: "Élevée" },
        { id: 3, title: "Revue des règles de détection SIEM", date: "28/09/2026", status: "Clôturé", severity: "Faible" }
      ]
    },
    pentester: {
      title: "Testeur d'Intrusion (Pentester)",
      department: "Évaluation des Vulnérabilités",
      badge: "Offensive Security",
      stats: { auditsDone: 12, vulnsFound: 45, criticalPatches: 8 },
      reports: [
        { id: 1, title: "Audit d'application Web - Portail Client", date: "30/09/2026", status: "Rapport Livré", severity: "Critique" },
        { id: 2, title: "Test d'intrusion Interne - Réseau Siège", date: "25/09/2026", status: "En Cours", severity: "Élevée" },
        { id: 3, title: "Simulation Phishing Campagne Q3", date: "15/09/2026", status: "Terminé", severity: "Moyenne" }
      ]
    },
    admin: {
      title: "Administrateur Sécurité",
      department: "Gouvernance & Infrastructure",
      badge: "SuperAdmin",
      stats: { activeNodes: 128, complianceRate: "94%", policiesEnforced: 24 },
      reports: [
        { id: 1, title: "Audit de conformité ISO 27001 / PCI DSS", date: "01/10/2026", status: "Validé", severity: "Conforme" },
        { id: 2, title: "Mise en place de la micro-segmentation réseau", date: "22/09/2026", status: "Actif", severity: "Critique" },
        { id: 3, title: "Revue des accès et privilèges IAM", date: "10/09/2026", status: "Complété", severity: "Moyenne" }
      ]
    }
  };

  const shareUrl = encodeURIComponent("https://reportsield-pro.sec");
  const shareText = encodeURIComponent("Découvrez ReportShield Pro, la plateforme de gestion des rapports de sécurité et d'analyse SOC !");
  
  const socialLinks = {
    linkedin: `https://www.linkedin.com/sharing/share-offsite/?url=${shareUrl}`,
    telegram: `https://t.me/share/url?url=${shareUrl}&text=${shareText}`,
    whatsapp: `https://api.whatsapp.com/send?text=${shareText}%20${shareUrl}`,
    twitter: `https://twitter.com/intent/tweet?text=${shareText}&url=${shareUrl}`
  };

 const handlePasswordReset = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!emailInput) return;

    try {
      const response = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: emailInput }),
      });

      const data = await response.json();

      if (response.ok) {
        setResetSent(true);
      } else {
        alert("Erreur lors de l'envoi : " + (data.error || "Une erreur est survenue"));
      }
    } catch (err) {
      console.error(err);
      alert("Erreur de connexion au serveur.");
    }
  };

  const currentProfile = profilesData[selectedRole];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-between font-sans">
      
      {/* HEADER */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setCurrentView('dashboard')}>
          <div className="bg-cyan-500/10 p-2 rounded-lg border border-cyan-500/30">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="font-bold text-lg tracking-wide text-cyan-400">ReportShield Pro</h1>
            <p className="text-xs text-slate-400">Security Operations & Compliance</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          {currentView === 'dashboard' && (
            <>
              <button 
                onClick={() => setShareOpen(!shareOpen)}
                className="flex items-center space-x-1 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm rounded-lg transition border border-slate-700"
              >
                <Share2 className="w-4 h-4 text-cyan-400" />
                <span>Partager</span>
              </button>
              <button 
                onClick={() => setCurrentView('support')}
                className="flex items-center space-x-1 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm rounded-lg transition border border-slate-700"
              >
                <HelpCircle className="w-4 h-4 text-emerald-400" />
                <span>Support</span>
              </button>
              <button 
                onClick={() => setCurrentView('login')}
                className="flex items-center space-x-1 px-3 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 text-sm rounded-lg transition border border-rose-500/30"
              >
                <LogOut className="w-4 h-4" />
                <span>Déconnexion</span>
              </button>
            </>
          )}
        </div>
      </header>

      {/* POPUP DE PARTAGE SOCIAL */}
      {shareOpen && (
        <div className="absolute right-6 top-20 bg-slate-900 border border-slate-700 p-4 rounded-xl shadow-2xl z-50 w-64">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center justify-between">
            <span>Partager la plateforme</span>
            <button onClick={() => setShareOpen(false)} className="text-slate-400 hover:text-white text-xs">✕</button>
          </h3>
          <div className="space-y-2">
            <a href={socialLinks.linkedin} target="_blank" rel="noopener noreferrer" className="block w-full text-left px-3 py-2 bg-blue-950/45 hover:bg-blue-900/50 text-blue-400 rounded text-sm transition border border-blue-800/50">LinkedIn</a>
            <a href={socialLinks.telegram} target="_blank" rel="noopener noreferrer" className="block w-full text-left px-3 py-2 bg-sky-950/45 hover:bg-sky-900/50 text-sky-400 rounded text-sm transition border border-sky-800/50">Telegram</a>
            <a href={socialLinks.whatsapp} target="_blank" rel="noopener noreferrer" className="block w-full text-left px-3 py-2 bg-emerald-950/45 hover:bg-emerald-900/50 text-emerald-400 rounded text-sm transition border border-emerald-800/50">WhatsApp</a>
            <a href={socialLinks.twitter} target="_blank" rel="noopener noreferrer" className="block w-full text-left px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-sm transition border border-slate-700">Twitter / X</a>
          </div>
        </div>
      )}

      {/* CONTENU PRINCIPAL */}
      <main className="flex-1 max-w-6xl w-full mx-auto p-6">

        {/* VUE 1 : CONNEXION */}
        {currentView === 'login' && (
          <div className="max-w-md mx-auto mt-12 bg-slate-900 border border-slate-800 p-8 rounded-2xl shadow-xl">
            <div className="text-center mb-6">
              <h2 className="text-2xl font-bold text-slate-100">Connexion</h2>
              <p className="text-sm text-slate-400">Accédez à votre espace de rapports de sécurité</p>
            </div>

            <form onSubmit={(e) => { e.preventDefault(); setCurrentView('dashboard'); }} className="space-y-4">
              <div>
                <label className="block text-xs uppercase tracking-wider text-slate-400 mb-1 font-semibold">Identifiant / Email</label>
                <div className="relative">
                  <User className="absolute left-3 top-3 w-5 h-5 text-slate-500" />
                  <input type="text" required placeholder="analyst@reportshield.sec" className="w-full bg-slate-950 border border-slate-800 rounded-lg px-10 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-cyan-500" />
                </div>
              </div>

              <div>
                <label className="block text-xs uppercase tracking-wider text-slate-400 mb-1 font-semibold">Mot de passe</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-3 w-5 h-5 text-slate-500" />
                  <input type="password" required placeholder="••••••••" className="w-full bg-slate-950 border border-slate-800 rounded-lg px-10 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-cyan-500" />
                </div>
              </div>

              <div className="flex items-center justify-between text-sm">
                <button type="button" onClick={() => { setResetSent(false); setCurrentView('forgot-password'); }} className="text-cyan-400 hover:underline">
                  Mot de passe oublié ?
                </button>
              </div>

              <button type="submit" className="w-full bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold py-2.5 rounded-lg transition">
                Se connecter
              </button>
            </form>
          </div>
        )}

        {/* VUE 2 : MOT DE PASSE OUBLIÉ */}
        {currentView === 'forgot-password' && (
          <div className="max-w-md mx-auto mt-12 bg-slate-900 border border-slate-800 p-8 rounded-2xl shadow-xl">
            <button onClick={() => setCurrentView('login')} className="flex items-center text-xs text-slate-400 hover:text-slate-200 mb-4 transition">
              <ArrowLeft className="w-4 h-4 mr-1" /> Retour à la connexion
            </button>

            <div className="text-center mb-6">
              <h2 className="text-2xl font-bold text-slate-100">Récupération</h2>
              <p className="text-sm text-slate-400">Entrez votre email pour réinitialiser vos accès</p>
            </div>

            {resetSent ? (
              <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-4 rounded-xl text-sm text-center">
                Un lien de réinitialisation a été envoyé à <strong>{emailInput}</strong>. Vérifiez votre boîte de réception.
              </div>
            ) : (
              <form onSubmit={handlePasswordReset} className="space-y-4">
                <div>
                  <label className="block text-xs uppercase tracking-wider text-slate-400 mb-1 font-semibold">Adresse Email</label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-3 w-5 h-5 text-slate-500" />
                    <input 
                      type="email" 
                      required 
                      value={emailInput}
                      onChange={(e) => setEmailInput(e.target.value)}
                      placeholder="vous@domaine.com" 
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-10 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-cyan-500" 
                    />
                  </div>
                </div>

                <button type="submit" className="w-full bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold py-2.5 rounded-lg transition">
                  Envoyer le lien de récupération
                </button>
              </form>
            )}
          </div>
        )}

        {/* VUE 3 : TABLEAU DE BORD & RAPPORTS MULTI-PROFILS */}
        {currentView === 'dashboard' && (
          <div className="space-y-6">
            
            {/* Sélecteur de Profil */}
            <div className="flex flex-wrap gap-3 bg-slate-900 p-3 rounded-xl border border-slate-800">
              <span className="text-xs uppercase tracking-wider text-slate-400 self-center px-2 font-bold">Sélectionner le profil :</span>
              {(Object.keys(profilesData) as ProfileKey[]).map((key) => {
                const p = profilesData[key];
                const isActive = selectedRole === key;
                return (
                  <button
                    key={key}
                    onClick={() => setSelectedRole(key)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
                      isActive 
                        ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20' 
                        : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                    }`}
                  >
                    {p.title}
                  </button>
                );
              })}
            </div>

            {/* En-tête du profil actif */}
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
              <div>
                <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 text-xs px-2.5 py-1 rounded-full font-semibold">
                  {currentProfile.badge}
                </span>
                <h2 className="text-2xl font-bold mt-2 text-slate-100">{currentProfile.title}</h2>
                <p className="text-sm text-slate-400">{currentProfile.department}</p>
              </div>

              {/* Statistiques rapides dynamiques */}
              <div className="flex gap-4 w-full md:w-auto">
                {Object.entries(currentProfile.stats).map(([statKey, statVal], idx) => (
                  <div key={idx} className="bg-slate-950 border border-slate-800 px-4 py-3 rounded-xl text-center flex-1 md:flex-initial">
                    <div className="text-xs text-slate-400 uppercase">{statKey}</div>
                    <div className="text-lg font-bold text-cyan-400 mt-1">{statVal}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Liste des Rapports */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-slate-100 mb-4 flex items-center">
                <AlertTriangle className="w-5 h-5 mr-2 text-cyan-400" />
                Rapports d'Activité & Incidents Associés
              </h3>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-xs tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="px-4 py-3">Titre du Rapport</th>
                      <th className="px-4 py-3">Date</th>
                      <th className="px-4 py-3">Statut</th>
                      <th className="px-4 py-3">Sévérité / Niveau</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {currentProfile.reports.map((report: Report) => (
                      <tr key={report.id} className="hover:bg-slate-800/50 transition">
                        <td className="px-4 py-3 font-medium text-slate-200">{report.title}</td>
                        <td className="px-4 py-3 text-slate-400">{report.date}</td>
                        <td className="px-4 py-3">
                          <span className="px-2.5 py-1 rounded text-xs bg-slate-800 border border-slate-700 text-slate-300">
                            {report.status}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2.5 py-1 rounded text-xs font-semibold ${
                            report.severity === 'Critique' || report.severity === 'Élevée' 
                              ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30' 
                              : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                          }`}>
                            {report.severity}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        )}

        {/* VUE 4 : SUPPORT TECHNIQUE & CONTACT */}
        {currentView === 'support' && (
          <div className="max-w-2xl mx-auto mt-6 bg-slate-900 border border-slate-800 p-8 rounded-2xl shadow-xl">
            <button onClick={() => setCurrentView('dashboard')} className="flex items-center text-xs text-slate-400 hover:text-slate-200 mb-4 transition">
              <ArrowLeft className="w-4 h-4 mr-1" /> Retour au tableau de bord
            </button>

            <h2 className="text-2xl font-bold text-slate-100 mb-2">Support Technique ReportShield Pro</h2>
            <p className="text-sm text-slate-400 mb-6">Notre équipe de réponse aux incidents et le support technique sont joignables 24/7.</p>

            <div className="space-y-4">
              <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl flex items-center space-x-4">
                <div className="bg-cyan-500/10 p-3 rounded-lg text-cyan-400 border border-cyan-500/30">
                  <Mail className="w-6 h-6" />
                </div>
                <div>
                  <div className="text-xs text-slate-400 uppercase font-semibold">Email du Support</div>
                  <div className="text-slate-200 font-medium">support@reportshield.sec</div>
                </div>
              </div>

              <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl flex items-center space-x-4">
                <div className="bg-emerald-500/10 p-3 rounded-lg text-emerald-400 border border-emerald-500/30">
                  <Phone className="w-6 h-6" />
                </div>
                <div>
                  <div className="text-xs text-slate-400 uppercase font-semibold">Ligne d'Urgence SOC (24/7)</div>
                  <div className="text-slate-200 font-medium">+33 1 89 00 44 22</div>
                </div>
              </div>

              <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl flex items-center space-x-4">
                <div className="bg-indigo-500/10 p-3 rounded-lg text-indigo-400 border border-indigo-500/30">
                  <ExternalLink className="w-6 h-6" />
                </div>
                <div>
                  <div className="text-xs text-slate-400 uppercase font-semibold">Documentation & Wiki Interne</div>
                  <a href="#" className="text-cyan-400 hover:underline font-medium text-sm">docs.reportshield.sec</a>
                </div>
              </div>
            </div>
          </div>
        )}

      </main>

      {/* FOOTER */}
      <footer className="border-t border-slate-800 bg-slate-900/30 text-center py-4 text-xs text-slate-500">
        ReportShield Pro © 2026 — Tous droits réservés. Plateforme sécurisée de gestion des opérations de cybersécurité.
      </footer>
    </div>
  );
}