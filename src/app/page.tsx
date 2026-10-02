"use client";

import React, { useState, useEffect } from "react";
import {
Shield,
FileText,
Printer,
Save,
CheckCircle,
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
AlertTriangle,
Lock,
Layers,
Terminal,
Calendar,
UserCheck,
Zap,
CheckSquare,
FileCode2
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
const [user, setUser] = useState(null);
const [email, setEmail] = useState("");
const [loading, setLoading] = useState(false);
const [savedReports, setSavedReports] = useState<ReportItem[]>([]);

// Langue (FR / EN)
const [lang, setLang] = useState<"fr" | "en">("fr");

// Profil sélectionné
const [reportType, setReportType] = useState<"SOC_CTI" | "Pentest" | "Compliance">("Pentest");

// Metadata communes
const [logoBase64, setLogoBase64] = useState("");
const [clientName, setClientName] = useState("Acme Corp International");
const [analystName, setAnalystName] = useState("Jean Dupont (Senior Lead Pentester)");
const [auditFirm, setAuditFirm] = useState("CyberShield Security Services");
const [date, setDate] = useState(new Date().toISOString().split("T")[0]);
const [reportVersion, setReportVersion] = useState("v1.0 (Version Finale)");
const [tlpLevel, setTLPLevel] = useState("TLP:AMBER");

// Champs Profil 1 : Combined SOC + CTI
const [socTitle, setSocTitle] = useState("Infiltration via Ransomware & Attaque Force Brute VPN");
const [socSystems, setSocSystems] = useState("Serveur Active Directory, BDD Client, Passerelle VPN");
const [socDescription, setSocDescription] = useState("Compromission initiale par attaque de force brute sur le portail VPN, suivie d'un mouvement latéral et d'une tentative d'exfiltration de données.");
const [socRootCause, setSocRootCause] = useState("Mots de passe faibles et absence d'authentification multifacteur (MFA) sur les accès distants.");
const [socRecommendations, setSocRecommendations] = useState("1. Déploiement immédiat du MFA sur tous les accès VPN.\n2. Blocage permanent des adresses IP malveillantes listées dans les IOCs.\n3. Réinitialisation globale des secrets Kerberos et mots de passe AD.");
const [threatActor, setThreatActor] = useState("LockBit 3.0 / APT29");
const [threatMotivation, setThreatMotivation] = useState("Gain Financier (Ransomware / Extorsion)");
const [threatSophistication, setThreatSophistication] = useState("Élevée (Organisé / State-Sponsored)");
const [confidenceLevel, setConfidenceLevel] = useState("Élevée (High Confidence)");
const [mitreTactic, setMitreTactic] = useState("Credential Access");
const [mitreTechnique, setMitreTechnique] = useState("T1110 - Brute Force");

// Champs Profil 2 : PENTEST ULTRA-COMPLET (8 ÉTAPES CANONIQUES)
// Step 1: Metadata & Header
const [pentestScopeType, setPentestScopeType] = useState("Boîte Grise / Web API & Infrastructure Active Directory");

// Step 2: Executive Summary
const [overallPosture, setOverallPosture] = useState("CRITIQUE");
const [executiveSummaryText, setExecutiveSummaryText] = useState(
"Au cours de cet audit, plusieurs vulnérabilités critiques ont été identifiées. Un attaquant non authentifié situé sur le réseau externe a pu exploiter une injection SQL aveugle sur le portail web client, extraire des identifiants d'administration, puis procéder à un pivotement latéral vers le contrôleur de domaine Active Directory interne pour obtenir les privilèges Domain Admin."
);
const [topStrategicRecommendations, setTopStrategicRecommendations] = useState(
"1. Corriger en priorité absolue les requêtes SQL dynamiques via des requêtes préparées sur l'API Web.\n2. Généraliser l'authentification multifacteur (MFA) sur toutes les interfaces d'administration internes et distantes.\n3. Segmenter strictement le réseau d'administration (VLAN Développeurs vs VLAN Contrôleurs de Domaine)."
);

// Step 3: Scope & Methodology
const [scopeDetails, setScopeDetails] = useState("https://portal.acme-corp.com/api/v1 (192.168.10.0/24, 10.0.5.0/24)");
const [excludedScope, setExcludedScope] = useState("Environnement de production bancaire directe, Passerelles Stripe/PayPal, Serveurs RH.");
const [methodologyStandard, setMethodologyStandard] = useState("OWASP Top 10 (2021), PTES, NIST SP 800-115, PCI DSS v4.0 Req 11.4");
const [testWindow, setTestWindow] = useState("Du 10 au 18 du mois courant - Tests effectués hors heures ouvrées pour l'infrastructure");

// Step 4: Vulnerability & CVSS
const [vulnTitle, setVulnTitle] = useState("Injection SQL Aveugle & Elévation de Privilèges Active Directory (Kerberoasting)");
const [vulnCweOwasp, setVulnCweOwasp] = useState("CWE-89 / OWASP A03:2021 - Injection / PCI DSS Req 6.2.4");
const [vulnTargetComps, setVulnTargetComps] = useState("https://portal.acme-corp.com/api/v1/checkout?id= & DC01.acme.local (Port 88 Kerberos)");

// CVSS v3.1 Calculator State
const [cvssAV, setCvssAV] = useState(0.85); // Network
const [cvssAC, setCvssAC] = useState(0.77); // Low
const [cvssPR, setCvssPR] = useState(0.85); // None
const [cvssUI, setCvssUI] = useState(0.85); // None
const [cvssImpactC, setCvssImpactC] = useState(0.56); // High
const [cvssImpactI, setCvssImpactI] = useState(0.56); // High
const [cvssImpactA, setCvssImpactA] = useState(0.56); // High

// Step 5: PoC Detailed Steps
const [pocStepsDetailed, setPocStepsDetailed] = useState(
"1. RECONNAISSANCE : Exécution de Nmap sur la cible https://portal.acme-corp.com.\n" +
"2. EXPLOITATION SQLi : Envoi de la charge utile sur le paramètre id :\n" +
"   curl -X POST 'https://portal.acme-corp.com/api/v1/checkout' -d "id=1' UNION SELECT username, password_hash FROM users--"\n" +
"3. EXTRACTION DE CREDENTIALS : Récupération du hash de l'administrateur 'svc_admin'.\n" +
"4. PIVOTEMENT & KERBEROASTING : Connexion au domaine interne via le VPN, demande de tickets TGS Kerberos pour les comptes SPN et cassage hors-ligne de la clé NTLM avec Hashcat.\n" +
"5. DOMAIN ADMIN : Prise de contrôle totale du serveur Active Directory DC01."
);

// Step 6: Attack Chain & SOC Evasion
const [attackChainPath, setAttackChainPath] = useState(
"Accès Externe (Web API SQLi) ➔ Extraction Identifiants ➔ Pivotement Interne VPN ➔ Kerberoasting (DC01) ➔ Élévation de Privilèges 'Domain Admin'"
);
const [socDetectionNotes, setSocDetectionNotes] = useState(
"Le SOC n'a déclenché aucune alerte lors de l'extraction SQLi (absence de WAF). La requête TGS Kerberos anormale a été journalisée par l'EDR mais n'a pas été bloquée par manque de règle de réponse automatisée."
);

// Step 7: Remediation Matrix & Plan
const [remediationPlanShortTerm, setRemediationPlanShortTerm] = useState(
"1. Implémenter immédiatement des requêtes préparées (Parameterized Queries) dans le code de l'API Checkout.\n" +
"2. Remplacer le mot de passe du compte 'svc_admin' par une chaîne complexe de plus de 25 caractères (AES-256 Kerberos)."
);
const [remediationPlanLongTerm, setRemediationPlanLongTerm] = useState(
"1. Intégrer un Web Application Firewall (WAF) en mode bloquant devant l'ensemble des API publiques.\n" +
"2. Déployer un outil de gestion des accès à privilèges (PAM) et auditer la politique de comptes de service Active Directory."
);

// Step 8: Certificate/Attestation Notes
const [certificateCustomNotes, setCertificateCustomNotes] = useState(
"Cet audit atteste que l'infrastructure désignée a fait l'objet d'un test d'intrusion rigoureux du 10 au 18 du mois courant. L'évaluation a permis de corriger les vulnérabilités majeures conformément aux directives PCI DSS v4.0 et ISO 27001."
);

// Champs Profil 3 : Conformité & Compliance
const [isoChecks, setIsoChecks] = useState<Record<string, boolean>>({ "A5.1": true, "A5.7": false, "A5.15": true, "A6.8": true, "A7.4": false, "A8.8": false, "A8.12": false, "A8.16": true });
const [pciChecks, setPciChecks] = useState<Record<string, boolean>>({ "Req 1": true, "Req 3": false, "Req 4": true, "Req 6": false, "Req 8": false, "Req 10": true, "Req 11": false, "Req 12": true });
const [gapSummary, setGapSummary] = useState("Alignement partiel sur ISO 27001:2022 et PCI DSS v4.0. Écarts critiques identifiés sur l'absence de MFA et la fréquence des scans ASV.");
const [gapActionPlan, setGapActionPlan] = useState("1. [Priorité Urgente] Déploiement du MFA généralisé sous 15 jours.\n2. [Priorité Haute] Mise en conformité de la gestion des correctifs sous 30 jours.\n3. [Priorité Moyenne] Intégration d'une solution DLP et surveillance SIEM 24/7.");

// IOCs & Parseur
const [rawLogsText, setRawLogsText] = useState("");
const [iocs, setIocs] = useState<IOCItem[]>([
{ id: "1", type: "IP Address", value: "192.168.10.105", description: "IP Attaquant durant le Pentest" },
{ id: "2", type: "Hash SHA256", value: "a2b4c68298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", description: "Payload d'Exploitation PoC" }
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

// Calcul du CVSS v3.1
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
const ipRegex = /\b(?:[0-9]{1,3}.){3}[0-9]{1,3}\b/g;
const ips = Array.from(new Set(rawLogsText.match(ipRegex) || []));
ips.forEach(ip => {
if (ip !== "127.0.0.1") extracted.push({ id: Math.random().toString(), type: "IP Address", value: ip, description: lang === "fr" ? "Extrait du périmètre pentest" : "Extracted from pentest logs" });
});
if (extracted.length > 0) {
setIocs([...iocs, ...extracted]);
setRawLogsText("");
alert(lang === "fr" ? ${extracted.length} IOC(s) extrait(s) ! : ${extracted.length} IOC(s) extracted!);
} else alert(lang === "fr" ? "Aucun IOC trouvé." : "No IOCs found.");
};

const handleExportSTIX = () => {
const stixBundle = {
type: "bundle",
id: bundle--${crypto.randomUUID()},
objects: iocs.map(ioc => ({
type: "indicator",
spec_version: "2.1",
id: indicator--${ioc.id},
pattern: [ipv4-addr:value = '${ioc.value}'],
description: ioc.description
}))
};
const blob = new Blob([JSON.stringify(stixBundle, null, 2)], { type: "application/json" });
const url = URL.createObjectURL(blob);
const link = document.createElement("a");
link.href = url;
link.download = STIX2.1_${clientName}.json;
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
title: reportType === "SOC_CTI" ? socTitle : reportType === "Pentest" ? vulnTitle : "ISO 27001 / PCI DSS Compliance Report",
severity: overallPosture,
systems: reportType === "Pentest" ? scopeDetails : socSystems,
description: reportType === "SOC_CTI" ? socDescription : reportType === "Pentest" ? executiveSummaryText : gapSummary,
root_cause: socRootCause,
recommendations: reportType === "SOC_CTI" ? socRecommendations : remediationPlanShortTerm,
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
poc_steps: pocStepsDetailed
}]);

if (error) alert(`Erreur: ${error.message}`);
else { alert(lang === "fr" ? "Rapport sauvegardé avec succès !" : "Report saved successfully!"); fetchReports(); }
setLoading(false);


};

const selectedTacticObj = MITRE_TACTICS.find(t => t.name === mitreTactic);

return (
<>
{@media print { body * { visibility: hidden; } #pdf-report, #pdf-report * { visibility: visible; } #pdf-report { position: absolute; left: 0; top: 0; width: 100%; margin: 0; padding: 20px; } .no-print { display: none !important; } .page-break { page-break-before: always; } }}

  <main className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
    
    {/* EN-TÊTE FIXE PANORAMIQUE */}
    <header className="bg-slate-900/90 border-b border-slate-800 px-8 py-4 flex flex-col md:flex-row items-center justify-between gap-4 sticky top-0 z-50 no-print">
      <div className="flex items-center gap-3">
        <Shield className="w-7 h-7 text-blue-500" />
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white">ReportShield Pro</h1>
          <p className="text-xs text-slate-400">
            {lang === "fr" ? "Plateforme Unifiée Pentest 8-Étapes, Incident SOC/CTI & Conformité" : "Unified 8-Step Pentest, SOC/CTI Incident & Compliance Platform"}
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
          <form onSubmit={async (e) => { e.preventDefault(); await supabase.auth.signInWithOtp({ email }); alert(lang === "fr" ? "Lien envoyé !" : "Link sent!"); }} className="flex gap-2">
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
        {lang === "fr" ? "Profil de Rapport Sélectionné :" : "Selected Report Profile:"}
      </span>
      <div className="flex gap-2">
        {[
          { id: "Pentest", label_fr: "🛡️ AUDIT DE SÉCURITÉ & PENTEST COMPLET (8 ÉTAPES)", label_en: "🛡️ FULL 8-STEP PENTEST AUDIT REPORT", color: "bg-amber-600/20 text-amber-400 border-amber-500/40" },
          { id: "SOC_CTI", label_fr: "🚨 INCIDENT SOC & THREAT INTEL (CTI)", label_en: "🚨 COMBINED SOC INCIDENT & CTI REPORT", color: "bg-red-600/20 text-red-400 border-red-500/40" },
          { id: "Compliance", label_fr: "📊 CONFORMITÉ ISO 27001 & PCI DSS", label_en: "📊 ISO 27001 & PCI DSS COMPLIANCE REPORT", color: "bg-emerald-600/20 text-emerald-400 border-emerald-500/40" }
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
      
      {/* COLONNE GAUCHE : FORMULAIRES DE SAISIE (SPAN 7) */}
      <div className="lg:col-span-7 space-y-6 no-print">

        {/* FORMULAIRE PENTEST ULTRA-COMPLET EN 8 ÉTAPES */}
        {reportType === "Pentest" && (
          <div className="space-y-6 animate-fadeIn">
            
            {/* ÉTAPE 1 : PAGE DE GARDE & MÉTADONNÉES */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-sm font-bold flex items-center gap-2 text-amber-400 border-b border-slate-800 pb-2">
                <FileText className="w-4 h-4" /> 1. Métadonnées du Livrable & Confidentialité (Cover Metadata)
              </h2>
              <div className="grid grid-cols-3 gap-3 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">Organisation Client</label>
                  <input type="text" value={clientName} onChange={(e) => setClientName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Cabinet / Prestataire</label>
                  <input type="text" value={auditFirm} onChange={(e) => setAuditFirm(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Lead Pentester</label>
                  <input type="text" value={analystName} onChange={(e) => setAnalystName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Date d'Émission</label>
                  <input type="date" value={date} onChange={(e) => setDate(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Version du Document</label>
                  <input type="text" value={reportVersion} onChange={(e) => setReportVersion(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Niveau TLP</label>
                  <select value={tlpLevel} onChange={(e) => setTLPLevel(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white">
                    <option value="TLP:RED">TLP:RED (Accès ultra-restreint)</option>
                    <option value="TLP:AMBER">TLP:AMBER (Confidentiel Client/Auditeur)</option>
                    <option value="TLP:GREEN">TLP:GREEN (Diffusion Interne)</option>
                  </select>
                </div>
              </div>
            </div>

            {/* ÉTAPE 2 : SYNTHÈSE EXÉCUTIVE */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-sm font-bold flex items-center gap-2 text-amber-400 border-b border-slate-800 pb-2">
                <Award className="w-4 h-4" /> 2. Synthèse Exécutive (Executive Summary)
              </h2>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">Niveau de Risque Global (Overall Posture)</label>
                  <select value={overallPosture} onChange={(e) => setOverallPosture(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-bold">
                    <option value="CRITIQUE">🔴 CRITIQUE / CRITICAL</option>
                    <option value="ÉLEVÉ">🟠 ÉLEVÉ / HIGH</option>
                    <option value="MOYEN">🟡 MOYEN / MEDIUM</option>
                    <option value="FAIBLE">🟢 FAIBLE / LOW</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Type de Test d'Intrusion</label>
                  <input type="text" value={pentestScopeType} onChange={(e) => setPentestScopeType(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Résumé Managérial des Constats Clés</label>
                <textarea rows={3} value={executiveSummaryText} onChange={(e) => setExecutiveSummaryText(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Recommandations Stratégiques Majeures (C-Level)</label>
                <textarea rows={2} value={topStrategicRecommendations} onChange={(e) => setTopStrategicRecommendations(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
              </div>
            </div>

            {/* ÉTAPE 3 : PÉRIMÈTRE & MÉTHODOLOGIE */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-sm font-bold flex items-center gap-2 text-amber-400 border-b border-slate-800 pb-2">
                <CheckSquare className="w-4 h-4" /> 3. Périmètre & Méthodologie (Scope & Rules of Engagement)
              </h2>
              <div className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">Périmètre Inclus (In-Scope)</label>
                  <input type="text" value={scopeDetails} onChange={(e) => setScopeDetails(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Périmètre Exclu (Out-of-Scope)</label>
                  <input type="text" value={excludedScope} onChange={(e) => setExcludedScope(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 mb-1">Référentiels & Standards</label>
                    <input type="text" value={methodologyStandard} onChange={(e) => setMethodologyStandard(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Fenêtre d'Exécution & Conditions</label>
                    <input type="text" value={testWindow} onChange={(e) => setTestWindow(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                  </div>
                </div>
              </div>
            </div>

            {/* ÉTAPE 4 : CALCULATEUR CVSS V3.1 & FICHE TECHNIQUE */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-sm font-bold flex items-center gap-2 text-amber-400 border-b border-slate-800 pb-2">
                <Calculator className="w-4 h-4" /> 4. Cotation de Risque CVSS v3.1 & Identification de la Faille
              </h2>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">Intitulé de la Vulnérabilité Majeure</label>
                  <input type="text" value={vulnTitle} onChange={(e) => setVulnTitle(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Mappage CWE / OWASP / PCI DSS</label>
                  <input type="text" value={vulnCweOwasp} onChange={(e) => setVulnCweOwasp(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white" />
                </div>
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Composants Affectés / Cibles</label>
                <input type="text" value={vulnTargetComps} onChange={(e) => setVulnTargetComps(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
              </div>

              {/* MATRICE DYNAMIQUE CVSS V3.1 */}
              <div className="border border-amber-500/30 bg-amber-950/20 p-4 rounded-xl space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-xs font-bold text-amber-400 flex items-center gap-1">Calculateur de Score CVSS v3.1</span>
                  <span className="text-xs font-bold bg-amber-600 text-white px-2.5 py-0.5 rounded">Score Calculé : {computedCvssScore} / 10</span>
                </div>

                <div className="grid grid-cols-4 gap-2 text-xs">
                  <div>
                    <label className="block text-[10px] text-slate-400">Attack Vector (AV)</label>
                    <select value={cvssAV} onChange={(e) => setCvssAV(parseFloat(e.target.value))} className="w-full bg-slate-950 border border-slate-800 rounded p-1 text-white">
                      <option value={0.85}>Network (N)</option>
                      <option value={0.62}>Adjacent (A)</option>
                      <option value={0.55}>Local (L)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] text-slate-400">Complexity (AC)</label>
                    <select value={cvssAC} onChange={(e) => setCvssAC(parseFloat(e.target.value))} className="w-full bg-slate-950 border border-slate-800 rounded p-1 text-white">
                      <option value={0.77}>Low (L)</option>
                      <option value={0.44}>High (H)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] text-slate-400">Privileges (PR)</label>
                    <select value={cvssPR} onChange={(e) => setCvssPR(parseFloat(e.target.value))} className="w-full bg-slate-950 border border-slate-800 rounded p-1 text-white">
                      <option value={0.85}>None (N)</option>
                      <option value={0.62}>Low (L)</option>
                      <option value={0.27}>High (H)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] text-slate-400">User Interaction (UI)</label>
                    <select value={cvssUI} onChange={(e) => setCvssUI(parseFloat(e.target.value))} className="w-full bg-slate-950 border border-slate-800 rounded p-1 text-white">
                      <option value={0.85}>None (N)</option>
                      <option value={0.62}>Required (R)</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>

            {/* ÉTAPE 5 : PREUVE DE CONCEPT (POC PAS-À-PAS) */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-sm font-bold flex items-center gap-2 text-amber-400 border-b border-slate-800 pb-2">
                <Terminal className="w-4 h-4" /> 5. Preuve de Concept Détaillée (PoC Steps & Replication)
              </h2>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Étapes Pas-à-Pas de Réplication Technique</label>
                <textarea rows={5} value={pocStepsDetailed} onChange={(e) => setPocStepsDetailed(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white font-mono" />
              </div>
            </div>

            {/* ÉTAPE 6 : CHAÎNE D'EXPLOITATION & ÉVALUATION SOC */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-sm font-bold flex items-center gap-2 text-amber-400 border-b border-slate-800 pb-2">
                <Zap className="w-4 h-4" /> 6. Chaîne d'Exploitation (Attack Path) & Test Evasion SOC
              </h2>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Enchaînement des Vulnérabilités (Kill Chain)</label>
                <input type="text" value={attackChainPath} onChange={(e) => setAttackChainPath(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Constats sur la Capacité de Détection / Réponse SOC</label>
                <textarea rows={2} value={socDetectionNotes} onChange={(e) => setSocDetectionNotes(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
              </div>
            </div>

            {/* ÉTAPE 7 : MATRICE DE REMÉDIATION & PLAN D'ACTION */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-sm font-bold flex items-center gap-2 text-amber-400 border-b border-slate-800 pb-2">
                <CheckCircle className="w-4 h-4" /> 7. Plan d'Action & Matrice de Remédiation Priorisée
              </h2>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Remédiations à Court Terme (Urgent - Correctifs)</label>
                <textarea rows={2} value={remediationPlanShortTerm} onChange={(e) => setRemediationPlanShortTerm(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white font-mono" />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Remédiations à Long Terme (Hardening & Architecture)</label>
                <textarea rows={2} value={remediationPlanLongTerm} onChange={(e) => setRemediationPlanLongTerm(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white font-mono" />
              </div>
            </div>

            {/* ÉTAPE 8 : ATTESTATION / CERTIFICAT EN ANNEXE */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-sm font-bold flex items-center gap-2 text-amber-400 border-b border-slate-800 pb-2">
                <FileCheck2 className="w-4 h-4" /> 8. Attestation de Réalisation & Certificat d'Audit
              </h2>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Texte Officiel de l'Attestation (Exportable Tiers/Assurances)</label>
                <textarea rows={2} value={certificateCustomNotes} onChange={(e) => setCertificateCustomNotes(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
              </div>
            </div>

          </div>
        )}

        {/* PROFIL 1 : COMBINÉ SOC + CTI */}
        {reportType === "SOC_CTI" && (
          <div className="space-y-6 animate-fadeIn">
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-base font-bold flex items-center gap-2 text-red-400 border-b border-slate-800 pb-3">
                <Activity className="w-5 h-5" /> Volet SOC & Incident Investigation
              </h2>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Titre de l'Incident</label>
                  <input type="text" value={socTitle} onChange={(e) => setSocTitle(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Périmètre Impacté</label>
                  <input type="text" value={socSystems} onChange={(e) => setSocSystems(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                </div>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Chronologie & Analyse du Déroulement</label>
                <textarea rows={3} value={socDescription} onChange={(e) => setSocDescription(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
              </div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-base font-bold flex items-center gap-2 text-cyan-400 border-b border-slate-800 pb-3">
                <Globe className="w-5 h-5" /> Threat Intelligence (CTI) & Threat Actor
              </h2>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Threat Actor / Groupe</label>
                  <input type="text" value={threatActor} onChange={(e) => setThreatActor(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Niveau de Confiance</label>
                  <input type="text" value={confidenceLevel} onChange={(e) => setConfidenceLevel(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-white" />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* PROFIL 3 : CONFORMITÉ ISO & PCI DSS */}
        {reportType === "Compliance" && (
          <div className="space-y-6 animate-fadeIn">
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h2 className="text-base font-bold text-emerald-400 border-b border-slate-800 pb-3">Conformité ISO 27001:2022 & PCI DSS v4.0</h2>
              <textarea rows={3} value={gapSummary} onChange={(e) => setGapSummary(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white" />
              <textarea rows={4} value={gapActionPlan} onChange={(e) => setGapActionPlan(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-white font-mono" />
            </div>
          </div>
        )}

      </div>

      {/* COLONNE DROITE : APERÇU INTÉGRAL DU DOCUMENT PDF (SPAN 5) */}
      <div className="lg:col-span-5 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-2xl flex flex-col items-center h-fit sticky top-24">
        <span className="text-xs font-semibold text-slate-400 mb-3 no-print flex items-center gap-2">
          <Cpu className="w-4 h-4 text-blue-400" /> {lang === "fr" ? "Aperçu du Rapport Exécutif & Technique" : "Executive & Technical PDF Preview"}
        </span>

        {/* DOCUMENT IMPRIMABLE COMPLET */}
        <div id="pdf-report" className="w-full bg-white text-slate-900 p-8 rounded-xl shadow-2xl border border-slate-200 text-xs space-y-6">
          
          {/* PAGE DE GARDE (SECTION 1) */}
          <div className="border-b-4 border-amber-600 pb-6 space-y-3">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-[10px] font-bold text-amber-600 uppercase tracking-widest">{auditFirm}</p>
                <h1 className="text-base font-extrabold uppercase text-slate-900">
                  {reportType === "Pentest" ? "Rapport d'Audit de Sécurité & Test d'Intrusion" :
                   reportType === "SOC_CTI" ? "Rapport Combiné Incident SOC & CTI" :
                   "Rapport d'Évaluation de Conformité ISO/PCI"}
                </h1>
              </div>
              <span className="text-[9px] font-bold bg-slate-900 text-white px-2 py-0.5 rounded">{tlpLevel}</span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[10px] text-slate-600 bg-slate-50 p-2.5 rounded border border-slate-200">
              <div><strong>Client :</strong> {clientName}</div>
              <div><strong>Lead Pentester :</strong> {analystName}</div>
              <div><strong>Date :</strong> {date}</div>
              <div><strong>Version :</strong> {reportVersion}</div>
            </div>
          </div>

          {/* TABLE DES MATIÈRES / SOMMAIRE */}
          {reportType === "Pentest" && (
            <div className="bg-slate-50 p-3 rounded border border-slate-200 space-y-1 text-[10px]">
              <p className="font-bold uppercase text-slate-800 border-b pb-1 mb-1">Sommaire du Rapport</p>
              <div className="grid grid-cols-2 gap-1 text-slate-700 font-mono">
                <div>1. Métadonnées & Confidentialité</div>
                <div>2. Synthèse Exécutive</div>
                <div>3. Périmètre & Méthodologie</div>
                <div>4. Cotation CVSS v3.1</div>
                <div>5. Preuve de Concept (PoC)</div>
                <div>6. Chaîne d'Exploitation</div>
                <div>7. Plan de Remédiation</div>
                <div>8. Attestation d'Audit</div>
              </div>
            </div>
          )}

          {/* SECTION 2: EXECUTIVE SUMMARY */}
          {reportType === "Pentest" && (
            <div className="space-y-3">
              <h2 className="text-[11px] font-bold text-slate-900 border-b pb-1 uppercase tracking-wider flex justify-between">
                <span>2. Synthèse Exécutive</span>
                <span className="text-red-600 font-extrabold">Postures : {overallPosture}</span>
              </h2>
              <p className="text-slate-800 leading-relaxed text-[11px] bg-amber-50/50 p-2.5 rounded border border-amber-200">{executiveSummaryText}</p>
              
              <div className="bg-slate-100 p-2.5 rounded border border-slate-200 space-y-1">
                <p className="font-bold text-[10px] text-slate-800 uppercase">Recommandations Stratégiques Direction (C-Level)</p>
                <p className="text-[10px] text-slate-700 whitespace-pre-line">{topStrategicRecommendations}</p>
              </div>
            </div>
          )}

          {/* SECTION 3: SCOPE & METHODOLOGY */}
          {reportType === "Pentest" && (
            <div className="space-y-2">
              <h2 className="text-[11px] font-bold text-slate-900 border-b pb-1 uppercase tracking-wider">3. Périmètre & Méthodologie</h2>
              <div className="grid grid-cols-2 gap-2 text-[10px]">
                <div className="bg-slate-50 p-2 rounded border border-slate-200">
                  <strong>In-Scope :</strong>
                  <p className="text-slate-700 font-mono">{scopeDetails}</p>
                </div>
                <div className="bg-slate-50 p-2 rounded border border-slate-200">
                  <strong>Out-of-Scope :</strong>
                  <p className="text-slate-700">{excludedScope}</p>
                </div>
              </div>
              <p className="text-[10px] text-slate-600"><strong>Normes :</strong> {methodologyStandard} | <strong>Conditions :</strong> {testWindow}</p>
            </div>
          )}

          {/* SECTION 4 & 5: CVSS & POC */}
          {reportType === "Pentest" && (
            <div className="space-y-3">
              <h2 className="text-[11px] font-bold text-slate-900 border-b pb-1 uppercase tracking-wider flex justify-between">
                <span>4. & 5. Fiche Technique & PoC</span>
                <span className="bg-amber-600 text-white px-2 py-0.5 rounded text-[10px]">CVSS v3.1 : {computedCvssScore}</span>
              </h2>

              <div className="bg-slate-50 p-2.5 rounded border border-slate-200 space-y-1">
                <p className="font-bold text-slate-900 text-[11px]">{vulnTitle}</p>
                <p className="text-[10px] text-amber-800 font-semibold">{vulnCweOwasp}</p>
                <p className="text-[10px] text-slate-600"><strong>Cible :</strong> {vulnTargetComps}</p>
              </div>

              <div>
                <p className="font-bold text-[10px] uppercase text-slate-700 mb-1">Preuve de Concept (PoC Step-by-Step)</p>
                <pre className="text-[10px] bg-slate-900 text-emerald-400 p-3 rounded font-mono whitespace-pre-wrap leading-tight overflow-x-auto">
                  {pocStepsDetailed}
                </pre>
              </div>
            </div>
          )}

          {/* SECTION 6 & 7: ATTACK PATH & REMEDIATION */}
          {reportType === "Pentest" && (
            <div className="space-y-3">
              <h2 className="text-[11px] font-bold text-slate-900 border-b pb-1 uppercase tracking-wider">6. & 7. Chemin d'Exploitation & Plan de Action</h2>
              
              <div className="bg-purple-50 border border-purple-200 p-2.5 rounded text-[10px] space-y-1">
                <p className="font-bold text-purple-950 uppercase">Kill Chain / Attack Path</p>
                <p className="font-mono text-purple-900">{attackChainPath}</p>
                <p className="text-slate-600 pt-1 border-t border-purple-200"><strong>Détection SOC :</strong> {socDetectionNotes}</p>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[10px]">
                <div className="bg-emerald-50 border border-emerald-200 p-2 rounded">
                  <strong className="text-emerald-950 uppercase block mb-1">Correctifs Immédiats</strong>
                  <p className="text-emerald-900 font-mono whitespace-pre-line">{remediationPlanShortTerm}</p>
                </div>
                <div className="bg-blue-50 border border-blue-200 p-2 rounded">
                  <strong className="text-blue-950 uppercase block mb-1">Hardening Long Terme</strong>
                  <p className="text-blue-900 font-mono whitespace-pre-line">{remediationPlanLongTerm}</p>
                </div>
              </div>
            </div>
          )}

          {/* SECTION 8: ATTESTATION D'AUDIT */}
          {reportType === "Pentest" && (
            <div className="border-t-2 border-slate-900 pt-4 mt-6 space-y-2">
              <h2 className="text-[11px] font-bold text-slate-900 uppercase tracking-wider">8. Attestation Officielles d'Audit de Sécurité</h2>
              <p className="text-[10px] text-slate-700 bg-slate-50 p-2.5 rounded border border-slate-200 italic">{certificateCustomNotes}</p>
              <div className="flex justify-between items-center pt-2 text-[9px] text-slate-500">
                <span>Certifié par : {auditFirm}</span>
                <span>Signé électroniquement par {analystName}</span>
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


---

### Résumé des ajouts dans cette mise à jour :
1. **Les 8 composants canoniques** sont intégrés dans le formulaire de saisie et le rendu imprimable du profil **Pentest**.
2. **Page de garde & TLP** avec marquage de confidentialité (`TLP:AMBER`, `TLP:RED`, etc.) et numéro de version du livrable.
3. **Sommaire interactif** structurant l'indexation du document.
4. **Calculateur CVSS v3.1 dynamique** avec évaluation des vecteurs d'attaque.
5. **Preuve de concept (PoC)** sous forme de blocs de code pour la réplication technique.
6. **Cartographie Kill Chain & Evasion SOC** pour mesurer la réponse des équipes de défense.
7. **Attestation de réalisation en Annexe** directement exportable pour les tiers, audits de conformité ou assurances.
