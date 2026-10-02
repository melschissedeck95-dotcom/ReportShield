'use client';

import React, { useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { Shield, Lock, CheckCircle, ArrowLeft } from 'lucide-react';
import Link from 'next/link';

export default function ResetPasswordPage() {
  const searchParams = useSearchParams();
  const email = searchParams.get('email') || '';
  
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState('');

  const handleResetSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (newPassword !== confirmPassword) {
      setError("Les mots de passe ne correspondent pas.");
      return;
    }

    if (newPassword.length < 6) {
      setError("Le mot de passe doit contenir au moins 6 caractères.");
      return;
    }

    // Simulation de la mise à jour du mot de passe (ou appel vers ta base Supabase/API)
    setSuccess(true);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center items-center p-6 font-sans">
      <div className="max-w-md w-full bg-slate-900 border border-slate-800 p-8 rounded-2xl shadow-xl">
        
        <div className="flex items-center space-x-3 mb-6 justify-center">
          <div className="bg-cyan-500/10 p-2.5 rounded-lg border border-cyan-500/35">
            <Shield className="w-7 h-7 text-cyan-400" />
          </div>
          <h1 className="font-bold text-xl text-cyan-400">ReportShield Pro</h1>
        </div>

        <div className="text-center mb-6">
          <h2 className="text-xl font-bold text-slate-100">Nouveau mot de passe</h2>
          <p className="text-xs text-slate-400 mt-1">
            Définition des nouveaux accès pour <span className="text-cyan-400 font-medium">{email || "votre compte"}</span>
          </p>
        </div>

        {success ? (
          <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-5 rounded-xl text-center space-y-4">
            <CheckCircle className="w-10 h-10 mx-auto text-emerald-400" />
            <p className="text-sm">Votre mot de passe a été réinitialisé avec succès !</p>
            <Link 
              href="/"
              className="inline-block w-full bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold py-2.5 rounded-lg text-sm transition text-center"
            >
              Se connecter avec le nouveau mot de passe
            </Link>
          </div>
        ) : (
          <form onSubmit={handleResetSubmit} className="space-y-4">
            {error && (
              <div className="bg-rose-500/10 border border-rose-500/30 text-rose-400 p-3 rounded-lg text-xs text-center">
                {error}
              </div>
            )}

            <div>
              <label className="block text-xs uppercase tracking-wider text-slate-400 mb-1 font-semibold">Nouveau mot de passe</label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 w-5 h-5 text-slate-500" />
                <input 
                  type="password" 
                  required 
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="••••••••" 
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-10 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-cyan-500" 
                />
              </div>
            </div>

            <div>
              <label className="block text-xs uppercase tracking-wider text-slate-400 mb-1 font-semibold">Confirmer le mot de passe</label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 w-5 h-5 text-slate-500" />
                <input 
                  type="password" 
                  required 
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••" 
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-10 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-cyan-500" 
                />
              </div>
            </div>

            <button type="submit" className="w-full bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold py-2.5 rounded-lg transition text-sm">
              Mettre à jour le mot de passe
            </button>
          </form>
        )}

        <div className="mt-6 text-center">
          <Link href="/" className="text-xs text-slate-400 hover:text-slate-200 flex items-center justify-center transition">
            <ArrowLeft className="w-4 h-4 mr-1" /> Retour à la page de connexion
          </Link>
        </div>

      </div>
    </div>
  );
}