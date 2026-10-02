import { NextResponse } from 'next/server';
import { Resend } from 'resend';

// Initialisation de Resend avec la clé API récupérée dans les variables d'environnement
const resend = new Resend(process.env.RESEND_API_KEY);

export async function POST(request: Request) {
  try {
    const { email } = await request.json();

    if (!email) {
      return NextResponse.json({ error: 'Email requis' }, { status: 400 });
    }

    // Génération d'un lien sécurisé simulé (ou token unique pour une vraie BDD)
    const resetLink = `https://report-shield.vercel.app/reset-password?email=${encodeURIComponent(email)}`;

    // Envoi de l'e-mail via Resend
    const { data, error } = await resend.emails.send({
      from: 'ReportShield Pro <onboarding@resend.dev>', // Adresse par défaut testable de Resend
      to: [email],
      subject: 'Réinitialisation de votre mot de passe - ReportShield Pro',
      html: `
        <div style="font-family: Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 30px; border-radius: 12px;">
          <h2 style="color: #38bdf8;">ReportShield Pro - Sécurité & SOC</h2>
            <p>Bonjour,</p>
            <p>Vous avez demandé la réinitialisation de votre mot de passe pour votre compte <strong>${email}</strong>.</p>
            <p>Cliquez sur le bouton ci-dessous pour définir un nouveau mot de passe :</p>
            <a href="${resetLink}" style="display: inline-block; background-color: #0284c7; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 20px 0;">Réinitialiser mon mot de passe</a>
            <p style="color: #94a3b8; font-size: 12px;">Si vous n'êtes pas à l'origine de cette demande, vous pouvez ignorer cet e-mail en toute sécurité.</p>
        </div>
      `,
    });

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }

    return NextResponse.json({ success: true, data });
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : 'Erreur interne du serveur';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}