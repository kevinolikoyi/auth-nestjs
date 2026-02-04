import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
    private transporter: nodemailer.Transporter;

    constructor(private configService: ConfigService) {
        const host = this.configService.get<string>('EMAIL_HOST');
        const port = parseInt(this.configService.get<string>('EMAIL_PORT') || '587', 10);
        const user = this.configService.get<string>('EMAIL_USER');
        const password = this.configService.get<string>('EMAIL_PASSWORD');

        // Validation des variables requises
        if (!host || !user || !password) {
            console.warn('Configuration email incomplète. Vérifiez vos variables d\'environnement.');
        }

        // secure = true pour le port 465 (SSL), false pour les autres ports (STARTTLS)
        const secure = port === 465;

        this.transporter = nodemailer.createTransport({
            host,
            port,
            secure,
            auth: {
                user,
                pass: password,
            },
        });
    }

    async sendVerificationEmail(email: string, token: string) {
        const appUrl = this.configService.get('APP_URL') || 'http://localhost:3000';
        const url = `${appUrl}/api/auth/verify-email?token=${token}`;

        // Afficher les infos dans la console pour le développement
        console.log('📧 Email de vérification:');
        console.log('   À:', email);
        console.log('   Token:', token);
        console.log('   URL:', url);

        // Envoyer l'email réel
        try {
            const fromEmail = this.configService.get<string>('EMAIL_FROM') || 'noreply@test.com';

            await this.transporter.sendMail({
                from: fromEmail,
                to: email,
                subject: 'Vérifiez votre adresse email',
                html: `
                <!DOCTYPE html>
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h1 style="color: #4F46E5;">Bienvenue sur ${this.configService.get('APP_NAME')} ! 🎉</h1>
                    
                    <p>Merci de vous être inscrit. Pour activer votre compte, veuillez vérifier votre adresse email en cliquant sur le bouton ci-dessous :</p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${url}" 
                        style="background-color: #4F46E5; color: white; padding: 12px 30px; 
                                text-decoration: none; border-radius: 5px; display: inline-block;">
                        Vérifier mon email
                        </a>
                    </div>
                    
                    <p style="color: #666; font-size: 14px;">
                        Ce lien expire dans 24 heures.
                    </p>
                    
                    <p style="color: #666; font-size: 14px;">
                        Si le bouton ne fonctionne pas, copiez ce lien dans votre navigateur :<br>
                        <a href="${url}" style="color: #4F46E5;">${url}</a>
                    </p>
                    
                    <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                    
                    <p style="color: #999; font-size: 12px;">
                        Vous avez reçu cet email car quelqu'un a créé un compte avec cette adresse.<br>
                        Si ce n'était pas vous, ignorez simplement cet email.
                    </p>
                    </div>
                </body>
                </html>
                `,
            });
            console.log('Email envoyé avec succès');
        } catch (error) {
            console.error('Erreur lors de l\'envoi de l\'email:', (error as Error).message);
            throw error;
        }
    }

    async sendPasswordResetEmail(email: string, token: string) {
        const appUrl = this.configService.get('APP_URL') || 'http://localhost:3000';
        const url = `${appUrl}/api/auth/reset-password?token=${token}`;

        // Afficher les infos dans la console pour le développement
        console.log('📧 Email de réinitialisation:');
        console.log('   À:', email);
        console.log('   Token:', token);
        console.log('   URL:', url);

        // Envoyer l'email réel
        try {
            const fromEmail = this.configService.get<string>('EMAIL_FROM') || 'noreply@test.com';

            await this.transporter.sendMail({
                from: fromEmail,
                to: email,
                subject: 'Réinitialisation de votre mot de passe',
                html: `
        <h1>Réinitialisation du mot de passe</h1>
        <p>Vous avez demandé à réinitialiser votre mot de passe. Cliquez sur le lien ci-dessous :</p>
        <a href="${url}">Réinitialiser mon mot de passe</a>
        <p>Ce lien expire dans 1 heure.</p>
        <p>Token de réinitialisation : <strong>${token}</strong></p>
        <p>Si vous n'avez pas demandé cette réinitialisation, ignorez cet email.</p>
      `,
            });
            console.log('Email envoyé avec succès');
        } catch (error) {
            console.error('Erreur lors de l\'envoi de l\'email:', (error as Error).message);
            throw error;
        }
    }
}