import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ExpressAdapter } from '@nestjs/platform-express';
import { ValidationPipe } from '@nestjs/common';
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

export async function createApp(expressApp?: express.Express) {
    const adapter = new ExpressAdapter(expressApp ?? express());
    const app = await NestFactory.create(AppModule, adapter);

    app.use(helmet());
    app.use(cookieParser());

    app.setGlobalPrefix('api');
    app.enableCors({
        origin: process.env.FRONTEND_URL || 'http://localhost:3000',
        credentials: true,
    });

    app.useGlobalPipes(
        new ValidationPipe({
            whitelist: true,
            forbidNonWhitelisted: true,
            transform: true,
        }),
    );

    const config = new DocumentBuilder()
        .setTitle("API d'Authentification NestJS")
        .setDescription(
            `
      API REST complète pour la gestion des utilisateurs et de l'authentification avec JWT.

      # Fonctionnalités principales:
      - Inscription avec validation d'email
      - Connexion et gestion des sessions
      - Gestion du profil utilisateur
      - Mot de passe oublié par email
      - Administration des utilisateurs (rôles USER et ADMIN)

      # Types d'utilisateurs:
      - USER: Peut créer son compte, gérer son profil, utiliser les fonctionnalités d'authentification
      - ADMIN: Tous les droits des utilisateurs + gestion complète des comptes utilisateurs

      # Authentification:
      - Utilise JWT pour l'accès (Bearer token)
      - Refresh tokens stockés dans des cookies HTTPOnly
      - Guards pour la protection des routes selon les rôles
    `,
        )
        .setVersion('1.0.0')
        .addServer('http://localhost:3000', 'Développement')
        .addBearerAuth(
            {
                type: 'http',
                scheme: 'bearer',
                bearerFormat: 'JWT',
                description: "Token JWT d'accès (expire après 1 minute)",
            },
            'BearerAuth',
        )
        .addCookieAuth(
            'refreshToken',
            {
                type: 'apiKey',
                in: 'cookie',
                name: 'refreshToken',
                description:
                    'Token de rafraîchissement (HttpOnly cookie, expire après 7 jours)',
            },
            'CookieAuth',
        )
        .addTag(
            'Authentification',
            "Endpoints pour l'inscription, connexion et gestion des sessions",
        )
        .addTag(
            'Utilisateurs',
            'Gestion des utilisateurs (réservé aux administrateurs)',
        )
        .addTag('Profil', 'Gestion du profil utilisateur connecté')
        .build();

    const document = SwaggerModule.createDocument(app, config);
    // Avec setGlobalPrefix('api'), 'docs' devient /api/docs
    SwaggerModule.setup('docs', app, document);

    await app.init();

    return app.getHttpAdapter().getInstance();
}
