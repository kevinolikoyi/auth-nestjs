import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ExpressAdapter } from '@nestjs/platform-express';
import { ValidationPipe } from '@nestjs/common';
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

export async function createApp(
    expressApp?: express.Express,
): Promise<express.Express> {
    const adapter = new ExpressAdapter(expressApp ?? express());
    const app = await NestFactory.create(AppModule, adapter);
    const appUrl = process.env.APP_URL || 'http://localhost:3000';

    app.use(helmet());
    app.use(cookieParser());

    app.setGlobalPrefix('api');
    app.enableCors({
        origin: true,
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

      # Guide d'utilisation dans Swagger UI:

      ## Étape 1: Connexion
      1. Appeler **POST /auth/login** avec vos identifiants (email et mot de passe)
      2. La réponse contient un **accessToken** dans le body
      3. Un **refreshToken** est automatiquement stocké dans un cookie HTTPOnly (non visible dans la réponse)

      ## Étape 2: Utiliser les routes protégées
      1. Cliquer sur le bouton **"Authorize"** (🔒) en haut à droite de Swagger UI
      2. Dans la section **"BearerAuth"**, coller votre **accessToken** (sans le préfixe "Bearer ")
      3. Cliquer sur **"Authorize"** puis **"Close"**
      4. Toutes les routes protégées utiliseront maintenant ce token automatiquement

      ## Étape 3: Rafraîchir le token d'accès
      - Appeler **POST /auth/refresh** (le cookie refreshToken est envoyé automatiquement)
      - Vous recevrez un nouveau **accessToken** à utiliser dans l'étape 2

      ## Notes importantes:
      - L'**accessToken** expire après 1 minute (configurable)
      - Le **refreshToken** expire après 7 jours
      - Le cookie refreshToken est envoyé automatiquement grâce à la configuration \`withCredentials: true\`
      - Après expiration de l'accessToken, utilisez **POST /auth/refresh** pour en obtenir un nouveau
    `,
        )
        .setVersion('1.0.0')
        .addServer(appUrl, 'Serveur principal')
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
    // Force Swagger à respecter le préfixe global 'api' -> /api/docs
    SwaggerModule.setup('docs', app, document, {
        useGlobalPrefix: true,
        swaggerOptions: {
            // Nécessaire pour que le navigateur envoie le cookie `refreshToken`
            // aux endpoints (ex: /auth/refresh) depuis Swagger UI.
            withCredentials: true,
            persistAuthorization: true,
        },
        customCssUrl: 'https://unpkg.com/swagger-ui-dist/swagger-ui.css',
        customJs: [
            'https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js',
            'https://unpkg.com/swagger-ui-dist/swagger-ui-standalone-preset.js',
        ],
    });

    await app.init();

    return app.getHttpAdapter().getInstance() as express.Express;
}
