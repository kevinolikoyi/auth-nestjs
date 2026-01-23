import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

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
  SwaggerModule.setup('api/docs', app, document);

  const port = process.env.PORT ?? 3000;
  await app.listen(port);

  console.log(`🚀 Application running on: http://localhost:${port}`);
  console.log(`📚 Swagger documentation: http://localhost:${port}/api/docs`);
}
void bootstrap();
