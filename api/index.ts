import type { VercelRequest, VercelResponse } from '@vercel/node';
import express from 'express';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { ExpressAdapter } from '@nestjs/platform-express';

import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

let cachedServer: any;

async function bootstrap() {
    if (cachedServer) return cachedServer;

    const expressApp = express();
    const app = await NestFactory.create(AppModule, new ExpressAdapter(expressApp));

    app.use(helmet());
    app.use(cookieParser());

    app.enableCors({
        origin: process.env.FRONTEND_URL || true,
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
        .setVersion('1.0.0')
        .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('docs', app, document); // => /api/docs sur Vercel

    await app.init();

    cachedServer = expressApp;
    return cachedServer;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
    const server = await bootstrap();
    return server(req, res);
}
