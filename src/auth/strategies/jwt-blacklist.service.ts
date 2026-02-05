import { Injectable, Logger } from '@nestjs/common';
import { DatabaseService } from '../../database/database.service';
import { Cron, CronExpression } from '@nestjs/schedule';

export type TokenType = 'access' | 'refresh';

@Injectable()
export class JwtBlacklistService {
    private readonly logger = new Logger(JwtBlacklistService.name);

    constructor(private readonly db: DatabaseService) { }

    // Ajouter un token à la blacklist
    async revokeToken(
        token: string,
        tokenType: TokenType,
        userId: number,
        expiresAt: Date,
        reason?: string,
    ): Promise<void> {
        try {
            await this.db.tokenBlacklist.create({
                data: {
                    token,
                    tokenType,
                    userId,
                    expiresAt,
                    reason: reason || 'logout',
                },
            });

            this.logger.log(
                `Token ${tokenType} révoqué pour l'utilisateur ${userId}. Raison: ${reason}`
            );
        } catch (error) {
            // Ignorer si le token est déjà blacklisté (erreur duplicate)
            if (error.code !== 'P2002') {
                this.logger.error('Erreur lors de la révocation du token', error);
                throw error;
            }
        }
    }

    // Vérifier si un token est révoqué
    async isTokenRevoked(token: string): Promise<boolean> {
        const blacklisted = await this.db.tokenBlacklist.findUnique({
            where: { token },
        });
        return !!blacklisted;
    }

    // Révoquer plusieurs tokens
    async revokeMultipleTokens(
        tokens: Array<{
            token: string;
            tokenType: TokenType;
            userId: number;
            expiresAt: Date;
            reason?: string;
        }>,
    ): Promise<void> {
        try {
            await this.db.tokenBlacklist.createMany({
                data: tokens.map(t => ({
                    token: t.token,
                    tokenType: t.tokenType,
                    userId: t.userId,
                    expiresAt: t.expiresAt,
                    reason: t.reason || 'logout',
                })),
                skipDuplicates: true, // Ignorer les doublons
            });

            this.logger.log(`${tokens.length} token(s) révoqué(s)`);
        } catch (error) {
            this.logger.error('Erreur lors de la révocation multiple', error);
            throw error;
        }
    }

    // Nettoyer les tokens expirés (cron job)
    @Cron(CronExpression.EVERY_DAY_AT_3AM)
    async cleanExpiredTokens(): Promise<void> {
        try {
            const result = await this.db.tokenBlacklist.deleteMany({
                where: {
                    expiresAt: {
                        lt: new Date(),
                    },
                },
            });

            this.logger.log(`Nettoyage effectué: ${result.count} tokens expirés supprimés`);
        } catch (error) {
            this.logger.error('Erreur lors du nettoyage des tokens expirés', error);
        }
    }
}