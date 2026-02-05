import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtBlacklistService } from './jwt-blacklist.service';
import { UsersService } from '../../users/users.service';
import { ConfigService } from '@nestjs/config';
import { sanitizeUser } from '../../users/utils/user-sanitizer.util';

export interface JwtPayload {
    sub: number;
    email: string;
    iat?: number;
    exp?: number;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        private readonly usersService: UsersService,
        private readonly configService: ConfigService,
        private readonly jwtBlacklistService: JwtBlacklistService,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: configService.get('JWT_ACCESS_SECRET'),
            passReqToCallback: true,
        });
    }

    async validate(req: any, payload: JwtPayload) {
        // Extraire le token de la requête
        const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);

        // Vérifier si le token est présent dans la requête
        if (!token) {
            throw new UnauthorizedException('Access token not found');
        }

        // Vérifier si le token est blacklisté
        const isRevoked = await this.jwtBlacklistService.isTokenRevoked(token);
        if (isRevoked) {
            throw new UnauthorizedException('Token has been revoked');
        }

        const user = await this.usersService.findOne(payload.sub);
        if (!user) {
            throw new UnauthorizedException('User not found');
        }
        // Exclure tous les champs sensibles avant de mettre dans req.user
        return sanitizeUser(user);
    }
}
