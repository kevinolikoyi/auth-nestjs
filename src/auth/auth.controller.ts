import {
    Body,
    Controller,
    Get,
    HttpCode,
    HttpStatus,
    Patch,
    Post,
    Query,
    Request,
    Res,
    UseGuards,
} from '@nestjs/common';
import type { Request as ExpressRequest, Response } from 'express';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { CreateAdminDto } from './dto/create-admin.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResendVerificationDto } from './dto/resend-email.dto'
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { JwtAuthGuard } from './guards/jwt-auth-guard';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { UpdateUserDto } from '../users/dto/update-user.dto';
import { JwtBlacklistService } from './strategies/jwt-blacklist.service';
import { CurrentUser } from './decorators/current-user.decorator';
import {
    ApiTags,
    ApiOperation,
    ApiResponse,
    ApiBearerAuth,
    ApiCookieAuth,
} from '@nestjs/swagger';

interface JwtPayload {
    sub: number;
    email: string;
    iat?: number;
    exp?: number;
}

type RefreshRequest = ExpressRequest & {
    user: {
        userId: number;
        refreshToken: string;
    };
};

type AccessRequest = ExpressRequest & {
    user: {
        id: number;
    } & Record<string, unknown>;
};

type LoginResult = {
    user: Record<string, unknown>;
    accessToken: string;
    refreshToken: string;
};

@ApiTags('Authentification')
@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly jwtService: JwtService,
        private readonly jwtBlacklistService: JwtBlacklistService,
    ) { }

    // ÉTAPE 1 : Création du premier admin
    @Post('create-first-admin')
    @ApiOperation({
        summary: 'Création du premier admin',
        description:
            'Crée le premier administrateur du système. À utiliser une seule fois pour initialiser le compte administrateur.',
    })
    @ApiResponse({
        status: 201,
        description: 'Admin créé avec succès',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'string',
                    example: 'First admin created successfully',
                },
                user: {
                    type: 'object',
                    properties: {
                        id: { type: 'number', example: 1 },
                        email: { type: 'string', example: 'admin@test.com' },
                        firstName: { type: 'string', example: 'Admin' },
                        lastName: { type: 'string', example: 'User' },
                        role: { type: 'string', example: 'ADMIN' },
                        isEmailVerified: { type: 'boolean', example: true },
                        createdAt: { type: 'string', format: 'date-time' },
                        updatedAt: { type: 'string', format: 'date-time' },
                    },
                },
            },
        },
    })
    @ApiResponse({ status: 409, description: 'Un administrateur existe déjà' })
    @HttpCode(HttpStatus.CREATED)
    async createFirstAdmin(@Body() registerDto: CreateAdminDto) {
        return this.authService.createFirstAdmin(registerDto);
    }

    // ÉTAPE 2 : Inscription
    @Post('register')
    @ApiOperation({
        summary: "Inscription d'un nouvel utilisateur",
        description:
            "Crée un nouveau compte utilisateur avec validation d'email. Un email de vérification sera envoyé automatiquement.",
    })
    @ApiResponse({
        status: 201,
        description:
            'Utilisateur créé avec succès. Un email de vérification a été envoyé.',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'string',
                    example:
                        'User created successfully. Please check your email to verify your account.',
                },
                user: {
                    type: 'object',
                    properties: {
                        id: { type: 'number', example: 1 },
                        email: { type: 'string', example: 'user@test.com' },
                        firstName: { type: 'string', example: 'John' },
                        lastName: { type: 'string', example: 'Doe' },
                        role: { type: 'string', example: 'USER' },
                        isEmailVerified: { type: 'boolean', example: false },
                        createdAt: { type: 'string', format: 'date-time' },
                    },
                },
            },
        },
    })
    @ApiResponse({ status: 409, description: 'Email déjà utilisé' })
    @ApiResponse({ status: 400, description: 'Données invalides' })
    @HttpCode(HttpStatus.CREATED)
    async register(@Body() registerDto: RegisterDto) {
        return this.authService.register(registerDto);
    }

    @Get('verify-email')
    @ApiOperation({
        summary: "Vérification de l'email",
        description:
            "Vérifie le token d'email et connecte automatiquement l'utilisateur si le token est valide.",
    })
    @ApiResponse({
        status: 200,
        description: 'Email vérifié avec succès',
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'Email verified successfully' },
            },
        },
    })
    @ApiResponse({
        status: 400,
        description:
            'Token invalide ou expiré. Utilisez POST /auth/resend-verification pour obtenir un nouveau lien.'
    })
    @HttpCode(HttpStatus.OK)
    async verifyEmail(
        @Query() query: VerifyEmailDto,
        @Res({ passthrough: true }) response: Response,
    ) {
        const result = await this.authService.verifyEmail(query.token);

        // Si la vérification inclut une connexion automatique
        if (result.autoLogin && result.refreshToken) {
            // Définir le refresh token dans un cookie HTTPOnly
            response.cookie('refreshToken', result.refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 jours
            });

            // Ne pas retourner le refresh token dans la réponse
            const { refreshToken, ...responseData } = result;
            return responseData;
        }

        return result;
    }

    @Post('resend-verification')
    @ApiOperation({
        summary: "Renvoyer l'email de vérification",
        description: `Envoie un nouveau lien de vérification. 
    
    **Limitations:**
    - Maximum 3 emails par heure
    - Le nouveau lien expire après 1 minute`
    })
    @ApiResponse({
        status: 200,
        description: 'Email de vérification renvoyé avec succès',
    })
    @ApiResponse({
        status: 400,
        description: 'Email déjà vérifié ou trop de tentatives (max 3/heure)'
    })
    @HttpCode(HttpStatus.OK)
    async resendVerification(@Body() dto: ResendVerificationDto) {
        return this.authService.resendVerificationEmail(dto.email);
    }

    // ÉTAPE 3 : Authentification
    @Post('login')
    @ApiOperation({
        summary: "Connexion d'un utilisateur",
        description: `Authentifie un utilisateur avec email et mot de passe.

**Important pour Swagger UI:**
- La réponse contient un **accessToken** que vous devez copier
- Un **refreshToken** est automatiquement stocké dans un cookie HTTPOnly (non visible dans la réponse JSON)
- Après la connexion, cliquez sur **"Authorize"** (🔒) en haut à droite et collez votre accessToken dans la section "BearerAuth"`,
    })
    @ApiResponse({
        status: 200,
        description: 'Connexion réussie',
        schema: {
            type: 'object',
            properties: {
                accessToken: {
                    type: 'string',
                    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                },
                user: {
                    type: 'object',
                    properties: {
                        id: { type: 'number', example: 1 },
                        email: { type: 'string', example: 'user@test.com' },
                        firstName: { type: 'string', example: 'John' },
                        lastName: { type: 'string', example: 'Doe' },
                        role: { type: 'string', example: 'USER' },
                        isEmailVerified: { type: 'boolean', example: true },
                    },
                },
            },
        },
    })
    @ApiResponse({ status: 401, description: 'Email ou mot de passe incorrect' })
    @ApiResponse({ status: 403, description: 'Email non vérifié' })
    @HttpCode(HttpStatus.OK)
    async login(
        @Body() loginDto: LoginDto,
        @Res({ passthrough: true }) response: Response,
    ) {
        const result = (await this.authService.login(
            loginDto,
        )) as unknown as LoginResult;

        // Définir le refresh token dans un cookie HTTPOnly
        response.cookie('refreshToken', result.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 jours
        });

        // Ne pas retourner le refresh token dans la réponse
        return { accessToken: result.accessToken, user: result.user };
    }

    @UseGuards(JwtRefreshGuard)
    @Post('refresh')
    @ApiOperation({
        summary: 'Rafraîchissement du token',
        description: `Rafraîchit le token d'accès en utilisant le refreshToken stocké dans un cookie.

**Important pour Swagger UI:**
- Ce endpoint utilise le cookie **refreshToken** qui a été défini lors de la connexion (POST /auth/login)
- Le cookie est envoyé automatiquement par le navigateur (grâce à \`withCredentials: true\`)
- Vous recevrez un nouveau **accessToken** à utiliser dans les routes protégées
- Mettez à jour votre token dans "Authorize" après avoir appelé cet endpoint`,
    })
    @ApiResponse({ status: 200, description: 'Token rafraîchi avec succès' })
    @ApiResponse({ status: 401, description: 'Token invalide' })
    @ApiCookieAuth('CookieAuth')
    @HttpCode(HttpStatus.OK)
    async refresh(
        @Request() req: RefreshRequest,
        @Res({ passthrough: true }) response: Response,
    ) {
        const tokens = await this.authService.refreshTokens(
            req.user.userId,
            req.user.refreshToken,
        );

        response.cookie('refreshToken', tokens.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return { accessToken: tokens.accessToken };
    }

    // Logout sans guard pour gérer tokens invalides
    @Post('logout')
    @ApiOperation({
        summary: 'Déconnexion complète',
        description:
            "Révoque l'access token ET le refresh token, puis supprime le cookie. Fonctionne même si les tokens sont invalides ou expirés.",
    })
    @ApiResponse({
        status: 200,
        description: 'Déconnexion réussie',
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'Logged out successfully' },
                tokensRevoked: {
                    type: 'object',
                    properties: {
                        accessToken: { type: 'boolean', example: true },
                        refreshToken: { type: 'boolean', example: true },
                    },
                },
            },
        },
    })
    @HttpCode(HttpStatus.OK)
    async logout(
        @Request() req: ExpressRequest,
        @Res({ passthrough: true }) res: Response,
    ) {
        const tokensRevoked = {
            accessToken: false,
            refreshToken: false,
        };

        // 1. RÉVOQUER L'ACCESS TOKEN (si présent)
        try {
            const accessToken = req.headers.authorization?.replace('Bearer ', '');

            if (accessToken) {
                const decoded = this.jwtService.decode(accessToken) as JwtPayload;

                if (decoded && decoded.exp && decoded.sub) {
                    const expiresAt = new Date(decoded.exp * 1000);

                    await this.jwtBlacklistService.revokeToken(
                        accessToken,
                        'access',
                        decoded.sub,
                        expiresAt,
                        'logout',
                    );

                    tokensRevoked.accessToken = true;
                }
            }
        } catch (error) {
            console.log('Access token non valide ou déjà expiré:', (error as Error).message);
        }

        // 2. RÉVOQUER LE REFRESH TOKEN (si présent dans le cookie)
        try {
            const refreshToken = req.cookies?.refreshToken;

            if (refreshToken) {
                const decoded = this.jwtService.decode(refreshToken) as JwtPayload;

                if (decoded && decoded.exp && decoded.sub) {
                    const expiresAt = new Date(decoded.exp * 1000);

                    await this.jwtBlacklistService.revokeToken(
                        refreshToken,
                        'refresh',
                        decoded.sub,
                        expiresAt,
                        'logout',
                    );

                    // Révoquer également dans la base de données User
                    await this.authService.logout(decoded.sub);

                    tokensRevoked.refreshToken = true;
                }
            }
        } catch (error) {
            console.log('Refresh token non valide ou déjà expiré:', (error as Error).message);
        }

        // 3. TOUJOURS SUPPRIMER LE COOKIE (même si tokens invalides)
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });

        return {
            message: 'Logged out successfully',
            tokensRevoked,
        };
    }

    // ÉTAPE 4 : Gestion du mot de passe
    @Post('forgot-password')
    @ApiOperation({
        summary: 'Demande de réinitialisation de mot de passe',
        description:
            "Envoie un email de réinitialisation de mot de passe à l'adresse email fournie.",
    })
    @ApiResponse({
        status: 200,
        description: 'Email de réinitialisation envoyé avec succès',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'string',
                    example: 'Password reset email sent successfully',
                },
            },
        },
    })
    @ApiResponse({ status: 400, description: 'Email invalide ou non trouvé' })
    @HttpCode(HttpStatus.OK)
    async forgotPassword(@Body() dto: ForgotPasswordDto) {
        return this.authService.forgotPassword(dto.email);
    }

    @Get('reset-password')
    @ApiOperation({
        summary: 'Vérification du token de réinitialisation',
        description:
            'Vérifie la validité du token de réinitialisation de mot de passe avant de permettre la réinitialisation.',
    })
    @ApiResponse({
        status: 200,
        description: 'Token de réinitialisation valide',
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'Reset token is valid' },
            },
        },
    })
    @ApiResponse({ status: 400, description: 'Token invalide ou expiré' })
    @HttpCode(HttpStatus.OK)
    async verifyResetToken(@Query('token') token: string) {
        return this.authService.verifyResetToken(token);
    }

    @Post('reset-password')
    @ApiOperation({
        summary: 'Réinitialisation de mot de passe',
        description:
            "Réinitialise le mot de passe d'un utilisateur en utilisant le token reçu par email.",
    })
    @ApiResponse({
        status: 200,
        description: 'Mot de passe réinitialisé avec succès',
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'Password reset successfully' },
            },
        },
    })
    @ApiResponse({
        status: 400,
        description: 'Token invalide, expiré ou mot de passe invalide',
    })
    @HttpCode(HttpStatus.OK)
    async resetPassword(@Body() dto: ResetPasswordDto) {
        return this.authService.resetPassword(dto.token, dto.newPassword);
    }

    // ÉTAPE 5 : Gestion du profil
    @UseGuards(JwtAuthGuard)
    @ApiTags('Profil')
    @Get('profile')
    @ApiOperation({
        summary: 'Récupération du profil utilisateur',
        description: `Récupère les informations du profil de l'utilisateur actuellement connecté.

**Route protégée:** Nécessite un accessToken valide dans le header Authorization (Bearer token).
Assurez-vous d'avoir configuré votre token dans "Authorize" avant d'appeler cet endpoint.`,
    })
    @ApiResponse({
        status: 200,
        description: 'Profil récupéré avec succès',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'string',
                    example: 'This is a protected profile route',
                },
                user: {
                    type: 'object',
                    properties: {
                        id: { type: 'number', example: 1 },
                        email: { type: 'string', example: 'user@test.com' },
                        firstName: { type: 'string', example: 'John' },
                        lastName: { type: 'string', example: 'Doe' },
                        role: { type: 'string', example: 'USER' },
                        isEmailVerified: { type: 'boolean', example: true },
                        createdAt: { type: 'string', format: 'date-time' },
                        updatedAt: { type: 'string', format: 'date-time' },
                    },
                },
            },
        },
    })
    @ApiResponse({ status: 401, description: "Token d'accès invalide ou expiré" })
    @ApiBearerAuth('BearerAuth')
    @HttpCode(HttpStatus.OK)
    getProfile(@Request() req: AccessRequest) {
        return {
            message: 'This is a protected profile route',
            user: req.user,
        };
    }

    @UseGuards(JwtAuthGuard)
    @ApiTags('Profil')
    @Patch('profile')
    @ApiOperation({
        summary: 'Mise à jour du profil utilisateur',
        description: `Met à jour les informations du profil de l'utilisateur actuellement connecté. Le rôle ne peut pas être modifié via cette endpoint.

**Route protégée:** Nécessite un accessToken valide dans le header Authorization (Bearer token).
Assurez-vous d'avoir configuré votre token dans "Authorize" avant d'appeler cet endpoint.`,
    })
    @ApiResponse({
        status: 200,
        description: 'Profil mis à jour avec succès',
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'Profile updated successfully' },
                user: {
                    type: 'object',
                    properties: {
                        id: { type: 'number', example: 1 },
                        email: { type: 'string', example: 'user@test.com' },
                        firstName: { type: 'string', example: 'John' },
                        lastName: { type: 'string', example: 'Doe' },
                        role: { type: 'string', example: 'USER' },
                        isEmailVerified: { type: 'boolean', example: true },
                        updatedAt: { type: 'string', format: 'date-time' },
                    },
                },
            },
        },
    })
    @ApiResponse({ status: 401, description: "Token d'accès invalide ou expiré" })
    @ApiResponse({ status: 400, description: 'Données invalides' })
    @ApiBearerAuth('BearerAuth')
    @HttpCode(HttpStatus.OK)
    async updateProfile(
        @Request() req: AccessRequest,
        @Body() updateUserDto: UpdateUserDto,
    ) {
        // Un utilisateur simple ne peut pas changer son rôle via cette route
        const { role: ignoredRole, ...dataWithoutRole } = updateUserDto;
        void ignoredRole;

        const updatedUser = (await this.authService.updateProfile(
            req.user.id,
            dataWithoutRole,
        )) as unknown as Record<string, unknown>;

        return {
            message: 'Profile updated successfully',
            user: updatedUser,
        };
    }

    @UseGuards(JwtAuthGuard)
    @Get('me')
    @ApiOperation({
        summary: 'Informations de l\'utilisateur connecté',
        description: 'Retourne le profil de l\'utilisateur authentifié.',
    })
    @ApiResponse({
        status: 200,
        description: 'Profil utilisateur',
        schema: {
            type: 'object',
            properties: {
                id: { type: 'number', example: 1 },
                email: { type: 'string', example: 'user@test.com' },
                firstName: { type: 'string', example: 'John' },
                lastName: { type: 'string', example: 'Doe' },
                role: { type: 'string', example: 'USER' },
                isEmailVerified: { type: 'boolean', example: true },
                createdAt: { type: 'string', format: 'date-time' },
                updatedAt: { type: 'string', format: 'date-time' },
            },
        },
    })
    @ApiResponse({ status: 401, description: 'Non authentifié' })
    @ApiBearerAuth('BearerAuth')
    getMe(@CurrentUser() user) {
        return user;
    }
}