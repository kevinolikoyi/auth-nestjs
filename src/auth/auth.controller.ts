import {
    BadRequestException,
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
import type { Response } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { CreateAdminDto } from './dto/create-admin.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { JwtAuthGuard } from './guards/jwt-auth-guard';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { UpdateUserDto } from '../users/dto/update-user.dto';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiCookieAuth } from '@nestjs/swagger';

@ApiTags('Authentification')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    // ÉTAPE 1 : Création du premier admin
    @Post('create-first-admin')
    @ApiOperation({
        summary: 'Création du premier admin',
        description: 'Crée le premier administrateur du système. Cette route n\'est disponible qu\'une seule fois et uniquement en environnement de développement.'
    })
    @ApiResponse({
        status: 201,
        description: 'Admin créé avec succès',
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'First admin created successfully' },
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
                        updatedAt: { type: 'string', format: 'date-time' }
                    }
                }
            }
        }
    })
    @ApiResponse({ status: 409, description: 'Un administrateur existe déjà' })
    @ApiResponse({ status: 400, description: 'Route non disponible en production' })
    @HttpCode(HttpStatus.CREATED)
    async createFirstAdmin(@Body() registerDto: CreateAdminDto) {
        // Route disponible uniquement en développement
        if (process.env.NODE_ENV === 'production') {
            throw new BadRequestException('This route is not available in production');
        }
        return this.authService.createFirstAdmin(registerDto);
    }

    // ÉTAPE 2 : Inscription
    @Post('register')
    @ApiOperation({
        summary: 'Inscription d\'un nouvel utilisateur',
        description: 'Crée un nouveau compte utilisateur avec validation d\'email. Un email de vérification sera envoyé automatiquement.'
    })
    @ApiResponse({
        status: 201,
        description: 'Utilisateur créé avec succès. Un email de vérification a été envoyé.',
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'User created successfully. Please check your email to verify your account.' },
                user: {
                    type: 'object',
                    properties: {
                        id: { type: 'number', example: 1 },
                        email: { type: 'string', example: 'user@test.com' },
                        firstName: { type: 'string', example: 'John' },
                        lastName: { type: 'string', example: 'Doe' },
                        role: { type: 'string', example: 'USER' },
                        isEmailVerified: { type: 'boolean', example: false },
                        createdAt: { type: 'string', format: 'date-time' }
                    }
                }
            }
        }
    })
    @ApiResponse({ status: 409, description: 'Email déjà utilisé' })
    @ApiResponse({ status: 400, description: 'Données invalides' })
    @HttpCode(HttpStatus.CREATED)
    async register(@Body() registerDto: RegisterDto) {
        return this.authService.register(registerDto);
    }

    @Get('verify-email')
    @ApiOperation({
        summary: 'Vérification de l\'email',
        description: 'Vérifie le token d\'email envoyé lors de l\'inscription pour activer le compte utilisateur.'
    })
    @ApiResponse({
        status: 200,
        description: 'Email vérifié avec succès',
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'Email verified successfully' }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Token invalide ou expiré' })
    @HttpCode(HttpStatus.OK)
    async verifyEmail(@Query() query: VerifyEmailDto) {
        return this.authService.verifyEmail(query.token);
    }

    // ÉTAPE 3 : Authentification
    @Post('login')
    @ApiOperation({
        summary: 'Connexion d\'un utilisateur',
        description: 'Authentifie un utilisateur avec email et mot de passe. Retourne un token d\'accès et définit un cookie de rafraîchissement.'
    })
    @ApiResponse({
        status: 200,
        description: 'Connexion réussie',
        schema: {
            type: 'object',
            properties: {
                accessToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
                user: {
                    type: 'object',
                    properties: {
                        id: { type: 'number', example: 1 },
                        email: { type: 'string', example: 'user@test.com' },
                        firstName: { type: 'string', example: 'John' },
                        lastName: { type: 'string', example: 'Doe' },
                        role: { type: 'string', example: 'USER' },
                        isEmailVerified: { type: 'boolean', example: true }
                    }
                }
            }
        }
    })
    @ApiResponse({ status: 401, description: 'Email ou mot de passe incorrect' })
    @ApiResponse({ status: 403, description: 'Email non vérifié' })
    @HttpCode(HttpStatus.OK)
    async login(
        @Body() loginDto: LoginDto,
        @Res({ passthrough: true }) response: Response,
    ) {
        const result = await this.authService.login(loginDto);

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

    @UseGuards(JwtRefreshGuard)
    @Post('refresh')
    @ApiOperation({ summary: 'Rafraîchissement du token', description: 'Rafraîchit le token d\'accès' })
    @ApiResponse({ status: 200, description: 'Token rafraîchi avec succès' })
    @ApiResponse({ status: 401, description: 'Token invalide' })
    @ApiBearerAuth('BearerAuth')
    @ApiCookieAuth('CookieAuth')
    @HttpCode(HttpStatus.OK)
    async refresh(
        @Request() req,
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

    @UseGuards(JwtAuthGuard)
    @Post('logout')
    @ApiOperation({ summary: 'Déconnexion d\'un utilisateur', description: 'Déconnecte un utilisateur' })
    @ApiResponse({ status: 200, description: 'Déconnexion réussie' })
    @ApiResponse({ status: 401, description: 'Token invalide' })
    @ApiBearerAuth('BearerAuth')
    @ApiCookieAuth('CookieAuth')
    @HttpCode(HttpStatus.OK)
    async logout(@Request() req, @Res({ passthrough: true }) response: Response) {
        await this.authService.logout(req.user.id);
        response.clearCookie('refreshToken');
        return { message: 'Logged out successfully' };
    }

    // ÉTAPE 4 : Gestion du mot de passe
    @Post('forgot-password')
    @ApiOperation({
        summary: 'Demande de réinitialisation de mot de passe',
        description: 'Envoie un email de réinitialisation de mot de passe à l\'adresse email fournie.'
    })
    @ApiResponse({
        status: 200,
        description: 'Email de réinitialisation envoyé avec succès',
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'Password reset email sent successfully' }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Email invalide ou non trouvé' })
    @HttpCode(HttpStatus.OK)
    async forgotPassword(@Body() dto: ForgotPasswordDto) {
        return this.authService.forgotPassword(dto.email);
    }

    @Get('reset-password')
    @ApiOperation({
        summary: 'Vérification du token de réinitialisation',
        description: 'Vérifie la validité du token de réinitialisation de mot de passe avant de permettre la réinitialisation.'
    })
    @ApiResponse({
        status: 200,
        description: 'Token de réinitialisation valide',
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'Reset token is valid' }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Token invalide ou expiré' })
    @HttpCode(HttpStatus.OK)
    async verifyResetToken(@Query('token') token: string) {
        return this.authService.verifyResetToken(token);
    }

    @Post('reset-password')
    @ApiOperation({
        summary: 'Réinitialisation de mot de passe',
        description: 'Réinitialise le mot de passe d\'un utilisateur en utilisant le token reçu par email.'
    })
    @ApiResponse({
        status: 200,
        description: 'Mot de passe réinitialisé avec succès',
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'Password reset successfully' }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Token invalide, expiré ou mot de passe invalide' })
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
        description: 'Récupère les informations du profil de l\'utilisateur actuellement connecté.'
    })
    @ApiResponse({
        status: 200,
        description: 'Profil récupéré avec succès',
        schema: {
            type: 'object',
            properties: {
                message: { type: 'string', example: 'This is a protected profile route' },
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
                        updatedAt: { type: 'string', format: 'date-time' }
                    }
                }
            }
        }
    })
    @ApiResponse({ status: 401, description: 'Token d\'accès invalide ou expiré' })
    @ApiBearerAuth('BearerAuth')
    @HttpCode(HttpStatus.OK)
    getProfile(@Request() req) {
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
        description: 'Met à jour les informations du profil de l\'utilisateur actuellement connecté. Le rôle ne peut pas être modifié via cette endpoint.'
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
                        updatedAt: { type: 'string', format: 'date-time' }
                    }
                }
            }
        }
    })
    @ApiResponse({ status: 401, description: 'Token d\'accès invalide ou expiré' })
    @ApiResponse({ status: 400, description: 'Données invalides' })
    @ApiBearerAuth('BearerAuth')
    @HttpCode(HttpStatus.OK)
    async updateProfile(@Request() req, @Body() updateUserDto: UpdateUserDto) {
        // Un utilisateur simple ne peut pas changer son rôle via cette route
        const { role, ...dataWithoutRole } = updateUserDto;

        const updatedUser = await this.authService.updateProfile(
            req.user.id,
            dataWithoutRole,
        );

        return {
            message: 'Profile updated successfully',
            user: updatedUser,
        };
    }
}
