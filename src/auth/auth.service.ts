import {
    ConflictException,
    Injectable,
    UnauthorizedException,
    BadRequestException,
} from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { RegisterDto } from './dto/register.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './strategies/jwt.strategy';
import { LoginDto } from './dto/login.dto';
import { ConfigService } from '@nestjs/config';
import { EmailService } from 'src/email/email.service';
import { UpdateUserDto } from 'src/users/dto/update-user.dto';
import { sanitizeUser } from 'src/users/utils/user-sanitizer.util';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
        private readonly emailService: EmailService,
    ) { }

    async register(registerDto: RegisterDto) {
        const existingUser = await this.usersService.findByEmail(registerDto.email);
        if (existingUser) {
            throw new ConflictException('User with this email already exists');
        }

        // Générer token de vérification
        const emailVerificationToken = randomBytes(32).toString('hex');

        const user = await this.usersService.createWithVerification(
            registerDto,
            emailVerificationToken,
        );

        // Envoyer email de vérification
        await this.emailService.sendVerificationEmail(
            user.email,
            emailVerificationToken,
        );

        return {
            message:
                'Registration successful. Please check your email to verify your account.',
            userId: user.id,
            // En dev seulement
            ...(process.env.NODE_ENV === 'development' && {
                emailVerificationToken,
            }),
        };
    }

    async verifyEmail(token: string) {
        const user = await this.usersService.findByVerificationToken(token);

        if (!user) {
            throw new BadRequestException('Invalid or expired verification token');
        }

        await this.usersService.verifyUserEmail(user.id);

        return { message: 'Email verified successfully' };
    }

    async login(loginDto: LoginDto) {
        const user = await this.usersService.findByEmail(loginDto.email);
        if (!user) {
            throw new UnauthorizedException('Invalid email or password');
        }

        // Vérifier si l'email est vérifié
        if (!user.isEmailVerified) {
            throw new UnauthorizedException('Please verify your email before logging in');
        }

        const isPasswordValid = await bcrypt.compare(
            loginDto.password,
            user.password,
        );
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid email or password');
        }

        // Générer access et refresh tokens
        const tokens = await this.generateTokens(user.id, user.email, user.role);

        // Sauvegarder le refresh token hashé
        await this.usersService.updateRefreshToken(user.id, tokens.refreshToken);

        // Exclure tous les champs sensibles (password, refreshToken, tokens, etc.)
        const sanitizedUser = sanitizeUser(user);

        return {
            user: sanitizedUser,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
        };
    }

    async refreshTokens(userId: number, refreshToken: string) {
        const user = await this.usersService.findOne(userId);

        if (!user || !user.refreshToken) {
            throw new UnauthorizedException('Access denied');
        }

        // Vérifier le refresh token
        const isValid = await bcrypt.compare(refreshToken, user.refreshToken);
        if (!isValid) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        // Générer nouveaux tokens
        const tokens = await this.generateTokens(user.id, user.email, user.role);

        // Mettre à jour le refresh token
        await this.usersService.updateRefreshToken(user.id, tokens.refreshToken);

        return tokens;
    }

    async logout(userId: number) {
        await this.usersService.removeRefreshToken(userId);
        return { message: 'Logged out successfully' };
    }

    async forgotPassword(email: string) {
        const user = await this.usersService.findByEmail(email);

        if (!user) {
            // Ne pas révéler si l'email existe
            return {
                message: 'If an account exists, a password reset link has been sent',
            };
        }

        const resetToken = randomBytes(32).toString('hex');
        const resetExpires = new Date(Date.now() + 3600000); // 1 heure

        await this.usersService.setPasswordResetToken(
            user.id,
            resetToken,
            resetExpires,
        );

        await this.emailService.sendPasswordResetEmail(user.email, resetToken);

        return {
            message: 'If an account exists, a password reset link has been sent',
        };
    }

    async verifyResetToken(token: string) {
        const user = await this.usersService.findByResetToken(token);

        if (!user) {
            return { valid: false, message: 'Invalid reset token' };
        }

        if (!user.passwordResetExpires) {
            return { valid: false, message: 'Reset token has no expiration date' };
        }

        if (user.passwordResetExpires < new Date()) {
            return { valid: false, message: 'Reset token has expired' };
        }

        return { valid: true, message: 'Reset token is valid' };
    }

    async resetPassword(token: string, newPassword: string) {
        try {
            console.log('🔑 Tentative de réinitialisation avec le token:', token.substring(0, 10) + '...');

            const user = await this.usersService.findByResetToken(token);

            if (!user) {
                console.log('❌ Token non trouvé dans la base de données');
                throw new BadRequestException('Invalid or expired reset token');
            }

            console.log('✅ Utilisateur trouvé:', user.email);

            if (!user.passwordResetExpires) {
                console.log('❌ Token sans date d\'expiration');
                throw new BadRequestException('Invalid or expired reset token');
            }

            if (user.passwordResetExpires < new Date()) {
                console.log('❌ Token expiré. Date d\'expiration:', user.passwordResetExpires);
                throw new BadRequestException('Invalid or expired reset token');
            }

            console.log('✅ Token valide, réinitialisation du mot de passe...');
            await this.usersService.resetPassword(user.id, newPassword);

            return { message: 'Password reset successfully' };
        } catch (error) {
            // Si c'est déjà une exception NestJS, on la relance
            if (error instanceof BadRequestException) {
                throw error;
            }
            // Sinon, on log l'erreur et on relance une exception générique
            console.error('Erreur lors de la réinitialisation du mot de passe:', error);
            throw new BadRequestException('An error occurred while resetting the password');
        }
    }

    async createFirstAdmin(registerDto: RegisterDto) {
        // Vérifier s'il existe déjà un admin
        const existingAdmins = await this.usersService.findAll('ADMIN');
        if (existingAdmins.length > 0) {
            throw new ConflictException('An admin already exists. Use the admin login to create users.');
        }

        // Créer le premier admin (usersService.create hash déjà le mot de passe)
        const admin = await this.usersService.create({
            ...registerDto,
            role: 'ADMIN',
        });

        // Marquer l'email comme vérifié pour le premier admin
        await this.usersService.verifyUserEmail(admin.id);

        // Exclure tous les champs sensibles
        const sanitizedAdmin = sanitizeUser(admin);

        return {
            message: 'First admin created successfully',
            user: sanitizedAdmin,
        };
    }

    async updateProfile(userId: number, updateUserDto: Omit<UpdateUserDto, 'role'>) {
        // On s'assure côté service que le rôle ne sera pas modifié via cette méthode
        const { role, ...dataWithoutRole } = updateUserDto as UpdateUserDto;

        const user = await this.usersService.update(userId, dataWithoutRole);

        // Exclure tous les champs sensibles
        return sanitizeUser(user);
    }

    private async generateTokens(userId: number, email: string, role: string) {
        const payload: JwtPayload = { sub: userId, email };

        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync(payload, {
                secret: this.configService.get('JWT_ACCESS_SECRET'),
                expiresIn: this.configService.get('JWT_ACCESS_EXPIRATION') || '15m',
            }),
            this.jwtService.signAsync(payload, {
                secret: this.configService.get('JWT_REFRESH_SECRET'),
                expiresIn: this.configService.get('JWT_REFRESH_EXPIRATION') || '7d',
            }),
        ]);

        return { accessToken, refreshToken };
    }
}