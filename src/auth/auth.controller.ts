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
import { LoginDto } from './dto/login.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { JwtAuthGuard } from './guards/jwt-auth-guard';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { UpdateUserDto } from 'src/users/dto/update-user.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    async register(@Body() registerDto: RegisterDto) {
        return this.authService.register(registerDto);
    }

    @Post('create-first-admin')
    @HttpCode(HttpStatus.CREATED)
    async createFirstAdmin(@Body() registerDto: RegisterDto) {
        // Route disponible uniquement en développement
        if (process.env.NODE_ENV === 'production') {
            throw new BadRequestException('This route is not available in production');
        }
        return this.authService.createFirstAdmin(registerDto);
    }

    @Get('verify-email')
    @HttpCode(HttpStatus.OK)
    async verifyEmail(@Query() query: VerifyEmailDto) {
        return this.authService.verifyEmail(query.token);
    }

    @Post('login')
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
    @HttpCode(HttpStatus.OK)
    async logout(@Request() req, @Res({ passthrough: true }) response: Response) {
        await this.authService.logout(req.user.id);
        response.clearCookie('refreshToken');
        return { message: 'Logged out successfully' };
    }

    @Post('forgot-password')
    @HttpCode(HttpStatus.OK)
    async forgotPassword(@Body() dto: ForgotPasswordDto) {
        return this.authService.forgotPassword(dto.email);
    }

    @Get('reset-password')
    @HttpCode(HttpStatus.OK)
    async verifyResetToken(@Query('token') token: string) {
        return this.authService.verifyResetToken(token);
    }

    @Post('reset-password')
    @HttpCode(HttpStatus.OK)
    async resetPassword(@Body() dto: ResetPasswordDto) {
        return this.authService.resetPassword(dto.token, dto.newPassword);
    }

    @UseGuards(JwtAuthGuard)
    @Get('profile')
    @HttpCode(HttpStatus.OK)
    getProfile(@Request() req) {
        return {
            message: 'This is a protected profile route',
            user: req.user,
        };
    }

    @UseGuards(JwtAuthGuard)
    @Patch('profile')
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
