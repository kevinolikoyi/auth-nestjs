import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
    IsEmail,
    IsEnum,
    IsNotEmpty,
    IsOptional,
    IsString,
    MaxLength,
    MinLength,
} from 'class-validator';

export class CreateAdminDto {
    @ApiProperty({
        description: 'Adresse email de l\'administrateur (doit être unique)',
        example: 'admin@test.com',
        format: 'email'
    })
    @IsEmail({}, { message: 'Invalid email address' })
    @IsNotEmpty({ message: 'Email is required' })
    email: string;

    @ApiProperty({
        description: 'Mot de passe administrateur (8-20 caractères)',
        example: 'Admin123!',
        minLength: 8,
        maxLength: 20
    })
    @IsString({ message: 'Password must be a string' })
    @IsNotEmpty({ message: 'Password is required' })
    @MinLength(8, { message: 'Password must be at least 8 characters long' })
    @MaxLength(20, { message: 'Password must not exceed 20 characters' })
    password: string;

    @ApiPropertyOptional({
        description: 'Prénom de l\'administrateur',
        example: 'Admin',
        minLength: 3,
        maxLength: 20
    })
    @IsString({ message: 'First name must be a string' })
    @MinLength(3, { message: 'First name must be at least 3 characters long' })
    @MaxLength(20, { message: 'First name must not exceed 20 characters' })
    firstName?: string;

    @ApiPropertyOptional({
        description: 'Nom de famille de l\'administrateur',
        example: 'User',
        minLength: 3,
        maxLength: 20
    })
    @IsString({ message: 'Last name must be a string' })
    @MinLength(3, { message: 'Last name must be at least 3 characters long' })
    @MaxLength(20, { message: 'Last name must not exceed 20 characters' })
    lastName?: string;

    @ApiPropertyOptional({
        description: 'Rôle (toujours ADMIN pour cet endpoint)',
        example: 'ADMIN',
        enum: ['ADMIN'],
        default: 'ADMIN'
    })
    @IsOptional({ message: 'Role is optional' })
    @IsEnum(['ADMIN'], { message: 'Role must be ADMIN' })
    role?: 'ADMIN';
}