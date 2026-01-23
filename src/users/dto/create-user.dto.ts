import {
    IsEmail,
    IsEnum,
    IsNotEmpty,
    IsOptional,
    IsString,
    MaxLength,
    MinLength,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';


export class CreateUserDto {
    @ApiProperty({
        description: 'Adresse email de l\'utilisateur (doit être unique)',
        example: 'user@test.com',
        format: 'email'
    })
    @IsString({ message: 'Email must be a string' })
    @IsEmail({}, { message: 'Invalid email address' })
    @IsNotEmpty({ message: 'Email is required' })
    email: string;

    @ApiProperty({
        description: 'Mot de passe (8-20 caractères)',
        example: 'User123!',
        minLength: 8,
        maxLength: 20
    })
    @IsString({ message: 'Password must be a string' })
    @MinLength(8, { message: 'Password must be at least 8 characters long' })
    @MaxLength(20, { message: 'Password must not exceed 20 characters' })
    @IsNotEmpty({ message: 'Password is required' })
    password: string;

    @ApiPropertyOptional({
        description: 'Prénom de l\'utilisateur',
        example: 'John',
        minLength: 3,
        maxLength: 20
    })
    @IsString({ message: 'First name must be a string' })
    @MinLength(3, { message: 'First name must be at least 3 characters long' })
    @MaxLength(20, { message: 'First name must not exceed 50 characters' })
    firstName?: string;

    @ApiPropertyOptional({
        description: 'Nom de famille de l\'utilisateur',
        example: 'Doe',
        minLength: 3,
        maxLength: 20
    })
    @IsString({ message: 'Last name must be a string' })
    @MinLength(3, { message: 'Last name must be at least 3 characters long' })
    @MaxLength(20, { message: 'Last name must not exceed 50 characters' })
    lastName?: string;

    @ApiPropertyOptional({
        description: 'Rôle de l\'utilisateur',
        example: 'USER',
        enum: ['USER', 'ADMIN'],
        default: 'USER'
    })
    @IsOptional({ message: 'Role is optional' })
    @IsEnum(['USER', 'ADMIN'], { message: 'Role must be either USER or ADMIN' })
    role?: 'USER' | 'ADMIN';
}
