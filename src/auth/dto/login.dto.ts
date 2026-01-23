import {
    IsEmail,
    IsNotEmpty,
    IsString,
    MaxLength,
    MinLength,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';


export class LoginDto {
    @ApiProperty({
        description: 'Adresse email de l\'utilisateur',
        example: 'user@test.com',
        format: 'email'
    })
    @IsString({ message: 'Email must be a string' })
    @IsEmail({}, { message: 'Invalid email address' })
    @IsNotEmpty({ message: 'Email is required' })
    email: string;

    @ApiProperty({
        description: 'Mot de passe de l\'utilisateur',
        example: 'User123!',
        minLength: 8,
        maxLength: 20
    })
    @IsString({ message: 'Password must be a string' })
    @IsNotEmpty({ message: 'Password is required' })
    @MinLength(8, { message: 'Password must be at least 8 characters long' })
    @MaxLength(20, { message: 'Password must not exceed 20 characters' })
    password: string;
}
