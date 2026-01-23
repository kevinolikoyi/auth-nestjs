import { IsString, IsNotEmpty, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';


export class ResetPasswordDto {
    @ApiProperty({
        description: 'Token de réinitialisation reçu par email',
        example: '1234567890abcdef'
    })
    @IsNotEmpty({ message: 'Token is required' })
    @IsString({ message: 'Token must be a string' })
    token: string;

    @ApiProperty({
        description: 'Nouveau mot de passe (8-20 caractères)',
        example: 'NewPassword123!',
        minLength: 8,
        maxLength: 20
    })
    @IsString({ message: 'Password must be a string' })
    @IsNotEmpty({ message: 'Password is required' })
    @MinLength(8, { message: 'Password must be at least 8 characters long' })
    @MaxLength(20, { message: 'Password must not exceed 20 characters' })
    newPassword: string;
}