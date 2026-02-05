import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';


export class ForgotPasswordDto {
    @ApiProperty({
        description: 'Adresse email de l\'utilisateur pour recevoir le lien de réinitialisation',
        example: 'user@test.com',
        format: 'email',
    })
    @IsString({ message: 'Email must be a string' })
    @IsEmail({}, { message: 'Invalid email address' })
    @IsNotEmpty({ message: 'Email is required' })
    email: string;
}
