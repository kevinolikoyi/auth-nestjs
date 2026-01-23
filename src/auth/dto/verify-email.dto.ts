import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';


export class VerifyEmailDto {
    @ApiProperty({ description: 'Token de vérification', example: '1234567890' })
    @IsNotEmpty({ message: 'Token is required' })
    @IsString({ message: 'Token must be a string' })
    token: string;
}