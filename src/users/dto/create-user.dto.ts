import {
    IsEmail,
    IsEnum,
    IsNotEmpty,
    IsOptional,
    IsString,
    MaxLength,
    MinLength,
} from 'class-validator';

export class CreateUserDto {
    @IsEmail({}, { message: 'Invalid email address' })
    @IsNotEmpty({ message: 'Email is required' })
    email: string;

    @IsString({ message: 'Password must be a string' })
    @MinLength(8, { message: 'Password must be at least 8 characters long' })
    @MaxLength(20, { message: 'Password must not exceed 20 characters' })
    @IsNotEmpty({ message: 'Password is required' })
    password: string;

    @IsString({ message: 'First name must be a string' })
    @MinLength(3, { message: 'First name must be at least 3 characters long' })
    @MaxLength(20, { message: 'First name must not exceed 50 characters' })
    firstName?: string;

    @IsString({ message: 'Last name must be a string' })
    @MinLength(3, { message: 'Last name must be at least 3 characters long' })
    @MaxLength(20, { message: 'Last name must not exceed 50 characters' })
    lastName?: string;

    @IsOptional()
    @IsEnum(['USER', 'ADMIN'], { message: 'Role must be either USER or ADMIN' })
    role?: 'USER' | 'ADMIN';
}
