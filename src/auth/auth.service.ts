import {
    ConflictException,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { RegisterDto } from './dto/register.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './strategies/jwt.strategy';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
    ) { }

    async register(registerDto: RegisterDto) {
        const existingUser = await this.usersService.findByEmail(registerDto.email);
        if (existingUser) {
            throw new ConflictException('User with this email already exists');
        }
        const user = await this.usersService.create(registerDto);

        const token = this.generateToken(user.id, user.email);

        const { password, ...userWithoutPassword } = user;

        return {
            user: userWithoutPassword,
            accessToken: token,
        };
    }

    async login(loginDto: LoginDto) {
        const user = await this.usersService.findByEmail(loginDto.email);
        if (!user) {
            throw new UnauthorizedException('Invalid email or password');
        }

        const isPasswordValid = await bcrypt.compare(
            loginDto.password,
            user.password,
        );
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid email or password');
        }

        const token = this.generateToken(user.id, user.email);

        const { password, ...userWithoutPassword } = user;

        return {
            user: userWithoutPassword,
            accessToken: token,
        };
    }
    private generateToken(userId: number, email: string): string {
        const payload: JwtPayload = { sub: userId, email };
        return this.jwtService.sign(payload);
    }
}
