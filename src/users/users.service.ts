import { Injectable } from '@nestjs/common';
import { Role } from 'generated/enums';
import { DatabaseService } from '../database/database.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcrypt';

const SALT_ROUNDS = 10;

@Injectable()
export class UsersService {
  constructor(private readonly databaseService: DatabaseService) { }

  async create(createUser: CreateUserDto): Promise<User> {
    const hashedPassword = await bcrypt.hash(createUser.password, SALT_ROUNDS);
    return this.databaseService.user.create({
      data: {
        email: createUser.email,
        password: hashedPassword,
        firstName: createUser.firstName,
        lastName: createUser.lastName,
        role: createUser.role || 'USER',
      },
    });
  }

  // Methode pour l'inscription avec token
  async createWithVerification(
    createUser: CreateUserDto,
    verificationToken: string,
  ): Promise<User> {
    const hashedPassword = await bcrypt.hash(createUser.password, SALT_ROUNDS);
    return this.databaseService.user.create({
      data: {
        email: createUser.email,
        password: hashedPassword,
        firstName: createUser.firstName,
        lastName: createUser.lastName,
        role: createUser.role || 'USER',
        emailVerificationToken: verificationToken,
        emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24h
        isEmailVerified: false,
      },
    });
  }

  // Methode pour trouver par token de vérification
  async findByVerificationToken(token: string): Promise<User | null> {
    return this.databaseService.user.findFirst({
      where: { emailVerificationToken: token },
    });
  }

  // Methode pour vérifier l'email
  async verifyUserEmail(userId: number): Promise<User> {
    return this.databaseService.user.update({
      where: { id: userId },
      data: {
        isEmailVerified: true,
        emailVerificationToken: null,
      },
    });
  }

  // Methode pour mettre à jour le refresh token
  async updateRefreshToken(
    userId: number,
    refreshToken: string,
  ): Promise<void> {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, SALT_ROUNDS);
    await this.databaseService.user.update({
      where: { id: userId },
      data: { refreshToken: hashedRefreshToken },
    });
  }

  //  Methode pour retirer le refresh token
  async removeRefreshToken(userId: number): Promise<void> {
    await this.databaseService.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });
  }

  //  Methode pour définir le token de reset
  async setPasswordResetToken(
    userId: number,
    token: string,
    expires: Date,
  ): Promise<void> {
    console.log('Sauvegarde du token de reset pour l\'utilisateur ID:', userId);
    console.log('   Token:', token.substring(0, 10) + '...');
    console.log('   Expire le:', expires);

    await this.databaseService.user.update({
      where: { id: userId },
      data: {
        passwordResetToken: token,
        passwordResetExpires: expires,
      },
    });

    console.log('Token sauvegardé avec succès');
  }

  //  Methode pour trouver par token de reset
  async findByResetToken(token: string): Promise<User | null> {
    try {
      console.log('Recherche du token:', token.substring(0, 10) + '...');

      const user = await this.databaseService.user.findFirst({
        where: {
          passwordResetToken: token,
        },
      });

      if (user) {
        console.log('Utilisateur trouvé avec ce token:', user.email);
      } else {
        console.log('Aucun utilisateur trouvé avec ce token');
      }

      return user;
    } catch (error) {
      console.error('Erreur lors de la recherche par token de reset:', error);
      throw error;
    }
  }

  // Methode pour réinitialiser le mot de passe
  async resetPassword(userId: number, newPassword: string): Promise<void> {
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await this.databaseService.user.update({
      where: { id: userId },
      data: {
        password: hashedPassword,
        passwordResetToken: null,
        passwordResetExpires: null,
        refreshToken: null, // Déconnecter l'utilisateur
      },
    });
  }

  findAll(role?: 'ADMIN' | 'USER'): Promise<User[]> {
    if (role) {
      return this.databaseService.user.findMany({
        where: { role: role as Role },
      });
    }
    return this.databaseService.user.findMany();
  }

  findOne(id: number): Promise<User | null> {
    if (!id) throw new Error('ID is required');
    return this.databaseService.user.findUnique({
      where: { id },
    });
  }

  findByEmail(email: string): Promise<User | null> {
    if (!email) throw new Error('Email is required');
    return this.databaseService.user.findUnique({
      where: { email },
    });
  }

  async findById(id: number): Promise<User | null> {
    return this.databaseService.user.findUnique({
      where: { id },
    });
  }

  async update(id: number, updateUser: UpdateUserDto): Promise<User> {
    let hashedPassword: string | undefined;
    if (updateUser.password) {
      hashedPassword = await bcrypt.hash(updateUser.password, SALT_ROUNDS);
    }
    return this.databaseService.user.update({
      where: { id },
      data: {
        ...updateUser,
        password: hashedPassword ?? undefined,
        role: updateUser.role ? (updateUser.role as Role) : undefined,
      },
    });
  }

  remove(id: number): Promise<User> {
    return this.databaseService.user.delete({
      where: { id },
    });
  }

  async verifyPassword(
    plainPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(plainPassword, hashedPassword);
  }
}
