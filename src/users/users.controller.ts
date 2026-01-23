import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseIntPipe,
  Patch,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';

import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth-guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { sanitizeUser, sanitizeUsers } from './utils/user-sanitizer.util';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';

@ApiTags('Utilisateurs')
@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('ADMIN')
export class UsersController {
  constructor(private readonly usersService: UsersService) { }

  /**
   * Routes d'administration pour gérer les utilisateurs
   * Accessible uniquement aux ADMIN grâce à JwtAuthGuard + RolesGuard
   */

  // ÉTAPE 1 : Consulter les utilisateurs (Lecture)
  @Get()
  @ApiOperation({
    summary: 'Lister tous les utilisateurs (Admin)',
    description:
      'Récupère la liste de tous les utilisateurs. Peut être filtré par rôle. Réservé aux administrateurs.',
  })
  @ApiResponse({
    status: 200,
    description: 'Utilisateurs listés avec succès',
    schema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'number', example: 1 },
          email: { type: 'string', example: 'user@test.com' },
          firstName: { type: 'string', example: 'John' },
          lastName: { type: 'string', example: 'Doe' },
          role: { type: 'string', example: 'USER' },
          isEmailVerified: { type: 'boolean', example: true },
          createdAt: { type: 'string', format: 'date-time' },
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Erreur lors de la liste des utilisateurs',
  })
  @ApiResponse({ status: 401, description: "Token d'accès invalide" })
  @ApiResponse({
    status: 403,
    description: 'Accès refusé - droits administrateur requis',
  })
  @ApiBearerAuth('BearerAuth')
  @HttpCode(200)
  async findAll(@Query('role') role?: 'ADMIN' | 'USER') {
    const users = await this.usersService.findAll(role);
    if (!users) {
      throw new BadRequestException('No users found');
    }
    return sanitizeUsers(users);
  }

  @Get(':id')
  @ApiOperation({
    summary: 'Récupérer un utilisateur par ID (Admin)',
    description:
      "Récupère les informations d'un utilisateur spécifique par son ID. Réservé aux administrateurs.",
  })
  @ApiResponse({
    status: 200,
    description: 'Utilisateur récupéré avec succès',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'number', example: 1 },
        email: { type: 'string', example: 'user@test.com' },
        firstName: { type: 'string', example: 'John' },
        lastName: { type: 'string', example: 'Doe' },
        role: { type: 'string', example: 'USER' },
        isEmailVerified: { type: 'boolean', example: true },
        createdAt: { type: 'string', format: 'date-time' },
        updatedAt: { type: 'string', format: 'date-time' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: "Erreur lors de la récupération de l'utilisateur",
  })
  @ApiResponse({ status: 401, description: "Token d'accès invalide" })
  @ApiResponse({
    status: 403,
    description: 'Accès refusé - droits administrateur requis',
  })
  @ApiResponse({ status: 404, description: 'Utilisateur non trouvé' })
  @ApiBearerAuth('BearerAuth')
  @HttpCode(200)
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const user = await this.usersService.findOne(id);
    if (!user) {
      throw new BadRequestException(`User with ID ${id} not found`);
    }
    return sanitizeUser(user);
  }

  // ÉTAPE 2 : Créer un utilisateur (Création)
  @Post()
  @ApiOperation({
    summary: "Création d'un utilisateur (Admin)",
    description: 'Crée un nouvel utilisateur. Réservé aux administrateurs.',
  })
  @ApiResponse({
    status: 201,
    description: 'Utilisateur créé avec succès',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'number', example: 1 },
        email: { type: 'string', example: 'newuser@test.com' },
        firstName: { type: 'string', example: 'New' },
        lastName: { type: 'string', example: 'User' },
        role: { type: 'string', example: 'USER' },
        isEmailVerified: { type: 'boolean', example: false },
        createdAt: { type: 'string', format: 'date-time' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: "Erreur lors de la création de l'utilisateur",
  })
  @ApiResponse({ status: 401, description: "Token d'accès invalide" })
  @ApiResponse({
    status: 403,
    description: 'Accès refusé - droits administrateur requis',
  })
  @ApiBearerAuth('BearerAuth')
  @HttpCode(201)
  async create(@Body() createUser: CreateUserDto) {
    try {
      const user = await this.usersService.create(createUser);
      if (!user) {
        throw new BadRequestException('User not created');
      }
      return sanitizeUser(user);
    } catch (error) {
      if (error.code === 'P2002') {
        throw new BadRequestException('User with this email already exists');
      }
      throw error;
    }
  }

  // ÉTAPE 3 : Modifier un utilisateur (Modification)
  @Patch(':id')
  @ApiOperation({
    summary: 'Modifier un utilisateur (Admin)',
    description:
      "Modifie les informations d'un utilisateur spécifique par son ID. Permet de changer le mot de passe et le rôle. Réservé aux administrateurs.",
  })
  @ApiResponse({
    status: 200,
    description: 'Utilisateur modifié avec succès',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'number', example: 1 },
        email: { type: 'string', example: 'user@test.com' },
        firstName: { type: 'string', example: 'John' },
        lastName: { type: 'string', example: 'Doe' },
        role: { type: 'string', example: 'USER' },
        isEmailVerified: { type: 'boolean', example: true },
        updatedAt: { type: 'string', format: 'date-time' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: "Erreur lors de la modification de l'utilisateur",
  })
  @ApiResponse({ status: 401, description: "Token d'accès invalide" })
  @ApiResponse({
    status: 403,
    description: 'Accès refusé - droits administrateur requis',
  })
  @ApiResponse({ status: 404, description: 'Utilisateur non trouvé' })
  @ApiBearerAuth('BearerAuth')
  @HttpCode(200)
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateUser: UpdateUserDto,
  ) {
    try {
      const user = await this.usersService.update(id, updateUser);
      if (!user) {
        throw new BadRequestException(`User with ID ${id} not updated`);
      }
      return sanitizeUser(user);
    } catch (error) {
      if (error.code === 'P2025') {
        throw new BadRequestException(`User with ID ${id} not found`);
      }
      if (error.code === 'P2002') {
        throw new BadRequestException('User with this email already exists');
      }
      throw error;
    }
  }

  // ÉTAPE 4 : Supprimer un utilisateur (Suppression)
  @Delete(':id')
  @ApiOperation({
    summary: 'Supprimer un utilisateur (Admin)',
    description:
      'Supprime définitivement un utilisateur par son ID. Réservé aux administrateurs.',
  })
  @ApiResponse({
    status: 200,
    description: 'Utilisateur supprimé avec succès',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'number', example: 1 },
        email: { type: 'string', example: 'user@test.com' },
        firstName: { type: 'string', example: 'John' },
        lastName: { type: 'string', example: 'Doe' },
        role: { type: 'string', example: 'USER' },
        isEmailVerified: { type: 'boolean', example: true },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: "Erreur lors de la suppression de l'utilisateur",
  })
  @ApiResponse({ status: 401, description: "Token d'accès invalide" })
  @ApiResponse({
    status: 403,
    description: 'Accès refusé - droits administrateur requis',
  })
  @ApiResponse({ status: 404, description: 'Utilisateur non trouvé' })
  @ApiBearerAuth('BearerAuth')
  @HttpCode(200)
  async remove(@Param('id', ParseIntPipe) id: number) {
    try {
      const user = await this.usersService.remove(id);
      if (!user) {
        throw new BadRequestException(`User with ID ${id} not deleted`);
      }
      return sanitizeUser(user);
    } catch (error) {
      if (error.code === 'P2025') {
        throw new BadRequestException(`User with ID ${id} not found`);
      }
      throw error;
    }
  }
}
