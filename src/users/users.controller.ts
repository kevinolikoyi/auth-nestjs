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
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth-guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { sanitizeUser, sanitizeUsers } from './utils/user-sanitizer.util';

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('ADMIN')
export class UsersController {
  constructor(private readonly usersService: UsersService) { }

  /**
   * Routes d'administration pour gérer les utilisateurs
   * Accessible uniquement aux ADMIN grâce à JwtAuthGuard + RolesGuard
   */

  @Post()
  @HttpCode(201)
  async create(@Body() createUser: CreateUserDto) {
    const user = await this.usersService.create(createUser);
    if (!user) {
      throw new BadRequestException('User not created');
    }
    return sanitizeUser(user);
  }

  @Get()
  @HttpCode(200)
  async findAll(@Query('role') role?: 'ADMIN' | 'USER') {
    const users = await this.usersService.findAll(role);
    if (!users) {
      throw new BadRequestException('No users found');
    }
    return sanitizeUsers(users);
  }

  @Get(':id')
  @HttpCode(200)
  async findOne(@Param('id', ParseIntPipe) id: number) {
    const user = await this.usersService.findOne(id);
    if (!user) {
      throw new BadRequestException(`User with ID ${id} not found`);
    }
    return sanitizeUser(user);
  }

  @Patch(':id')
  @HttpCode(200)
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateUser: UpdateUserDto,
  ) {
    const user = await this.usersService.update(id, updateUser);
    if (!user) {
      throw new BadRequestException(`User with ID ${id} not updated`);
    }
    return sanitizeUser(user);
  }

  @Delete(':id')
  @HttpCode(200)
  async remove(@Param('id', ParseIntPipe) id: number) {
    const user = await this.usersService.remove(id);
    if (!user) {
      throw new BadRequestException(`User with ID ${id} not deleted`);
    }
    return sanitizeUser(user);
  }
}
