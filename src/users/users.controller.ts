import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  HttpCode,
  BadRequestException,
  ParseIntPipe,
} from '@nestjs/common';

import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) { }

  @Post()
  @HttpCode(201)
  create(@Body() createUser: CreateUserDto) {
    const user = this.usersService.create(createUser);
    if (!user) {
      throw new BadRequestException('User not created');
    }
    return user;
  }

  @Get()
  @HttpCode(200)
  findAll(@Query('role') role?: 'ADMIN' | 'USER') {
    const users = this.usersService.findAll(role);
    if (!users) {
      throw new BadRequestException('No users found');
    }
    return users;
  }

  @Get(':id')
  @HttpCode(200)
  findOne(@Param('id', ParseIntPipe) id: number) {
    const user = this.usersService.findOne(id);
    if (!user) {
      throw new BadRequestException(`User with ID ${id} not found`);
    }
    return user;
  }

  @Patch(':id')
  @HttpCode(200)
  update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateUser: UpdateUserDto,
  ) {
    const user = this.usersService.update(id, updateUser);
    if (!user) {
      throw new BadRequestException(`User with ID ${id} not updated`);
    }
    return user;
  }

  @Delete(':id')
  @HttpCode(200)
  remove(@Param('id', ParseIntPipe) id: number) {
    const user = this.usersService.remove(id);
    if (!user) {
      throw new BadRequestException(`User with ID ${id} not deleted`);
    }
    return user;
  }
}
