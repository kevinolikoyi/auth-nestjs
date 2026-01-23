import 'dotenv/config';
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { App } from 'supertest/types';
import request from 'supertest';
import { AppModule } from './../src/app.module';
const cookieParser = require('cookie-parser');
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';
import * as bcrypt from 'bcrypt';

describe('Auth API (e2e)', () => {
  let app: INestApplication<App>;
  let prisma: PrismaClient;
  let adminToken: string;
  let userToken: string;
  let refreshToken: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();

    // Apply the same middleware as in main.ts
    app.use(cookieParser());
    app.setGlobalPrefix('api');
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );

    await app.init();

    // Create Prisma instance for tests
    const pool = new Pool({ connectionString: process.env.DATABASE_URL });
    const adapter = new PrismaPg(pool);
    prisma = new PrismaClient({ adapter });
    await prisma.$connect();

    // Clean database before tests
    await prisma.user.deleteMany();
  });

  afterAll(async () => {
    await prisma.$disconnect();
    await app.close();
  });

  describe('App', () => {
    it('/api (GET) - should return Hello World', () => {
      return request(app.getHttpServer())
        .get('/api')
        .expect(200)
        .expect('Hello World!');
    });
  });

  describe('Authentication', () => {
    describe('POST /api/auth/create-first-admin', () => {
      it('should create first admin successfully', () => {
        return request(app.getHttpServer())
          .post('/api/auth/create-first-admin')
          .send({
            email: 'admin@test.com',
            password: 'Admin123!',
            firstName: 'Admin',
            lastName: 'User',
          })
          .expect(201)
          .expect((res) => {
            expect(res.body).toHaveProperty('message');
            expect(res.body).toHaveProperty('user');
            expect(res.body.user.email).toBe('admin@test.com');
            expect(res.body.user.role).toBe('ADMIN');
            expect(res.body.user.isEmailVerified).toBe(true);
          });
      });

      it('should reject second admin creation', () => {
        return request(app.getHttpServer())
          .post('/api/auth/create-first-admin')
          .send({
            email: 'admin2@test.com',
            password: 'Admin123!',
            firstName: 'Admin2',
            lastName: 'User2',
          })
          .expect(409);
      });

      it('should reject in production environment', () => {
        process.env.NODE_ENV = 'production';
        return request(app.getHttpServer())
          .post('/api/auth/create-first-admin')
          .send({
            email: 'admin3@test.com',
            password: 'Admin123!',
            firstName: 'Admin3',
            lastName: 'User3',
          })
          .expect(400)
          .then(() => {
            process.env.NODE_ENV = 'test';
          });
      });
    });

    describe('POST /api/auth/register', () => {
      it('should register user successfully', () => {
        return request(app.getHttpServer())
          .post('/api/auth/register')
          .send({
            email: 'user@test.com',
            password: 'User123!',
            firstName: 'John',
            lastName: 'Doe',
          })
          .expect(201)
          .expect((res) => {
            expect(res.body).toHaveProperty('message');
            expect(res.body).toHaveProperty('userId');
            expect(typeof res.body.userId).toBe('number');
          });
      });

      it('should reject duplicate email', () => {
        return request(app.getHttpServer())
          .post('/api/auth/register')
          .send({
            email: 'user@test.com',
            password: 'User123!',
            firstName: 'John',
            lastName: 'Doe',
          })
          .expect(409);
      });

      it('should validate required fields', () => {
        return request(app.getHttpServer())
          .post('/api/auth/register')
          .send({
            email: 'invalid-email',
            password: '123',
          })
          .expect(400);
      });
    });

    describe('GET /api/auth/verify-email', () => {
      let verificationToken: string;

      beforeAll(async () => {
        // Get verification token from database
        const user = await prisma.user.findFirst({
          where: { email: 'user@test.com' },
        });
        verificationToken = user?.emailVerificationToken;
      });

      it('should verify email successfully', () => {
        return request(app.getHttpServer())
          .get(`/api/auth/verify-email?token=${verificationToken}`)
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('message');
          });
      });

      it('should reject invalid token', () => {
        return request(app.getHttpServer())
          .get('/api/auth/verify-email?token=invalid-token')
          .expect(400);
      });
    });

    describe('POST /api/auth/login', () => {
      beforeAll(async () => {
        // Ensure user is verified
        await prisma.user.update({
          where: { email: 'user@test.com' },
          data: { isEmailVerified: true },
        });
      });

      it('should login successfully', () => {
        return request(app.getHttpServer())
          .post('/api/auth/login')
          .send({
            email: 'user@test.com',
            password: 'User123!',
          })
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('accessToken');
            expect(res.body).toHaveProperty('user');
            expect(res.headers['set-cookie']).toBeDefined();
            userToken = res.body.accessToken;
            refreshToken = res.headers['set-cookie'][0];
          });
      });

      it('should reject invalid credentials', () => {
        return request(app.getHttpServer())
          .post('/api/auth/login')
          .send({
            email: 'user@test.com',
            password: 'wrongpassword',
          })
          .expect(401);
      });

      it('should reject unverified email', async () => {
        // Create unverified user
        await prisma.user.create({
          data: {
            email: 'unverified@test.com',
            password: await bcrypt.hash('User123!', 10),
            firstName: 'Unverified',
            lastName: 'User',
            isEmailVerified: false,
          },
        });

        return request(app.getHttpServer())
          .post('/api/auth/login')
          .send({
            email: 'unverified@test.com',
            password: 'User123!',
          })
          .expect(401);
      });
    });

    describe('POST /api/auth/refresh', () => {
      it('should refresh token successfully', () => {
        return request(app.getHttpServer())
          .post('/api/auth/refresh')
          .set('Cookie', refreshToken)
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('accessToken');
          });
      });

      it('should reject without refresh token', () => {
        return request(app.getHttpServer())
          .post('/api/auth/refresh')
          .expect(401);
      });
    });

    describe('POST /api/auth/logout', () => {
      it('should logout successfully', () => {
        return request(app.getHttpServer())
          .post('/api/auth/logout')
          .set('Authorization', `Bearer ${userToken}`)
          .set('Cookie', refreshToken)
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('message');
          });
      });

      it('should reject without token', () => {
        return request(app.getHttpServer())
          .post('/api/auth/logout')
          .expect(401);
      });
    });

    describe('POST /api/auth/forgot-password', () => {
      it('should send reset email successfully', () => {
        return request(app.getHttpServer())
          .post('/api/auth/forgot-password')
          .send({
            email: 'user@test.com',
          })
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('message');
          });
      });

      it('should handle non-existent email', () => {
        return request(app.getHttpServer())
          .post('/api/auth/forgot-password')
          .send({
            email: 'nonexistent@test.com',
          })
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('message');
          });
      });
    });

    describe('GET /api/auth/reset-password', () => {
      let resetToken: string;

      beforeAll(async () => {
        // Get reset token from database
        const user = await prisma.user.findFirst({
          where: { email: 'user@test.com' },
        });
        resetToken = user?.passwordResetToken;
      });

      it('should verify reset token successfully', () => {
        return request(app.getHttpServer())
          .get(`/api/auth/reset-password?token=${resetToken}`)
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('message');
          });
      });

      it('should reject invalid reset token', () => {
        return request(app.getHttpServer())
          .get('/api/auth/reset-password?token=invalid-token')
          .expect(200)
          .expect((res) => {
            expect(res.body.valid).toBe(false);
            expect(res.body.message).toBe('Invalid reset token');
          });
      });
    });

    describe('POST /api/auth/reset-password', () => {
      let resetToken: string;

      beforeAll(async () => {
        // Get reset token from database
        const user = await prisma.user.findFirst({
          where: { email: 'user@test.com' },
        });
        resetToken = user?.passwordResetToken;
      });

      it('should reset password successfully', () => {
        return request(app.getHttpServer())
          .post('/api/auth/reset-password')
          .send({
            token: resetToken,
            newPassword: 'NewPassword123!',
          })
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('message');
          });
      });

      it('should reject invalid reset token', () => {
        return request(app.getHttpServer())
          .post('/api/auth/reset-password')
          .send({
            token: 'invalid-token',
            newPassword: 'NewPassword123!',
          })
          .expect(400);
      });
    });
  });

  describe('Profile Management', () => {
    beforeAll(async () => {
      // Login as user to get token
      const loginResponse = await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({
          email: 'user@test.com',
          password: 'NewPassword123!',
        });

      userToken = loginResponse.body.accessToken;
    });

    describe('GET /api/auth/profile', () => {
      it('should get user profile successfully', () => {
        return request(app.getHttpServer())
          .get('/api/auth/profile')
          .set('Authorization', `Bearer ${userToken}`)
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('message');
            expect(res.body).toHaveProperty('user');
            expect(res.body.user.email).toBe('user@test.com');
          });
      });

      it('should reject without token', () => {
        return request(app.getHttpServer())
          .get('/api/auth/profile')
          .expect(401);
      });
    });

    describe('PATCH /api/auth/profile', () => {
      it('should update profile successfully', () => {
        return request(app.getHttpServer())
          .patch('/api/auth/profile')
          .set('Authorization', `Bearer ${userToken}`)
          .send({
            firstName: 'UpdatedJohn',
            lastName: 'UpdatedDoe',
          })
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('message');
            expect(res.body).toHaveProperty('user');
            expect(res.body.user.firstName).toBe('UpdatedJohn');
            expect(res.body.user.lastName).toBe('UpdatedDoe');
          });
      });

      it('should reject role update', () => {
        return request(app.getHttpServer())
          .patch('/api/auth/profile')
          .set('Authorization', `Bearer ${userToken}`)
          .send({
            role: 'ADMIN',
          })
          .expect(200)
          .expect((res) => {
            expect(res.body.user.role).toBe('USER'); // Should remain USER
          });
      });

      it('should reject without token', () => {
        return request(app.getHttpServer())
          .patch('/api/auth/profile')
          .send({
            firstName: 'Test',
          })
          .expect(401);
      });
    });
  });

  describe('User Management (Admin)', () => {
    beforeAll(async () => {
      // Login as admin to get token
      const loginResponse = await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({
          email: 'admin@test.com',
          password: 'Admin123!',
        });

      adminToken = loginResponse.body.accessToken;
    });

    describe('GET /api/users', () => {
      it('should list all users successfully', () => {
        return request(app.getHttpServer())
          .get('/api/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200)
          .expect((res) => {
            expect(Array.isArray(res.body)).toBe(true);
            expect(res.body.length).toBeGreaterThan(0);
          });
      });

      it('should filter users by role', () => {
        return request(app.getHttpServer())
          .get('/api/users?role=ADMIN')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200)
          .expect((res) => {
            expect(Array.isArray(res.body)).toBe(true);
            res.body.forEach((user: any) => {
              expect(user.role).toBe('ADMIN');
            });
          });
      });

      it('should reject without admin token', () => {
        return request(app.getHttpServer())
          .get('/api/users')
          .set('Authorization', `Bearer ${userToken}`)
          .expect(403);
      });
    });

    describe('GET /api/users/:id', () => {
      let userId: number;

      beforeAll(async () => {
        const user = await prisma.user.findFirst({
          where: { email: 'user@test.com' },
        });
        userId = user!.id;
      });

      it('should get user by id successfully', () => {
        return request(app.getHttpServer())
          .get(`/api/users/${userId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('id', userId);
            expect(res.body).toHaveProperty('email', 'user@test.com');
          });
      });

      it('should reject invalid id', () => {
        return request(app.getHttpServer())
          .get('/api/users/99999')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(400);
      });

      it('should reject without admin token', () => {
        return request(app.getHttpServer())
          .get(`/api/users/${userId}`)
          .set('Authorization', `Bearer ${userToken}`)
          .expect(403);
      });
    });

    describe('POST /api/users', () => {
      it('should create user successfully', () => {
        return request(app.getHttpServer())
          .post('/api/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            email: 'newuser@test.com',
            password: 'Password123!',
            firstName: 'New',
            lastName: 'User',
            role: 'USER',
          })
          .expect(201)
          .expect((res) => {
            expect(res.body).toHaveProperty('id');
            expect(res.body).toHaveProperty('email', 'newuser@test.com');
            expect(res.body).toHaveProperty('role', 'USER');
          });
      });

      it('should create admin user', () => {
        return request(app.getHttpServer())
          .post('/api/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            email: 'newadmin@test.com',
            password: 'Admin123!',
            firstName: 'New',
            lastName: 'Admin',
            role: 'ADMIN',
          })
          .expect(201)
          .expect((res) => {
            expect(res.body).toHaveProperty('role', 'ADMIN');
          });
      });

      it('should reject duplicate email', () => {
        return request(app.getHttpServer())
          .post('/api/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            email: 'newuser@test.com',
            password: 'Password123!',
            firstName: 'Duplicate',
            lastName: 'User',
          })
          .expect(400);
      });

      it('should reject without admin token', () => {
        return request(app.getHttpServer())
          .post('/api/users')
          .set('Authorization', `Bearer ${userToken}`)
          .send({
            email: 'test@test.com',
            password: 'Password123!',
            firstName: 'Test',
            lastName: 'User',
          })
          .expect(403);
      });
    });

    describe('PATCH /api/users/:id', () => {
      let userId: number;

      beforeAll(async () => {
        const user = await prisma.user.findFirst({
          where: { email: 'newuser@test.com' },
        });
        userId = user!.id;
      });

      it('should update user successfully', () => {
        return request(app.getHttpServer())
          .patch(`/api/users/${userId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            firstName: 'Updated',
            lastName: 'User',
            password: 'NewPassword123!',
          })
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('firstName', 'Updated');
            expect(res.body).toHaveProperty('lastName', 'User');
          });
      });

      it('should update user role', () => {
        return request(app.getHttpServer())
          .patch(`/api/users/${userId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            role: 'ADMIN',
          })
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('role', 'ADMIN');
          });
      });

      it('should reject invalid id', () => {
        return request(app.getHttpServer())
          .patch('/api/users/99999')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            firstName: 'Test',
          })
          .expect(400);
      });

      it('should reject without admin token', () => {
        return request(app.getHttpServer())
          .patch(`/api/users/${userId}`)
          .set('Authorization', `Bearer ${userToken}`)
          .send({
            firstName: 'Test',
          })
          .expect(403);
      });
    });

    describe('DELETE /api/users/:id', () => {
      let userId: number;

      beforeAll(async () => {
        const user = await prisma.user.findFirst({
          where: { email: 'newuser@test.com' },
        });
        userId = user!.id;
      });

      it('should delete user successfully', () => {
        return request(app.getHttpServer())
          .delete(`/api/users/${userId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200)
          .expect((res) => {
            expect(res.body).toHaveProperty('id', userId);
          });
      });

      it('should reject invalid id', () => {
        return request(app.getHttpServer())
          .delete('/api/users/99999')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(400);
      });

      it('should reject without admin token', () => {
        return request(app.getHttpServer())
          .delete('/api/users/1')
          .set('Authorization', `Bearer ${userToken}`)
          .expect(403);
      });
    });
  });
});
