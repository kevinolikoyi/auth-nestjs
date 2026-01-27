import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';

@Injectable()
export class DatabaseService extends PrismaClient implements OnModuleInit {
  constructor() {
    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) {
      throw new Error(
        'DATABASE_URL manquant. Sur Vercel: Project → Settings → Environment Variables → ajoute DATABASE_URL.',
      );
    }

    const pool = new Pool({ connectionString: databaseUrl });
    const adapter = new PrismaPg(pool);
    super({ adapter });
  }

  async onModuleInit() {
    await this.$connect();
    console.log('Prisma connected... ');
  }
}
