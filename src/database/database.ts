import { PrismaClient } from '@prisma/client';
import {logger} from '../utils/logger';

const prisma = new PrismaClient();

async function connectDB() {
  try {
    await prisma.$connect();
    console.log('✅ Prisma connected to PostgreSQL successfully');
    logger.info('🚀 Prisma connected to PostgreSQL database');
  } catch (error) {
    console.error('❌ Failed to connect to PostgreSQL:', error);
    logger.error('Failed to connect to PostgreSQL:', error);
    process.exit(1);
  }
}

// Graceful shutdown
async function disconnectDB() {
  try {
    await prisma.$disconnect();
    console.log('✅ Database connection closed');
    logger.info('Database connection closed');
  } catch (error) {
    console.error('❌ Error closing database connection:', error);
    logger.error('Error closing database connection:', error);
  }
}

export { prisma, connectDB, disconnectDB };