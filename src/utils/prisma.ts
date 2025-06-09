import { PrismaClient } from '@prisma/client'

// Prevent multiple instances of Prisma Client in development
declare global {
  var prisma: PrismaClient | undefined
}

export const prisma = global.prisma || new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
})

// Prevent multiple instances in development environment
if (process.env.NODE_ENV !== 'production') {
  global.prisma = prisma
}

// Handle cleanup on application shutdown
process.on('beforeExit', async () => {
  await prisma.$disconnect()
})

