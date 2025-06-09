import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
// import { parseUserAgent, getGeoLocation } from '../utils/device';
import { logger } from '../utils/logger';
import crypto from 'crypto';

const prisma = new PrismaClient();

export async function createSession(req: Request, userId: string) {
  try {
    const sessionId = crypto.randomUUID();
    const userAgent = req.headers['user-agent'] || '';
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    // const location = await getGeoLocation(ip);
    // const deviceInfo = parseUserAgent(userAgent);

    const session = await prisma.session.create({
      data: {
        id: sessionId,
        userId,
        ip,
        userAgent,
        // location,
        deviceInfo: {}, // Provide an empty object or appropriate device info
        lastSeen: new Date(),
      }
    });

    return session;
  } catch (error) {
    logger.error('Error creating session:', error);
    throw error;
  }
}

export async function getSessions(req: Request, res: Response) {
  try {
    const sessions = await prisma.session.findMany({
      where: {
        userId: req.user!.id,
      },
      orderBy: {
        lastSeen: 'desc'
      }
    });

    res.json(sessions);
  } catch (error) {
    logger.error('Error fetching sessions:', error);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
}

export async function updateSessionActivity(sessionId: string) {
  try {
    await prisma.session.update({
      where: { id: sessionId },
      data: { lastSeen: new Date() }
    });
  } catch (error) {
    logger.error('Error updating session activity:', error);
    throw error;
  }
}