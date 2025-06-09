import { Router, Request, Response } from 'express'
import { prisma } from '../utils/prisma'
import { AuditAction } from '@prisma/client'
import { authenticate, authorize } from '../middleware/auth'
import { logger } from '../utils/logger'

const router = Router()

// Test audit log creation
router.post('/test-audit', authenticate, authorize(['ADMIN']), async (req: Request, res: Response) => {
  try {
    const auditLog = await prisma.auditLog.create({
      data: {
        action: AuditAction.CREATED,
        entityType: 'TEST',
        entityId: 'test-123',
        performedById: req.user!.id,
        userId: req.user!.id,
        newData: {
          details: 'Testing audit log functionality',
          timestamp: new Date(),
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        }
      }
    })

    logger.info(`Test audit log created by user ${req.user!.id}`)
    res.json({ message: 'Audit log created successfully', auditLog })
  } catch (error) {
    logger.error('Failed to create test audit log:', error)
    res.status(500).json({ error: 'Failed to create audit log' })
  }
})

// Get recent audit logs with pagination
router.get('/recent', authenticate, authorize(['ADMIN']), async (req: Request, res: Response) => {
  logger.debug('Recent audit logs endpoint hit');
  try {
    const page = Number(req.query.page) || 1
    const limit = Number(req.query.limit) || 50
    const skip = (page - 1) * limit

    const [auditLogs, total] = await Promise.all([
      prisma.auditLog.findMany({
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: {
          performedBy: {
            select: {
              id: true,
              username: true,
              email: true,
              role: true
            }
          },
          user: {
            select: {
              id: true,
              username: true,
              email: true,
              role: true
            }
          }
        }
      }),
      prisma.auditLog.count()
    ])

    logger.info(`Audit logs retrieved by admin ${req.user!.id}`)
    res.json({
      data: auditLogs,
      pagination: {
        total,
        pages: Math.ceil(total / limit),
        currentPage: page,
        perPage: limit
      }
    })
  } catch (error) {
    logger.error('Failed to fetch audit logs:', error)
    res.status(500).json({ error: 'Failed to fetch audit logs' })
  }
})

// Get audit logs by user with filters
router.get('/user/:userId', authenticate, authorize(['ADMIN']), async (req: Request, res: Response) => {
  logger.debug(`User audit logs endpoint hit for userId: ${req.params.userId}`);
  try {
    const { userId } = req.params
    const { action, entityType, startDate, endDate } = req.query
    
    const where = {
      OR: [
        { performedById: userId },
        { userId: userId }
      ],
      ...(action && { action: action as AuditAction }),
      ...(entityType && { entityType: entityType as string }),
      ...(startDate || endDate) && {
        createdAt: {
          ...(startDate && { gte: new Date(startDate as string) }),
          ...(endDate && { lte: new Date(endDate as string) })
        }
      }
    }

    const auditLogs = await prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      include: {
        performedBy: {
          select: {
            id: true,
            username: true,
            email: true,
            role: true
          }
        },
        user: {
          select: {
            id: true,
            username: true,
            email: true,
            role: true
          }
        }
      }
    })

    logger.info(`User audit logs retrieved for ${userId} by admin ${req.user!.id}`)
    res.json(auditLogs)
  } catch (error) {
    logger.error('Failed to fetch user audit logs:', error)
    res.status(500).json({ error: 'Failed to fetch user audit logs' })
  }
})

export default router