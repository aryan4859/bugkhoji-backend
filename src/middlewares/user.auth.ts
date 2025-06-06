import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../utils/environment';
import { User, IUser } from '../models/user.model';
import { logger, auditLog } from '../utils/logger';

export interface AuthRequest extends Request {
  user?: IUser;
}

export const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, env.JWT_SECRET) as { userId: string; role: string };
    const user = await User.findById(decoded.userId).select('-passwordHash -refreshTokenHash');

    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Invalid token or user inactive' });
    }

    req.user = user;
    next();
  } catch (error) {
    logger.error('Authentication error:', error);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

export const requireRole = (roles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!roles.includes(req.user.role)) {
      auditLog('UNAUTHORIZED_ACCESS_ATTEMPT', req.user.id.toString(), {
        requiredRoles: roles,
        userRole: req.user.role,
        endpoint: req.path,
        ip: req.ip
      });
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
};