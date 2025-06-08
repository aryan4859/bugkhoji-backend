import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";
import { logger } from "../utils/logger";
import { config } from "../utils/config";

const prisma = new PrismaClient();

// Extend Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        role: "researcher" | "admin";
        isActive: boolean;
      };
    }
  }
}

interface JwtPayload {
  id: string;
  email: string;
  role: "researcher" | "admin";
  iat?: number;
  exp?: number;
}

// Rate limiting map for failed authentication attempts
const failedAttempts = new Map<string, { count: number; lastAttempt: Date }>();
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

function isRateLimited(ip: string): boolean {
  const attempts = failedAttempts.get(ip);
  if (!attempts) return false;

  const timeSinceLastAttempt = Date.now() - attempts.lastAttempt.getTime();

  // Reset attempts after lockout duration
  if (timeSinceLastAttempt > LOCKOUT_DURATION) {
    failedAttempts.delete(ip);
    return false;
  }

  return attempts.count >= MAX_FAILED_ATTEMPTS;
}

function recordFailedAttempt(ip: string): void {
  const attempts = failedAttempts.get(ip) || {
    count: 0,
    lastAttempt: new Date(),
  };
  attempts.count += 1;
  attempts.lastAttempt = new Date();
  failedAttempts.set(ip, attempts);
}

function clearFailedAttempts(ip: string): void {
  failedAttempts.delete(ip);
}

export async function authenticate(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const clientIp = req.ip || req.connection.remoteAddress || "unknown";

  try {
    // Check rate limiting
    if (isRateLimited(clientIp)) {
      logger.warn(`Rate limited authentication attempt from IP: ${clientIp}`);
      res.status(429).json({
        error:
          "Too many failed authentication attempts. Please try again later.",
      });
      return;
    }

    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      recordFailedAttempt(clientIp);
      res.status(401).json({ error: "Authorization token required" });
      return;
    }

    const token = authHeader.split(" ")[1];
    if (!token || token.length === 0) {
      recordFailedAttempt(clientIp);
      res.status(401).json({ error: "Invalid token format" });
      return;
    }

    // Verify JWT secret exists
    const jwtSecret = config.JWT_SECRET || process.env.JWT_SECRET;
    if (!jwtSecret) {
      logger.error("JWT_SECRET not configured");
      res.status(500).json({ error: "Server configuration error" });
      return;
    }

    // Verify and decode token
    let decoded: JwtPayload;
    try {
      decoded = jwt.verify(token, jwtSecret) as JwtPayload;
    } catch (jwtError) {
      recordFailedAttempt(clientIp);

      if (jwtError instanceof jwt.TokenExpiredError) {
        logger.warn(`Expired token from IP: ${clientIp}`);
        res.status(401).json({ error: "Token has expired" });
        return;
      }

      if (jwtError instanceof jwt.JsonWebTokenError) {
        logger.warn(`Invalid token from IP: ${clientIp} - ${jwtError.message}`);
        res.status(401).json({ error: "Invalid token" });
        return;
      }

      throw jwtError;
    }

    // Validate token payload
    if (!decoded.id || !decoded.email || !decoded.role) {
      recordFailedAttempt(clientIp);
      logger.warn(`Invalid token payload from IP: ${clientIp}`);
      res.status(401).json({ error: "Invalid token payload" });
      return;
    }

    // Fetch user from database with error handling
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: {
        id: true,
        email: true,
        role: true,
        isActive: true,
        lastLogin: true,
      },
    });

    // Validate user exists and is active
    if (!user) {
      recordFailedAttempt(clientIp);
      logger.warn(`Authentication failed: User ${decoded.id} not found`);
      res.status(401).json({ error: "User not found" });
      return;
    }

    if (!user.isActive) {
      recordFailedAttempt(clientIp);
      logger.warn(`Authentication failed: User ${decoded.id} is inactive`);
      res.status(401).json({ error: "Account is inactive" });
      return;
    }

    // Optional: Check token version for forced logout capability
    // if (user.tokenVersion && decoded.tokenVersion !== user.tokenVersion) {
    //   recordFailedAttempt(clientIp)
    //   logger.warn(`Authentication failed: Token version mismatch for user ${decoded.id}`)
    //   res.status(401).json({ error: "Token has been revoked" })
    //   return
    // }

    // Verify email matches (additional security check)
    if (user.email !== decoded.email) {
      recordFailedAttempt(clientIp);
      logger.warn(
        `Authentication failed: Email mismatch for user ${decoded.id}`
      );
      res.status(401).json({ error: "Token validation failed" });
      return;
    }

    // Update last login timestamp (optional)
    await prisma.user
      .update({
        where: { id: user.id },
        data: { lastLogin: new Date() },
      })
      .catch((error: unknown) => {
        logger.error(`Failed to update lastLogin for user ${user.id}:`, error);
      });

    // Clear failed attempts on successful authentication
    clearFailedAttempts(clientIp);

    // Attach user to request
    req.user = {
      id: user.id,
      email: user.email,
      role: user.role as "researcher" | "admin",
      isActive: user.isActive,
    };

    logger.info(
      `User ${user.id} authenticated successfully from IP: ${clientIp}`
    );
    next();
  } catch (error) {
    recordFailedAttempt(clientIp);
    logger.error("Authentication error:", error);
    res.status(500).json({ error: "Internal server error" });
    return;
  }
}

export function authorize(allowedRoles: Array<"researcher" | "admin">) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      if (!req.user) {
        logger.warn("Authorization failed: No user in request");
        res.status(401).json({ error: "Authentication required" });
        return;
      }

      if (!allowedRoles.includes(req.user.role)) {
        logger.warn(
          `Authorization failed: User ${req.user.id} with role ${
            req.user.role
          } attempted to access endpoint requiring roles: ${allowedRoles.join(
            ", "
          )}`
        );
        res.status(403).json({
          error: "Insufficient privileges",
          required: allowedRoles,
          current: req.user.role,
        });
        return;
      }

      // Additional check for active status
      if (!req.user.isActive) {
        logger.warn(`Authorization failed: User ${req.user.id} is inactive`);
        res.status(403).json({ error: "Account is inactive" });
        return;
      }

      next();
    } catch (error) {
      logger.error("Authorization error:", error);
      res.status(500).json({ error: "Internal server error" });
      return;
    }
  };
}

// Utility function to require specific roles
export const requireAdmin = authorize(["admin"]);
export const requireResearcher = authorize(["researcher", "admin"]);

// Middleware to extract user info without requiring authentication (for optional auth)
export async function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    next();
    return;
  }

  try {
    const token = authHeader.split(" ")[1];
    const jwtSecret = config.JWT_SECRET || process.env.JWT_SECRET;

    if (!jwtSecret || !token) {
      next();
      return;
    }

    const decoded = jwt.verify(token, jwtSecret) as JwtPayload;
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, email: true, role: true, isActive: true },
    });

    if (user && user.isActive) {
      req.user = {
        id: user.id,
        email: user.email,
        role: user.role as "researcher" | "admin",
        isActive: user.isActive,
      };
    }
  } catch (error) {
    // Silently fail for optional auth
    logger.debug("Optional auth failed:", error);
  }

  next();
}

// Cleanup function to remove expired rate limit entries
export function cleanupRateLimitMap(): void {
  const now = Date.now();
  for (const [ip, attempts] of failedAttempts.entries()) {
    if (now - attempts.lastAttempt.getTime() > LOCKOUT_DURATION) {
      failedAttempts.delete(ip);
    }
  }
}

// Run cleanup every hour
setInterval(cleanupRateLimitMap, 60 * 60 * 1000);
