import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { PrismaClient, UserRole } from "@prisma/client";
import { logger } from "../utils/logger";
import { config } from "../utils/config";
import { RateLimiterMemory } from "rate-limiter-flexible";

// Singleton Prisma Client instance
const prisma = new PrismaClient();

// Enhanced rate limiting with RateLimiterFlexible
const rateLimiter = new RateLimiterMemory({
  points: 5,
  duration: 15 * 60,
  blockDuration: 15 * 60, // Block for 15 minutes after limit reached
});

// Update the Request interface definition
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        role: UserRole;
        isActive: boolean;
        sessionId?: string;
      };
      authInfo?: {
        clientIp: string;
        userAgent: string;
      };
    }
  }
}

// Strict JwtPayload interface with type guard
interface JwtPayload {
  id: string;
  email: string;
  role: UserRole;
  sessionId?: string;
  iat: number;
  exp: number;
}

function isJwtPayload(decoded: any): decoded is JwtPayload {
  return (
    decoded &&
    typeof decoded.id === "string" &&
    typeof decoded.email === "string" &&
    Object.values(UserRole).includes(decoded.role) &&
    typeof decoded.iat === "number" &&
    typeof decoded.exp === "number"
  );
}

// Constant-time string comparison to prevent timing attacks
function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// Get client IP considering proxy headers
function getClientIp(req: Request): string {
  return (
    (Array.isArray(req.headers["x-forwarded-for"])
      ? req.headers["x-forwarded-for"][0]
      : req.headers["x-forwarded-for"]) ||
    req.ip ||
    req.connection.remoteAddress ||
    "unknown"
  );
}

// Add this function to handle rate limiter errors
async function checkRateLimit(ip: string): Promise<boolean> {
  try {
    await rateLimiter.consume(ip);
    return true;
  } catch (error) {
    return false;
  }
}

export async function authenticate(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const clientIp = getClientIp(req);
  const userAgent = req.headers["user-agent"] || "unknown";

  // Store auth info in request for logging
  req.authInfo = { clientIp, userAgent };

  try {
    // Check rate limiting
    try {
      await rateLimiter.consume(clientIp);
    } catch (rateLimiterRes) {
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
      logger.warn(
        `Missing or invalid Authorization header from IP: ${clientIp}`
      );
      res.status(401).json({ error: "Authorization token required" });
      return;
    }

    const token = authHeader.split(" ")[1];
    if (!token || token.length === 0) {
      logger.warn(`Empty token from IP: ${clientIp}`);
      res.status(401).json({ error: "Invalid token format" });
      return;
    }

    // Verify JWT secret exists
    const jwtSecret = config.JWT_SECRET;
    if (!jwtSecret) {
      logger.error("JWT_SECRET not configured");
      res.status(500).json({ error: "Server configuration error" });
      return;
    }
    // Verify and decode token
    let decoded: unknown;
    try {
      decoded = jwt.verify(token, jwtSecret);
    } catch (jwtError) {
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

      logger.error("Unexpected JWT error:", jwtError);
      res.status(500).json({ error: "Internal server error" });
      return;
    }

    // Validate token payload with type guard
    if (!isJwtPayload(decoded)) {
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
      logger.warn(`Authentication failed: User ${decoded.id} not found`);
      res.status(401).json({ error: "Authentication failed" });
      return;
    }

    if (!user.isActive) {
      logger.warn(`Authentication failed: User ${decoded.id} is inactive`);
      res.status(403).json({ error: "Account is inactive" });
      return;
    }

    // Verify email matches using constant-time comparison
    if (!secureCompare(user.email, decoded.email)) {
      logger.warn(
        `Authentication failed: Email mismatch for user ${decoded.id}`
      );
      res.status(401).json({ error: "Token validation failed" });
      return;
    }

    // Update last login timestamp (fire and forget)
    prisma.user
      .update({
        where: { id: user.id },
        data: { lastLogin: new Date() },
      })
      .catch((error) => {
        logger.error(`Failed to update lastLogin for user ${user.id}:`, error);
      });

    // Attach user and session to request
    req.user = {
      id: user.id,
      email: user.email,
      role: user.role,
      isActive: user.isActive,
      sessionId: decoded.sessionId,
    };

    logger.info(
      `User ${user.id} authenticated successfully from IP: ${clientIp}`
    );
    next();
  } catch (error) {
    logger.error(
      "Authentication error:",
      error instanceof Error ? error.message : "Unknown error"
    );
    res.status(500).json({ error: "Internal server error" });
  }
}

export function authorize(allowedRoles: UserRole[]) {
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

      next();
    } catch (error) {
      logger.error("Authorization error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  };
}

// Role-specific middleware
export const requireAdmin = authorize([UserRole.ADMIN]);
export const requireResearcher = authorize([UserRole.RESEARCHER]);
export const requireOrganization = authorize([UserRole.ORGANIZATION]);
export const requireAny = authorize([
  UserRole.RESEARCHER,
  UserRole.ADMIN,
  UserRole.ORGANIZATION,
]);

export function requireActiveOrganization(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  try {
    if (!req.user) {
      logger.warn("Organization authorization failed: No user in request");
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    if (req.user.role !== UserRole.ORGANIZATION) {
      logger.warn(
        `Authorization failed: User ${req.user.id} with role ${req.user.role} attempted to access organization endpoint`
      );
      res.status(403).json({
        error: "Organization access required",
        current: req.user.role,
      });
      return;
    }

    if (!req.user.isActive) {
      logger.warn(
        `Organization authorization failed: Organization ${req.user.id} is inactive`
      );
      res.status(403).json({
        error:
          "Organization account is pending activation or has been deactivated",
      });
      return;
    }

    next();
  } catch (error) {
    logger.error(
      "Organization authorization error:",
      error instanceof Error ? error.message : "Unknown error"
    );
    res.status(500).json({ error: "Internal server error" });
  }
}

export const requireOrganizationOrAdmin = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  try {
    if (!req.user) {
      logger.warn("Authorization failed: No user in request");
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    if (
      req.user.role !== UserRole.ORGANIZATION &&
      req.user.role !== UserRole.ADMIN
    ) {
      logger.warn(
        `Authorization failed: User ${req.user.id} with role ${req.user.role} attempted to access protected endpoint`
      );
      res.status(403).json({ error: "Insufficient privileges" });
      return;
    }

    if (!req.user.isActive) {
      logger.warn(`Authorization failed: User ${req.user.id} is inactive`);
      res.status(403).json({ error: "Account is inactive" });
      return;
    }

    next();
  } catch (error) {
    logger.error(
      "Authorization error:",
      error instanceof Error ? error.message : "Unknown error"
    );
    res.status(500).json({ error: "Internal server error" });
  }
};

export async function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next();
  }

  try {
    const token = authHeader.split(" ")[1];
    const jwtSecret = config.JWT_SECRET;

    if (!jwtSecret || !token) {
      return next();
    }

    const decoded = jwt.verify(token, jwtSecret);
    if (!isJwtPayload(decoded)) {
      return next();
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, email: true, role: true, isActive: true },
    });

    if (user && user.isActive && secureCompare(user.email, decoded.email)) {
      req.user = {
        id: user.id,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
      };
    }
  } catch (error) {
    // Silently fail for optional auth but log for debugging
    logger.debug(
      "Optional auth failed:",
      error instanceof Error ? error.message : "Unknown error"
    );
  }

  next();
}

// Proper cleanup
const cleanup = async () => {
  try {
    await prisma.$disconnect();
    logger.info("Database connection closed");
  } catch (error) {
    logger.error("Error during cleanup:", error);
    process.exit(1);
  }
};

process.on("SIGTERM", cleanup);
process.on("SIGINT", cleanup);
process.on("beforeExit", cleanup);
