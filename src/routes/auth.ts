import { Router, type Request, type Response } from "express";
import bcrypt from "bcryptjs";
import jwt, { type Secret, type SignOptions } from "jsonwebtoken";
import { z } from "zod";
import { PrismaClient, UserRole } from "@prisma/client";
import rateLimit from "express-rate-limit";
import { logger } from "../utils/logger";
import { validate } from "../middleware/validate";
import { config } from "../utils/config";
import { generateRefreshToken } from "../utils/token";
import { getSessions } from "../controllers/session.controller";
import { authenticate } from "../middleware/auth";

const router = Router();
const prisma = new PrismaClient();

// ============================================================================
// RATE LIMITING CONFIGURATION
// ============================================================================

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many authentication attempts, please try again later",
  },
  keyGenerator: (req) => {
    const email = req.body?.email || "unknown";
    return `${req.ip}-${email}`;
  },
});

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password too long"),
});

const registerSchema = z.object({
  username: z
    .string()
    .min(3, "Username must be at least 3 characters")
    .max(30, "Username too long")
    .regex(
      /^[a-zA-Z0-9_]+$/,
      "Username can only contain letters, numbers, and underscores"
    ),
  firstName: z
    .string()
    .min(1, "First name is required")
    .max(100, "First name too long"),
  lastName: z
    .string()
    .min(1, "Last name is required")
    .max(100, "Last name too long"),
  email: z.string().email("Invalid email address"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password too long")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[0-9]/, "Password must contain at least one number")
    .regex(
      /[^A-Za-z0-9]/,
      "Password must contain at least one special character"
    ),
});

const organizationRegisterSchema = z.object({
  organizationName: z
    .string()
    .min(2, "Organization name must be at least 2 characters")
    .max(100, "Organization name too long")
    .trim(), // Add trim to remove whitespace
  email: z
    .string()
    .email("Invalid email address")
    .toLowerCase() // Normalize email case
    .trim(),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password too long")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[0-9]/, "Password must contain at least one number")
    .regex(
      /[^A-Za-z0-9]/,
      "Password must contain at least one special character"
    ), // Add special char requirement
  website: z
    .string()
    .url("Invalid website URL")
    .trim()
    .optional()
    .or(z.literal("")), // Allow empty string
  description: z
    .string()
    .max(500, "Description too long")
    .trim()
    .optional()
    .or(z.literal("")), // Allow empty string
});

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

const generateToken = (id: string, role: string): string => {
  const secret = config.JWT_SECRET;

  if (!secret) {
    throw new Error("JWT_SECRET not defined");
  }

  const expiresIn = process.env.JWT_ACCESS_EXPIRE || "15m";
  const payload = { id, role };
  const options: SignOptions = {
    expiresIn: expiresIn as SignOptions["expiresIn"],
  };

  return jwt.sign(payload, secret as Secret, options);
};

const setRefreshTokenCookie = (res: Response, refreshToken: string): void => {
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
};

interface UserLoginData {
  id: string;
  email: string;
  passwordHash: string;
  role: string;
  isActive: boolean;
  username: string;
  firstName: string;
  lastName: string;
}

const handleLoginSuccess = async (
  user: UserLoginData,
  res: Response
): Promise<void> => {
  // Update last login timestamp
  try {
    await prisma.user.update({
      where: { id: user.id },
      data: {
        lastLogin: new Date(),
      },
    });
  } catch (updateError) {
    // Log the error but don't fail the login process
    logger.warn(`Failed to update lastLogin for user ${user.id}:`, updateError);
  }

  // Generate tokens
  const accessToken = generateToken(user.id, user.role);
  const { token: refreshToken } = await generateRefreshToken(user.id);

  // Set refresh token cookie
  setRefreshTokenCookie(res, refreshToken);

  // Return success response
  res.json({
    token: accessToken,
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
    },
  });
};

// ============================================================================
// REGISTRATION ENDPOINTS
// ============================================================================

/**
 * 🔐 Researcher Registration
 */
router.post(
  "/register/researcher",
  authLimiter,
  validate(registerSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password, username, firstName, lastName } = req.body;

      logger.info(`Registration attempt for email: ${email}`);

      // Validate request body exists
      if (!req.body) {
        logger.error("Request body is missing");
        res.status(400).json({ error: "Request body is required" });
        return;
      }

      // Check if email or username already exists
      const existingUser = await prisma.user.findFirst({
        where: {
          OR: [{ email }, { username }],
        },
      });

      if (existingUser) {
        const conflictField =
          existingUser.email === email ? "Email" : "Username";
        logger.warn(
          `Registration failed: ${conflictField} already exists for ${email}`
        );
        res.status(409).json({ message: `${conflictField} already exists` });
        return;
      }

      // Hash password with high salt rounds
      const passwordHash = await bcrypt.hash(password, 12);

      // Create new researcher user
      const user = await prisma.user.create({
        data: {
          email,
          passwordHash,
          username,
          firstName,
          lastName,
          role: "RESEARCHER",
        },
      });

      logger.info(`Researcher registration successful for user: ${user.id}`);
      res.status(201).json({ message: "Registration successful" });
    } catch (err) {
      logger.error("Server error during researcher registration:", err);
      res.status(500).json({ message: "Server error during registration" });
    }
  }
);

/**
 * 🏢 Organization Registration
 */
router.post(
  "/register/organization",
  authLimiter,
  validate(organizationRegisterSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password, organizationName, website, description } =
        req.body;

      logger.info(`Organization registration attempt for: ${organizationName}`);

      // Check if organization email already exists
      const existingOrg = await prisma.user.findUnique({
        where: { email },
      });

      if (existingOrg) {
        logger.warn(`Registration failed: Email already exists for ${email}`);
        res.status(409).json({ message: "Email already exists" });
        return;
      }

      // Generate username and check for conflicts
      let baseUsername = organizationName
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "_") // Replace non-alphanumeric with underscore
        .replace(/_+/g, "_") // Replace multiple underscores with single
        .replace(/^_+|_+$/g, "") // Remove leading/trailing underscores
        .substring(0, 30); // Limit length

      let username = baseUsername;
      let counter = 1;

      // Ensure username uniqueness
      while (await prisma.user.findUnique({ where: { username } })) {
        username = `${baseUsername}_${counter}`;
        counter++;
      }

      // Hash password
      const passwordHash = await bcrypt.hash(password, 12);

      // Create new organization user with transaction
      const user = await prisma.$transaction(async (tx) => {
        return await tx.user.create({
          data: {
            email,
            passwordHash,
            username,
            firstName: organizationName,
            lastName: "",
            role: UserRole.ORGANIZATION,
            isActive: false, // Organizations need admin approval
            organizationProfile: {
              create: {
                name: organizationName,
                website: website || null,
                description: description || null,
              },
            },
          },
          include: {
            organizationProfile: true,
          },
        });
      });

      // Don't log sensitive data in production
      logger.info(
        `Organization registration successful for user ID: ${user.id}`
      );

      // Don't return sensitive user data
      res.status(201).json({
        message:
          "Registration successful. Please wait for admin approval to activate your account.",
        userId: user.id, // Only return non-sensitive identifier if needed
      });
    } catch (err) {
      // Handle specific Prisma errors
      if (err instanceof Error) {
        if (err.message.includes("Unique constraint")) {
          logger.warn(
            `Registration failed: Duplicate data for ${req.body.organizationName}`
          );
          res
            .status(409)
            .json({
              message: "Registration data conflicts with existing account",
            });
          return;
        }
      }

      logger.error("Server error during organization registration:", {
        error: err instanceof Error ? err.message : "Unknown error",
        organizationName: req.body.organizationName,
        email: req.body.email,
      });
      res.status(500).json({ message: "Server error during registration" });
    }
  }
);

// ============================================================================
// LOGIN ENDPOINTS
// ============================================================================

/**
 * 🔐 Researcher Login
 */
router.post(
  "/login/researcher",
  authLimiter,
  validate(loginSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password } = req.body;

      logger.info(`Login attempt for researcher email: ${email}`);

      // Find user by email
      const user = await prisma.user.findUnique({
        where: { email },
        select: {
          id: true,
          email: true,
          passwordHash: true,
          role: true,
          isActive: true,
          username: true,
          firstName: true,
          lastName: true,
        },
      });

      // **NULL CHECK**: Ensure user exists
      if (!user) {
        logger.warn(
          `Failed login attempt for researcher email: ${email} - User not found`
        );
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      // Check if user is a researcher and is active
      if (user.role !== "RESEARCHER" || !user.isActive) {
        logger.warn(
          `Failed login attempt for researcher email: ${email} - Invalid role or inactive account`
        );
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      // Verify password
      const passwordMatch = await bcrypt.compare(password, user.passwordHash);
      if (!passwordMatch) {
        logger.warn(
          `Failed login attempt for researcher: ${user.email} - Invalid password`
        );
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      // Handle successful login
      await handleLoginSuccess(user, res);
      logger.info(`Successful researcher login for user: ${user.id}`);
    } catch (err) {
      logger.error("Researcher login error:", err);
      res.status(500).json({ message: "Server error during login" });
    }
  }
);

/**
 * 🔐 Admin Login
 */
router.post(
  "/login/admin",
  authLimiter,
  validate(loginSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password } = req.body;

      logger.info(`Login attempt for admin email: ${email}`);

      // Find user by email
      const user = await prisma.user.findUnique({
        where: { email },
        select: {
          id: true,
          email: true,
          passwordHash: true,
          role: true,
          isActive: true,
          username: true,
          firstName: true,
          lastName: true,
        },
      });

      // **NULL CHECK**: Ensure user exists
      if (!user) {
        logger.warn(
          `Failed login attempt for admin email: ${email} - User not found`
        );
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      // Check if user is an admin and is active
      if (user.role !== "ADMIN" || !user.isActive) {
        logger.warn(
          `Failed login attempt for admin email: ${email} - Invalid role or inactive account`
        );
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      // Verify password
      const passwordMatch = await bcrypt.compare(password, user.passwordHash);
      if (!passwordMatch) {
        logger.warn(
          `Failed login attempt for admin: ${user.email} - Invalid password`
        );
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      // TODO: Implement MFA check for admin accounts
      // if (user.mfaEnabled) {
      //   // Handle MFA verification
      // }

      // Handle successful login
      await handleLoginSuccess(user, res);
      logger.info(`Successful admin login for user: ${user.id}`);
    } catch (err) {
      logger.error("Admin login error:", err);
      res.status(500).json({ message: "Server error during login" });
    }
  }
);

/**
 * 🏢 Organization Login
 */
router.post(
  "/login/organization",
  authLimiter,
  validate(loginSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password } = req.body;

      logger.info(`Login attempt for organization email: ${email}`);

      // Find organization by email
      const user = await prisma.user.findUnique({
        where: { email },
        select: {
          id: true,
          email: true,
          passwordHash: true,
          role: true,
          isActive: true,
          username: true,
          firstName: true,
          lastName: true,
        },
      });

      // Ensure organization exists
      if (!user) {
        logger.warn(
          `Failed login attempt for organization email: ${email} - Organization not found`
        );
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      // Check if user is an organization and is active
      if (user.role !== ("ORGANIZATION" as typeof user.role)) {
        logger.warn(
          `Failed login attempt for email: ${email} - Not an organization account`
        );
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      if (!user.isActive) {
        logger.warn(
          `Failed login attempt for organization: ${email} - Account not activated`
        );
        res.status(401).json({
          message:
            "Account pending activation. Please wait for admin approval.",
        });
        return;
      }

      // Verify password
      const passwordMatch = await bcrypt.compare(password, user.passwordHash);
      if (!passwordMatch) {
        logger.warn(
          `Failed login attempt for organization: ${user.email} - Invalid password`
        );
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      // Handle successful login
      await handleLoginSuccess(user, res);
      logger.info(`Successful organization login for: ${user.id}`);
    } catch (err) {
      logger.error("Organization login error:", err);
      res.status(500).json({ message: "Server error during login" });
    }
  }
);

// ============================================================================
// TOKEN MANAGEMENT ENDPOINTS
// ============================================================================

/**
 * 🔐 Refresh Token Endpoint
 */
router.post("/refresh", async (req: Request, res: Response): Promise<void> => {
  try {
    // Get refresh token from cookie
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      res.status(401).json({ error: "Refresh token not found" });
      return;
    }

    // Decode token to get user ID
    const decoded = jwt.decode(refreshToken) as { id: string } | null;

    if (!decoded || !decoded.id) {
      res.status(401).json({ error: "Invalid refresh token" });
      return;
    }

    // Verify refresh token
    const { verifyRefreshToken } = await import("../utils/token");
    const isValid = await verifyRefreshToken(refreshToken, decoded.id);

    if (!isValid) {
      logger.warn(`Invalid refresh token used for user ID: ${decoded.id}`);
      res.status(401).json({ error: "Invalid refresh token" });
      return;
    }

    // Get user data
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, email: true, role: true, isActive: true },
    });

    // **NULL CHECK**: Ensure user exists and is active
    if (!user) {
      logger.warn(`Refresh token used for non-existent user: ${decoded.id}`);
      res.status(401).json({ error: "User not found" });
      return;
    }

    if (!user.isActive) {
      logger.warn(`Refresh token used for inactive user: ${decoded.id}`);
      res.status(401).json({ error: "User account is inactive" });
      return;
    }

    // Generate new tokens
    const accessToken = generateToken(user.id, user.role);
    const { token: newRefreshToken } = await generateRefreshToken(user.id);

    // Set new refresh token cookie
    setRefreshTokenCookie(res, newRefreshToken);

    res.json({ token: accessToken });
  } catch (error) {
    logger.error("Token refresh error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * 🔐 Logout Endpoint
 */
router.post("/logout", async (req: Request, res: Response): Promise<void> => {
  try {
    // Get user ID from token if available
    const authHeader = req.headers.authorization;
    let userId: string | null = null;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      try {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, config.JWT_SECRET as string) as {
          id: string;
        };
        userId = decoded.id;
      } catch (error) {
        // Token might be expired, but we still want to clear cookies
        logger.warn("Invalid token during logout:", error);
      }
    }

    if (userId) {
      // Invalidate refresh token
      const { invalidateRefreshToken } = await import("../utils/token");
      await invalidateRefreshToken(userId);
    }

    // Clear refresh token cookie
    res.clearCookie("refreshToken");
    res.json({ message: "Logged out successfully" });
  } catch (error) {
    logger.error("Logout error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/sessions", authenticate, getSessions);

export default router;
