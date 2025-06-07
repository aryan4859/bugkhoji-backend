import { Router, type Request, type Response } from "express"
import bcrypt from "bcryptjs"
import jwt, { type Secret, type SignOptions } from "jsonwebtoken"
import { z } from "zod"
import { PrismaClient } from "@prisma/client"
import rateLimit from "express-rate-limit"
import { logger } from "../utils/logger"
import { validate } from "../middleware/validate"
import { config } from "../utils/config"
import { createAuditLog } from "../utils/audit"
import { generateRefreshToken } from "../utils/token"

const router = Router()
const prisma = new PrismaClient()

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many authentication attempts, please try again later" },
  keyGenerator: (req) => {
    // Use IP + email for more granular rate limiting
    const email = req.body?.email || "unknown"
    return `${req.ip}-${email}`
  },
})

// Validation schemas using Zod (more secure than Joi)
const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(8, "Password must be at least 8 characters").max(128, "Password too long"),
})

const registerSchema = z.object({
  username: z
    .string()
    .min(3, "Username must be at least 3 characters")
    .max(30, "Username too long")
    .regex(/^[a-zA-Z0-9_]+$/, "Username can only contain letters, numbers, and underscores"),
  fullName: z.string().min(3, "Full name must be at least 3 characters").max(100, "Full name too long"),
  email: z.string().email("Invalid email address"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password too long")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[0-9]/, "Password must contain at least one number")
    .regex(/[^A-Za-z0-9]/, "Password must contain at least one special character"),
})

// Helper function to generate JWT token (keeping your existing logic)
const generateToken = (id: string, role: string): string => {
  const secret = config.JWT_SECRET

  if (!secret) {
    throw new Error("JWT_SECRET not defined")
  }

  const expiresIn = process.env.JWT_ACCESS_EXPIRE || "15m"

  const payload = { id, role }
  const options: SignOptions = {
    expiresIn: expiresIn as SignOptions["expiresIn"],
  }

  return jwt.sign(payload, secret as Secret, options)
}

// 🔐 Researcher Registration
router.post(
  "/register/researcher",
  authLimiter,
  validate(registerSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password, username, fullName } = req.body

      // Log registration attempt
      logger.info(`Registration attempt for email: ${email}`)

      if (!req.body) {
        logger.error("Request body is missing")
        res.status(400).json({ error: "Request body is required" })
        return
      }

      // Check if email already exists
      const existingEmail = await prisma.user.findUnique({
        where: { email },
      })

      if (existingEmail) {
        logger.warn(`Registration attempt with existing email: ${email}`)
        res.status(409).json({ message: "Email already exists" })
        return
      }

      // Check if username already exists
      const existingUsername = await prisma.user.findUnique({
        where: { username },
      })

      if (existingUsername) {
        logger.warn(`Registration attempt with existing username: ${username}`)
        res.status(409).json({ message: "Username already exists" })
        return
      }

      // Hash password with higher salt rounds for security
      const hashed = await bcrypt.hash(password, 12)

      // Create user with Prisma
      const user = await prisma.user.create({
        data: {
          email,
          passwordHash: hashed,
          username,
          firstName: fullName.split(" ")[0] || fullName,
          lastName: fullName.split(" ").slice(1).join(" ") || "",
          role: "RESEARCHER",
        },
      })

      // Create audit log
      await createAuditLog(
        {
          userId: user.id,
          action: "REGISTER",
          entity: "USER",
          entityId: user.id,
          details: "Researcher registration successful",
        },
        req,
      )

      logger.info(`Researcher registration successful for user: ${user.id}`)
      res.status(201).json({ message: "Registration successful" })
    } catch (err) {
      logger.error("Server error during researcher registration:", err)
      res.status(500).json({ message: "Server error during registration" })
    }
  },
)

// 🔐 Researcher Login
router.post(
  "/login/researcher",
  authLimiter,
  validate(loginSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password } = req.body

      logger.info(`Login attempt for researcher email: ${email}`)

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
      })

      // Check if user exists, is a researcher, and is active
      if (!user || user.role !== "RESEARCHER" || !user.isActive) {
        logger.warn(`Failed login attempt for researcher email: ${email} - User not found or invalid role`)

        // Create audit log for failed attempt if user exists
        if (user) {
          await createAuditLog(
            {
              userId: user.id,
              action: "LOGIN_FAILED",
              entity: "USER",
              entityId: user.id,
              details: "Failed researcher login attempt - invalid role or inactive account",
            },
            req,
          )
        }

        res.status(401).json({ message: "Invalid email or password" })
        return
      }

      // Verify password
      const passwordMatch = await bcrypt.compare(password, user.passwordHash)
      if (!passwordMatch) {
        logger.warn(`Failed login attempt for researcher: ${user.email} - Invalid password`)

        // Create audit log for failed password
        await createAuditLog(
          {
            userId: user.id,
            action: "LOGIN_FAILED",
            entity: "USER",
            entityId: user.id,
            details: "Failed researcher login attempt - invalid password",
          },
          req,
        )

        res.status(401).json({ message: "Invalid email or password" })
        return
      }

      // Update last login timestamp
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLogin: new Date() },
      })

      // Generate tokens
      const accessToken = generateToken(user.id, user.role)
      const { token: refreshToken } = await generateRefreshToken(user.id)

      // Set refresh token as HTTP-only cookie
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      })

      // Create audit log for successful login
      await createAuditLog(
        {
          userId: user.id,
          action: "LOGIN_SUCCESS",
          entity: "USER",
          entityId: user.id,
          details: "Successful researcher login",
        },
        req,
      )

      logger.info(`Successful researcher login for user: ${user.id}`)

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
      })
    } catch (err) {
      logger.error("Researcher login error:", err)
      res.status(500).json({ message: "Server error during login" })
    }
  },
)

// 🔐 Admin Login
router.post("/login/admin", authLimiter, validate(loginSchema), async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body

    logger.info(`Login attempt for admin email: ${email}`)

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
        mfaEnabled: true,
      },
    })

    // Check if user exists, is an admin, and is active
    if (!user || user.role !== "ADMIN" || !user.isActive) {
      logger.warn(`Failed login attempt for admin email: ${email} - User not found or invalid role`)

      // Create audit log for failed attempt if user exists
      if (user) {
        await createAuditLog(
          {
            userId: user.id,
            action: "LOGIN_FAILED",
            entity: "USER",
            entityId: user.id,
            details: "Failed admin login attempt - invalid role or inactive account",
          },
          req,
        )
      }

      res.status(401).json({ message: "Invalid email or password" })
      return
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.passwordHash)
    if (!passwordMatch) {
      logger.warn(`Failed login attempt for admin: ${user.email} - Invalid password`)

      // Create audit log for failed password
      await createAuditLog(
        {
          userId: user.id,
          action: "LOGIN_FAILED",
          entity: "USER",
          entityId: user.id,
          details: "Failed admin login attempt - invalid password",
        },
        req,
      )

      res.status(401).json({ message: "Invalid email or password" })
      return
    }

    // TODO: Implement MFA check for admin accounts
    // if (user.mfaEnabled) {
    //   // Handle MFA verification
    // }

    // Update last login timestamp
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() },
    })

    // Generate tokens
    const accessToken = generateToken(user.id, user.role)
    const { token: refreshToken } = await generateRefreshToken(user.id)

    // Set refresh token as HTTP-only cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    })

    // Create audit log for successful login
    await createAuditLog(
      {
        userId: user.id,
        action: "LOGIN_SUCCESS",
        entity: "USER",
        entityId: user.id,
        details: "Successful admin login",
      },
      req,
    )

    logger.info(`Successful admin login for user: ${user.id}`)

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
    })
  } catch (err) {
    logger.error("Admin login error:", err)
    res.status(500).json({ message: "Server error during login" })
  }
})

// 🔐 Refresh Token Endpoint
router.post("/refresh", async (req: Request, res: Response): Promise<void> => {
  try {
    // Get refresh token from cookie
    const refreshToken = req.cookies.refreshToken

    if (!refreshToken) {
      res.status(401).json({ error: "Refresh token not found" })
      return
    }

    // Verify refresh token (implementation from token utils)
    const { verifyRefreshToken } = await import("../utils/token")

    // Extract user ID from token (you'll need to implement this)
    const decoded = jwt.decode(refreshToken) as { id: string } | null

    if (!decoded || !decoded.id) {
      res.status(401).json({ error: "Invalid refresh token" })
      return
    }

    const isValid = await verifyRefreshToken(refreshToken, decoded.id)

    if (!isValid) {
      logger.warn(`Invalid refresh token used for user ID: ${decoded.id}`)
      res.status(401).json({ error: "Invalid refresh token" })
      return
    }

    // Get user data
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, email: true, role: true, isActive: true },
    })

    if (!user || !user.isActive) {
      logger.warn(`Refresh token used for non-existent or inactive user: ${decoded.id}`)
      res.status(401).json({ error: "User not found or inactive" })
      return
    }

    // Generate new tokens
    const accessToken = generateToken(user.id, user.role)
    const { token: newRefreshToken } = await generateRefreshToken(user.id)

    // Set new refresh token as HTTP-only cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    })

    // Create audit log
    await createAuditLog(
      {
        userId: user.id,
        action: "TOKEN_REFRESH",
        entity: "USER",
        entityId: user.id,
        details: "Refresh token used to generate new tokens",
      },
      req,
    )

    res.json({ token: accessToken })
  } catch (error) {
    logger.error("Token refresh error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// 🔐 Logout Endpoint
router.post("/logout", async (req: Request, res: Response): Promise<void> => {
  try {
    // Get user ID from token if available
    const authHeader = req.headers.authorization
    let userId: string | null = null

    if (authHeader && authHeader.startsWith("Bearer ")) {
      try {
        const token = authHeader.split(" ")[1]
        const decoded = jwt.verify(token, config.JWT_SECRET as string) as { id: string }
        userId = decoded.id
      } catch (error) {
        // Token might be expired, but we still want to clear cookies
        logger.warn("Invalid token during logout:", error)
      }
    }

    if (userId) {
      // Invalidate refresh token
      const { invalidateRefreshToken } = await import("../utils/token")
      await invalidateRefreshToken(userId)

      // Create audit log
      await createAuditLog(
        {
          userId,
          action: "LOGOUT",
          entity: "USER",
          entityId: userId,
          details: "User logged out",
        },
        req,
      )
    }

    // Clear refresh token cookie
    res.clearCookie("refreshToken")

    res.json({ message: "Logged out successfully" })
  } catch (error) {
    logger.error("Logout error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

export default router
