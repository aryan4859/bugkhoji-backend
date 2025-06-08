import type { Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import {
  loginSchema,
  registerSchema,
  refreshTokenSchema,
  changePasswordSchema,
} from "../schemas/auth.schemas";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  invalidateRefreshToken,
} from "../utils/token";
import { createAuditLog } from "../utils/audit";
import { logger } from "../utils/logger";
import jwt from "jsonwebtoken";

const prisma = new PrismaClient();

export async function register(req: Request, res: Response) {
  try {
    // Validate request body
    const validatedData = registerSchema.parse(req.body);

    // Check if email already exists
    const existingEmail = await prisma.user.findUnique({
      where: { email: validatedData.email },
    });

    if (existingEmail) {
      return res.status(409).json({ error: "Email already in use" });
    }

    // Check if username already exists
    const existingUsername = await prisma.user.findUnique({
      where: { username: validatedData.username },
    });

    if (existingUsername) {
      return res.status(409).json({ error: "Username already in use" });
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(validatedData.password, saltRounds);

    // Create user
    const user = await prisma.user.create({
      data: {
        email: validatedData.email,
        passwordHash,
        firstName: validatedData.firstName,
        lastName: validatedData.lastName,
        username: validatedData.username,
        role: "RESEARCHER", 
      },
    });

    // Create audit log
    await createAuditLog(
      {
        userId: user.id,
        action: "REGISTER",
        entity: "USER",
        entityId: user.id,
        details: "User registered",
      },
      req
    );

    // Generate tokens
    const accessToken = generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    const { token: refreshToken } = await generateRefreshToken(user.id);

    // Set refresh token as HTTP-only cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Return user data and access token
    return res.status(201).json({
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
      accessToken,
    });
  } catch (error) {
    logger.error("Registration error:", error);
    const errorMessage =
      error instanceof Error ? error.message : "An unknown error occurred";
    return res.status(400).json({ error: errorMessage });
  }
}

export async function login(req: Request, res: Response) {
  try {
    // Validate request body
    const validatedData = loginSchema.parse(req.body);

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email: validatedData.email },
    });

    // Check if user exists and is active
    if (!user || !user.isActive) {
      logger.warn(
        `Login attempt for non-existent or inactive user: ${validatedData.email}`
      );
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check password
    const passwordMatch = await bcrypt.compare(
      validatedData.password,
      user.passwordHash
    );

    if (!passwordMatch) {
      logger.warn(`Failed login attempt for user: ${user.email}`);

      // Create audit log for failed login
      await createAuditLog(
        {
          userId: user.id,
          action: "LOGIN_FAILED",
          entity: "USER",
          entityId: user.id,
          details: "Failed login attempt",
        },
        req
      );

      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Update last login timestamp
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() },
    });

    // Generate tokens
    const accessToken = generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    const { token: refreshToken } = await generateRefreshToken(user.id);

    // Set refresh token as HTTP-only cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Create audit log for successful login
    await createAuditLog(
      {
        userId: user.id,
        action: "LOGIN_SUCCESS",
        entity: "USER",
        entityId: user.id,
        details: "Successful login",
      },
      req
    );

    // Return user data and access token
    return res.status(200).json({
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
      accessToken,
    });
  } catch (error) {
    logger.error("Login error:", error);
    const errorMessage =
      error instanceof Error ? error.message : "An unknown error occurred";
    return res.status(400).json({ error: errorMessage });
  }
}

export async function refreshToken(req: Request, res: Response) {
  try {
    // Get refresh token from cookie
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ error: "Refresh token not found" });
    }

    // Validate request body if using body instead of cookie
    if (req.body.refreshToken) {
      const validatedData = refreshTokenSchema.parse(req.body);
    }

    // Decode token to get user ID
    const decoded = jwt.decode(req.body.refreshToken || refreshToken) as {
      id: string;
    } | null;

    if (!decoded || !decoded.id) {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    // Verify refresh token
    const isValid = await verifyRefreshToken(refreshToken, decoded.id);

    if (!isValid) {
      logger.warn(`Invalid refresh token used for user ID: ${decoded.id}`);
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    // Get user data
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, email: true, role: true, isActive: true },
    });

    if (!user || !user.isActive) {
      logger.warn(
        `Refresh token used for non-existent or inactive user: ${decoded.id}`
      );
      return res.status(401).json({ error: "User not found or inactive" });
    }

    // Generate new tokens
    const accessToken = generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    const { token: newRefreshToken } = await generateRefreshToken(user.id);

    // Set new refresh token as HTTP-only cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Create audit log
    await createAuditLog(
      {
        userId: user.id,
        action: "TOKEN_REFRESH",
        entity: "USER",
        entityId: user.id,
        details: "Refresh token used to generate new tokens",
      },
      req
    );

    // Return new access token
    return res.status(200).json({ accessToken });
  } catch (error) {
    logger.error("Token refresh error:", error);
    const errorMessage =
      error instanceof Error ? error.message : "An unknown error occurred";
    return res.status(400).json({ error: errorMessage });
  }
}

export async function logout(req: Request, res: Response) {
  try {
    // Get user ID from authenticated request
    const userId = req.user?.id;

    if (userId) {
      // Invalidate refresh token
      await invalidateRefreshToken(userId);

      // Create audit log
      await createAuditLog(
        {
          userId,
          action: "LOGOUT",
          entity: "USER",
          entityId: userId,
          details: "User logged out",
        },
        req
      );
    }

    // Clear refresh token cookie
    res.clearCookie("refreshToken");

    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    logger.error("Logout error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}

export async function changePassword(req: Request, res: Response) {
  try {
    // Get user ID from authenticated request
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Validate request body
    const validatedData = changePasswordSchema.parse(req.body);

    // Get user
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check current password
    const passwordMatch = await bcrypt.compare(
      validatedData.currentPassword,
      user.passwordHash
    );

    if (!passwordMatch) {
      logger.warn(`Failed password change attempt for user: ${user.email}`);
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    // Hash new password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(
      validatedData.newPassword,
      saltRounds
    );

    // Update password
    await prisma.user.update({
      where: { id: userId },
      data: { passwordHash },
    });

    // Invalidate refresh tokens
    await invalidateRefreshToken(userId);

    // Create audit log
    await createAuditLog(
      {
        userId,
        action: "PASSWORD_CHANGE",
        entity: "USER",
        entityId: userId,
        details: "User changed password",
      },
      req
    );

    // Clear refresh token cookie
    res.clearCookie("refreshToken");

    return res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    logger.error("Password change error:", error);
    const errorMessage =
      error instanceof Error ? error.message : "An unknown error occurred";
    return res.status(400).json({ error: errorMessage });
  }
}
