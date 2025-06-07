import jwt from "jsonwebtoken"
import crypto from "crypto"
import { PrismaClient } from "@prisma/client"
import { logger } from "./logger"
import { config } from "./config"

const prisma = new PrismaClient()

interface TokenPayload {
  id: string
  email: string
  role: string
}

/**
 * Generate access token
 * @param payload - User data to include in token
 * @returns Access token
 */
export function generateAccessToken(payload: TokenPayload): string {
  return jwt.sign(payload, config.JWT_SECRET as string, {
    expiresIn: config.JWT_ACCESS_EXPIRE as string | number,
  })
}

/**
 * Generate refresh token
 * @param userId - User ID
 * @returns Refresh token and its hash
 */
export async function generateRefreshToken(userId: string): Promise<{ token: string; hash: string }> {
  // Generate a random token
  const refreshToken = crypto.randomBytes(40).toString("hex")

  // Hash the token for storage
  const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex")

  // Store the hashed token in the database
  try {
    await prisma.user.update({
      where: { id: userId },
      data: { refreshTokenHash },
    })

    return { token: refreshToken, hash: refreshTokenHash }
  } catch (error) {
    logger.error("Error storing refresh token:", error)
    throw new Error("Failed to generate refresh token")
  }
}

/**
 * Verify refresh token
 * @param token - Refresh token
 * @param userId - User ID
 * @returns Boolean indicating if token is valid
 */
export async function verifyRefreshToken(token: string, userId: string): Promise<boolean> {
  try {
    // Hash the provided token
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex")

    // Find the user with this token hash
    const user = await prisma.user.findFirst({
      where: {
        id: userId,
        refreshTokenHash: tokenHash,
      },
    })

    return !!user
  } catch (error) {
    logger.error("Error verifying refresh token:", error)
    return false
  }
}

/**
 * Invalidate refresh token
 * @param userId - User ID
 */
export async function invalidateRefreshToken(userId: string): Promise<void> {
  try {
    await prisma.user.update({
      where: { id: userId },
      data: { refreshTokenHash: null },
    })
  } catch (error) {
    logger.error("Error invalidating refresh token:", error)
    throw new Error("Failed to invalidate refresh token")
  }
}
