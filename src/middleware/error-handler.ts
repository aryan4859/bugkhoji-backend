import type { Request, Response, NextFunction } from "express"
import { logger } from "../utils/logger"
import { ZodError } from "zod"
import { Prisma } from "@prisma/client"
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library"

export function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  // Log the error
  logger.error("Error caught by error handler:", {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  })

  // Handle Zod validation errors
  if (err instanceof ZodError) {
    return res.status(400).json({
      error: "Validation error",
      details: err.errors,
    })
  }

  if (err instanceof PrismaClientKnownRequestError) {
    // Handle unique constraint violations
    if (err.code === "P2002") {
      return res.status(409).json({
        error: "Resource already exists",
        details: `A resource with this ${err.meta?.target as string} already exists`,
      })
    }

    // Handle not found errors
    if (err.code === "P2025") {
      return res.status(404).json({
        error: "Resource not found",
        details: err.meta?.cause,
      })
    }

    // Other Prisma errors
    return res.status(500).json({
      error: "Database error",
      details: process.env.NODE_ENV === "production" ? "An error occurred" : err.message,
    })
  }

  // Default error handler
  res.status(500).json({
    error: "Internal server error",
    details: process.env.NODE_ENV === "production" ? undefined : err.message,
  })
}
