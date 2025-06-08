// import { PrismaClient } from "@prisma/client"
// import type { Request } from "express"
// import { auditLogger } from "./logger"

// const prisma = new PrismaClient()

// interface AuditLogData {
//   userId: string
//   action: string
//   entity: string
//   entityId: string
//   details: string
//   reportId?: string
//   paymentId?: string
// }

// /**
//  * Create an audit log entry
//  * @param data - Audit log data
//  * @param req - Express request object for IP and user agent
//  */
// export async function createAuditLog(data: AuditLogData, req?: Request): Promise<void> {
//   try {
//     // Create audit log in database
//     await prisma.auditLog.create({
//       data: {
//         userId: data.userId,
//         action: data.action,
//         entity: data.entity,
//         entityId: data.entityId,
//         details: data.details,
//         ipAddress: req?.ip,
//         userAgent: req?.headers["user-agent"],
//         reportId: data.reportId,
//         paymentId: data.paymentId,
//       },
//     })

//     // Also log to audit log file
//     auditLogger.info("Audit event", {
//       userId: data.userId,
//       action: data.action,
//       entity: data.entity,
//       entityId: data.entityId,
//       details: data.details,
//       ipAddress: req?.ip,
//       userAgent: req?.headers["user-agent"],
//       timestamp: new Date().toISOString(),
//     })
//   } catch (error) {
//     // Log error but don't throw - audit logging should not break the application
//     auditLogger.error("Failed to create audit log:", error)
//   }
// }
