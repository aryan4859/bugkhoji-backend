export interface AuditLogData {
  userId: string
  action: AuditAction
  entity: string
  entityId: string
  details: string
  reportId?: string
  paymentId?: string
  id?: string
  timestamp?: Date
}
export type AuditAction =
  | "REGISTER"
  | "LOGIN_SUCCESS"
  | "LOGIN_FAILED"
  | "TOKEN_REFRESH"
  | "LOGOUT"
  | "PASSWORD_CHANGE"
;

