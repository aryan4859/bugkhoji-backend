export interface Session {
  sessionId: string;
  userId: string;
  ip: string;
  userAgent: string;
  location?: string;
  createdAt: Date;
  lastSeen: Date;
}
