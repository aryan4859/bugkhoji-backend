import { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload as DefaultJwtPayload } from "jsonwebtoken";
import User, { IUser } from "../models/user.model";
import { config } from "../utils/config";

interface CustomJwtPayload extends DefaultJwtPayload {
  id: string;
  role: "researcher" | "admin";
}

export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({ message: "Authorization token required" });
      return;
    }

    const token = authHeader.split(" ")[1];
    const secret = config.JWT_SECRET;
    if (!secret) {
      throw new Error("JWT_SECRET not set in environment");
    }

    const decoded = jwt.verify(token, secret) as CustomJwtPayload;

    const user: IUser | null = await User.findById(decoded.id).select(
      "-password"
    );
    if (!user) {
      res.status(401).json({ message: "Unauthorized user" });
      return;
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid or expired token" });
    return;
  }
};

export const authorize = (roles: Array<"researcher" | "admin">) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user || !roles.includes(req.user.role)) {
      res.status(403).json({ message: "Forbidden: insufficient privileges" });
      return;
    }
    next();
  };
};
