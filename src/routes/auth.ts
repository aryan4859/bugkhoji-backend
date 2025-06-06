import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt, { Secret, SignOptions } from "jsonwebtoken";
import Joi from "joi";

import User, { UserRole } from "../models/user.model";
import logger from "../utils/logger";
import { validate } from "../middleware/validate";
import { config } from "../utils/config";

const router = Router();

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).max(128).required(),
});

const registerSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  fullName: Joi.string().min(3).max(100).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).max(128).required(),
});

const generateToken = (id: string, role: UserRole): string => {
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

// 🔐 Researcher Registration
router.post(
  "/register/researcher",
  validate(registerSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password, username, fullName } = req.body;

      const existing = await User.findOne({ email });
      if (existing) {
        res.status(409).json({ message: "Email already exists" });
        return;
      }

      const hashed = await bcrypt.hash(password, 12);
      const user = new User({
        email,
        password: hashed,
        username,
        fullName,
        role: "researcher",
      });

      await user.save();
      res.status(201).json({ message: "Registration successful" });
    } catch (err) {
      res.status(500).json({ message: "Server error during registration" });
    }
  }
);

router.post(
  "/login/researcher",
  validate(loginSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password } = req.body;

      const user = (await User.findOne({ email })) as typeof User.prototype & {
        _id: any;
        role: UserRole;
        password: string;
      };
      if (!user || user.role !== "researcher") {
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      const token = generateToken(user._id.toString(), user.role);
      res.json({ token });
    } catch (err) {
      logger.error("Researcher login error:", err);
      res.status(500).json({ message: "Server error during login" });
    }
  }
);

router.post(
  "/login/admin",
  validate(loginSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password } = req.body;

      const user = (await User.findOne({ email })) as typeof User.prototype & {
        _id: any;
        role: UserRole;
        password: string;
      };
      if (!user || user.role !== "admin") {
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        res.status(401).json({ message: "Invalid email or password" });
        return;
      }

      const token = generateToken(user._id.toString(), user.role);
      res.json({ token });
    } catch (err) {
      logger.error("Admin login error:", err);
      res.status(500).json({ message: "Server error during login" });
    }
  }
);

export default router;
