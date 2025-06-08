import { Request, Response, NextFunction } from "express";
import { ZodSchema } from "zod";

export const validate =
  (schema: ZodSchema) =>
  (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      res.status(400).json({
        message: "Validation error",
        details: result.error.errors.map((err) => err.message),
      });
      return;
    }

    // Replace body with parsed data (optional, but ensures type safety)
    req.body = result.data;
    next();
  };