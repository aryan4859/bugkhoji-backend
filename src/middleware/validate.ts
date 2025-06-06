import { Request, Response, NextFunction } from "express";
import { Schema } from "joi";

export const validate =
  (schema: Schema) =>
  (req: Request, res: Response, next: NextFunction): void => {
    const { error } = schema.validate(req.body, {
      abortEarly: false,
      allowUnknown: false,
      stripUnknown: true,
    });

    if (error) {
      res.status(400).json({
        message: "Validation error",
        details: error.details.map((d) => d.message),
      });
      return;
    }

    next();
  };
