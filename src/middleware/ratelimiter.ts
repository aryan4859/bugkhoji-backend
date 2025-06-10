import rateLimit from "express-rate-limit";

export const rateLimiting = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: "Too many login attempts from this IP, try after 15 mins",
});
