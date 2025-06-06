import "dotenv/config";

export const config = {
  PORT: String(process.env.PORT),
  MONGODB_URL: String(process.env.MONGODB_URL),
  JWT_SECRET: String(process.env.JWT_SECRET),
  JWT_ACCESS_EXPIRE: process.env.JWT_ACCESS_EXPIRE,
  JWT_REFRESH_EXPIRE: process.env.JWT_REFRESH_EXPIRE,
};
