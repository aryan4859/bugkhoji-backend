import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import { config } from "./config";
import { logger } from "./logger";

const prisma = new PrismaClient();

export async function seedAdmin() {
  try {
    if (!config.ADMIN_EMAIL) {
      logger.error("ADMIN_EMAIL is not set in config.");
      return;
    }

    const adminExists = await prisma.user.findUnique({
      where: { email: config.ADMIN_EMAIL },
    });

    if (!adminExists) {
      const passwordHash = await bcrypt.hash(config.ADMIN_PASSWORD!, 12);

      await prisma.user.create({
        data: {
          email: config.ADMIN_EMAIL!,
          passwordHash,
          username: config.ADMIN_USERNAME!,
          firstName: config.ADMIN_FIRST_NAME!,
          lastName: config.ADMIN_LAST_NAME!,
          role: "ADMIN",
          isActive: true,
        },
      });

      logger.info("Admin user seeded successfully");
    }
  } catch (error) {
    logger.error("Error seeding admin user:", error);
  }
}
