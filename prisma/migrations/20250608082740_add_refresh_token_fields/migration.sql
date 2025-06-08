/*
  Warnings:

  - You are about to drop the column `mfaEnabled` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `mfaSecret` on the `users` table. All the data in the column will be lost.
  - You are about to drop the `Session` table. If the table is not empty, all the data it contains will be lost.

*/
-- AlterTable
ALTER TABLE "users" DROP COLUMN "mfaEnabled",
DROP COLUMN "mfaSecret",
ADD COLUMN     "refreshTokenExpiresAt" TIMESTAMP(3),
ADD COLUMN     "refreshTokenHash" TEXT;

-- DropTable
DROP TABLE "Session";
