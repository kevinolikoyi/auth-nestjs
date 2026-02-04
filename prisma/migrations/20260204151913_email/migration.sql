-- AlterTable
ALTER TABLE "User" ADD COLUMN     "emailVerificationExpires" TIMESTAMP(3),
ADD COLUMN     "lastVerificationEmailSent" TIMESTAMP(3),
ADD COLUMN     "verificationEmailCount" INTEGER NOT NULL DEFAULT 0;
