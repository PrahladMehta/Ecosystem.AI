-- CreateEnum
CREATE TYPE "Role" AS ENUM ('User', 'Admin', 'Guest', 'Member');

-- CreateEnum
CREATE TYPE "Subscription" AS ENUM ('pro', 'business', 'team', 'enterprise');

-- CreateTable
CREATE TABLE "users" (
    "id" SERIAL NOT NULL,
    "firstName" VARCHAR(50),
    "lastName" VARCHAR(50),
    "phoneNumber" VARCHAR(20),
    "image" VARCHAR(100),
    "email" VARCHAR(100) NOT NULL,
    "password" VARCHAR(255),
    "city" VARCHAR(30),
    "company" VARCHAR(50),
    "country" VARCHAR(50),
    "role" "Role" NOT NULL DEFAULT 'User',
    "subscriptionType" "Subscription",
    "numberOfTeamMembers" INTEGER NOT NULL DEFAULT 0,
    "paymentId" VARCHAR(100),
    "activeProfile" BOOLEAN NOT NULL DEFAULT false,
    "isProfileComplete" BOOLEAN NOT NULL DEFAULT false,
    "stripeCustomerId" VARCHAR(50),
    "subscriptionStatus" VARCHAR(50),
    "subscriptionId" VARCHAR(100),
    "refreshToken" VARCHAR(255),
    "otp" VARCHAR(6),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "password_reset_tokens" (
    "id" SERIAL NOT NULL,
    "email" VARCHAR(100) NOT NULL,
    "token" VARCHAR(255) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "password_reset_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "teamMembers" (
    "id" INTEGER NOT NULL,
    "memberId" INTEGER NOT NULL,
    "adminId" INTEGER NOT NULL,
    "role" "Role" NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "teamMembers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "invite_tokens" (
    "id" SERIAL NOT NULL,
    "email" VARCHAR(100) NOT NULL,
    "token" VARCHAR(255) NOT NULL,
    "adminId" INTEGER NOT NULL,
    "role" "Role" NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "accepted" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "invite_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "password_reset_tokens_token_key" ON "password_reset_tokens"("token");

-- CreateIndex
CREATE UNIQUE INDEX "invite_tokens_token_key" ON "invite_tokens"("token");
