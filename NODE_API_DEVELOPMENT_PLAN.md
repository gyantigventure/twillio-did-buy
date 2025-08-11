# Node.js API Development Plan for DID Buy System with Twilio

## 1. Project Overview

This document outlines the detailed development plan for building a Node.js REST API that enables users to search, purchase, and manage DID (Direct Inward Dialing) numbers using Twilio's telephony services.

## 2. Technology Stack

### 2.1 Core Technologies
- **Runtime**: Node.js (v18+ LTS)
- **Framework**: Express.js with TypeScript
- **Database**: PostgreSQL (primary) + Redis (caching/sessions)
- **ORM**: Prisma ORM for type-safe database operations
- **Authentication**: JWT with refresh tokens
- **Validation**: Zod for request/response validation
- **Testing**: Jest + Supertest
- **Documentation**: Swagger/OpenAPI 3.0

### 2.2 Twilio Integration
- **SDK**: Twilio Node.js SDK (latest version)
- **Services**: Phone Numbers API, Voice API, Webhooks
- **Features**: Number search, purchase, configuration, call routing

### 2.3 Additional Libraries
```json
{
  "dependencies": {
    "express": "^4.18.2",
    "typescript": "^5.0.0",
    "@types/express": "^4.17.17",
    "twilio": "^4.19.0",
    "prisma": "^5.0.0",
    "@prisma/client": "^5.0.0",
    "jsonwebtoken": "^9.0.0",
    "bcrypt": "^5.1.0",
    "zod": "^3.21.0",
    "redis": "^4.6.0",
    "stripe": "^12.0.0",
    "winston": "^3.8.0",
    "helmet": "^7.0.0",
    "cors": "^2.8.5",
    "rate-limiter-flexible": "^3.0.0",
    "swagger-jsdoc": "^6.2.0",
    "swagger-ui-express": "^4.6.0"
  },
  "devDependencies": {
    "jest": "^29.5.0",
    "supertest": "^6.3.0",
    "@types/jest": "^29.5.0",
    "nodemon": "^2.0.0",
    "ts-node": "^10.9.0"
  }
}
```

## 3. Project Structure

```
did-buy-api/
├── src/
│   ├── controllers/           # Route handlers
│   │   ├── auth.controller.ts
│   │   ├── numbers.controller.ts
│   │   ├── orders.controller.ts
│   │   ├── billing.controller.ts
│   │   └── webhooks.controller.ts
│   ├── services/              # Business logic
│   │   ├── auth.service.ts
│   │   ├── twilio.service.ts
│   │   ├── numbers.service.ts
│   │   ├── orders.service.ts
│   │   ├── billing.service.ts
│   │   └── notification.service.ts
│   ├── middlewares/           # Custom middleware
│   │   ├── auth.middleware.ts
│   │   ├── validation.middleware.ts
│   │   ├── rate-limit.middleware.ts
│   │   └── error.middleware.ts
│   ├── models/               # Database models & types
│   │   ├── user.model.ts
│   │   ├── number.model.ts
│   │   ├── order.model.ts
│   │   └── index.ts
│   ├── routes/               # Route definitions
│   │   ├── auth.routes.ts
│   │   ├── numbers.routes.ts
│   │   ├── orders.routes.ts
│   │   ├── billing.routes.ts
│   │   └── index.ts
│   ├── schemas/              # Zod validation schemas
│   │   ├── auth.schemas.ts
│   │   ├── numbers.schemas.ts
│   │   └── common.schemas.ts
│   ├── utils/                # Utility functions
│   │   ├── logger.ts
│   │   ├── database.ts
│   │   ├── redis.ts
│   │   ├── encryption.ts
│   │   └── helpers.ts
│   ├── config/               # Configuration
│   │   ├── database.config.ts
│   │   ├── twilio.config.ts
│   │   ├── redis.config.ts
│   │   └── app.config.ts
│   └── app.ts               # Express app setup
├── prisma/
│   ├── schema.prisma
│   ├── migrations/
│   └── seed.ts
├── tests/
│   ├── unit/
│   ├── integration/
│   └── setup.ts
├── docs/
│   ├── api.yaml
│   └── README.md
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── docker-compose.dev.yml
├── scripts/
│   ├── setup.sh
│   ├── migrate.sh
│   └── seed.sh
├── .env.example
├── .gitignore
├── package.json
├── tsconfig.json
└── jest.config.js
```

## 4. Database Design

### 4.1 Prisma Schema

```prisma
// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id                String   @id @default(cuid())
  email             String   @unique
  password          String
  firstName         String
  lastName          String
  company           String?
  phone             String?
  emailVerified     Boolean  @default(false)
  emailVerificationToken String?
  passwordResetToken String?
  passwordResetExpires DateTime?
  isActive          Boolean  @default(true)
  role              UserRole @default(USER)
  createdAt         DateTime @default(now())
  updatedAt         DateTime @updatedAt

  // Relationships
  numbers           Number[]
  orders            Order[]
  billingAccount    BillingAccount?
  sessions          Session[]

  @@map("users")
}

model Number {
  id              String      @id @default(cuid())
  phoneNumber     String      @unique
  friendlyName    String?
  countryCode     String
  region          String?
  locality        String?
  areaCode        String?
  numberType      NumberType
  capabilities    String[]    // ["voice", "sms", "mms", "fax"]
  twilioSid       String      @unique
  status          NumberStatus @default(ACTIVE)
  monthlyPrice    Decimal
  setupPrice      Decimal?
  
  // Call routing configuration
  voiceUrl        String?
  voiceMethod     HttpMethod? @default(POST)
  voiceFallbackUrl String?
  statusCallback  String?
  
  // Purchase information
  purchasedAt     DateTime    @default(now())
  userId          String
  orderId         String?
  
  // Metadata
  createdAt       DateTime    @default(now())
  updatedAt       DateTime    @updatedAt

  // Relationships
  user            User        @relation(fields: [userId], references: [id])
  order           Order?      @relation(fields: [orderId], references: [id])
  callLogs        CallLog[]

  @@map("numbers")
}

model Order {
  id              String      @id @default(cuid())
  orderNumber     String      @unique
  userId          String
  status          OrderStatus @default(PENDING)
  totalAmount     Decimal
  currency        String      @default("USD")
  
  // Payment information
  paymentIntentId String?
  paymentStatus   PaymentStatus @default(PENDING)
  paymentMethod   String?
  
  // Order items (numbers purchased)
  numbers         Number[]
  
  // Timestamps
  createdAt       DateTime    @default(now())
  updatedAt       DateTime    @updatedAt
  completedAt     DateTime?

  // Relationships
  user            User        @relation(fields: [userId], references: [id])

  @@map("orders")
}

model BillingAccount {
  id              String      @id @default(cuid())
  userId          String      @unique
  stripeCustomerId String?    @unique
  
  // Billing details
  company         String?
  address         Json?
  taxId           String?
  
  // Account status
  accountBalance  Decimal     @default(0)
  creditLimit     Decimal?
  isActive        Boolean     @default(true)
  
  // Timestamps
  createdAt       DateTime    @default(now())
  updatedAt       DateTime    @updatedAt

  // Relationships
  user            User        @relation(fields: [userId], references: [id])
  invoices        Invoice[]

  @@map("billing_accounts")
}

model Invoice {
  id                String        @id @default(cuid())
  invoiceNumber     String        @unique
  billingAccountId  String
  
  // Invoice details
  amount            Decimal
  currency          String        @default("USD")
  status            InvoiceStatus @default(DRAFT)
  dueDate           DateTime
  
  // Line items
  lineItems         Json
  
  // Payment
  paidAt            DateTime?
  paymentMethod     String?
  
  // Timestamps
  createdAt         DateTime      @default(now())
  updatedAt         DateTime      @updatedAt

  // Relationships
  billingAccount    BillingAccount @relation(fields: [billingAccountId], references: [id])

  @@map("invoices")
}

model CallLog {
  id              String      @id @default(cuid())
  twilioCallSid   String      @unique
  numberId        String
  
  // Call details
  from            String
  to              String
  direction       CallDirection
  status          CallStatus
  duration        Int?        // in seconds
  price           Decimal?
  priceUnit       String?
  
  // Timestamps
  startTime       DateTime?
  endTime         DateTime?
  createdAt       DateTime    @default(now())

  // Relationships
  number          Number      @relation(fields: [numberId], references: [id])

  @@map("call_logs")
}

model Session {
  id              String      @id @default(cuid())
  userId          String
  refreshToken    String      @unique
  expiresAt       DateTime
  isRevoked       Boolean     @default(false)
  createdAt       DateTime    @default(now())

  // Relationships
  user            User        @relation(fields: [userId], references: [id])

  @@map("sessions")
}

// Enums
enum UserRole {
  USER
  ADMIN
  SUPER_ADMIN
}

enum NumberType {
  LOCAL
  TOLL_FREE
  MOBILE
  INTERNATIONAL
}

enum NumberStatus {
  ACTIVE
  SUSPENDED
  RELEASED
  PENDING
}

enum HttpMethod {
  GET
  POST
}

enum OrderStatus {
  PENDING
  PROCESSING
  COMPLETED
  CANCELLED
  FAILED
}

enum PaymentStatus {
  PENDING
  SUCCEEDED
  FAILED
  CANCELLED
  REFUNDED
}

enum InvoiceStatus {
  DRAFT
  SENT
  PAID
  OVERDUE
  CANCELLED
}

enum CallDirection {
  INBOUND
  OUTBOUND
}

enum CallStatus {
  INITIATED
  RINGING
  ANSWERED
  COMPLETED
  BUSY
  FAILED
  NO_ANSWER
  CANCELLED
}
```

## 5. API Endpoints Specification

### 5.1 Authentication Endpoints

```typescript
// Auth Routes
POST   /api/v1/auth/register          // User registration
POST   /api/v1/auth/login             // User login
POST   /api/v1/auth/logout            // User logout
POST   /api/v1/auth/refresh           // Refresh access token
POST   /api/v1/auth/forgot-password   // Request password reset
POST   /api/v1/auth/reset-password    // Reset password
GET    /api/v1/auth/verify-email      // Verify email address
POST   /api/v1/auth/resend-verification // Resend verification email
```

### 5.2 Number Management Endpoints

```typescript
// Number Search & Purchase
GET    /api/v1/numbers/search         // Search available numbers
POST   /api/v1/numbers/purchase       // Purchase selected numbers
GET    /api/v1/numbers/pricing        // Get pricing information

// Number Management
GET    /api/v1/numbers                // Get user's numbers
GET    /api/v1/numbers/:id            // Get specific number details
PUT    /api/v1/numbers/:id            // Update number configuration
DELETE /api/v1/numbers/:id            // Release number
POST   /api/v1/numbers/:id/configure  // Configure call routing

// Number Capabilities
GET    /api/v1/numbers/countries      // Get supported countries
GET    /api/v1/numbers/area-codes     // Get available area codes
GET    /api/v1/numbers/types          // Get number types
```

### 5.3 Order Management Endpoints

```typescript
// Order Management
GET    /api/v1/orders                 // Get user's orders
GET    /api/v1/orders/:id             // Get specific order
POST   /api/v1/orders                 // Create new order
PUT    /api/v1/orders/:id/cancel      // Cancel order
GET    /api/v1/orders/:id/status      // Get order status
```

### 5.4 Billing Endpoints

```typescript
// Billing Management
GET    /api/v1/billing/account        // Get billing account
PUT    /api/v1/billing/account        // Update billing account
GET    /api/v1/billing/invoices       // Get invoices
GET    /api/v1/billing/invoices/:id   // Get specific invoice
POST   /api/v1/billing/payment-method // Add payment method
GET    /api/v1/billing/usage          // Get usage statistics
```

### 5.5 Analytics Endpoints

```typescript
// Analytics & Reporting
GET    /api/v1/analytics/calls        // Call analytics
GET    /api/v1/analytics/usage        // Usage statistics
GET    /api/v1/analytics/costs        // Cost analysis
GET    /api/v1/analytics/dashboard    // Dashboard metrics
```

### 5.6 Webhook Endpoints

```typescript
// Twilio Webhooks
POST   /api/v1/webhooks/twilio/voice       // Voice call webhooks
POST   /api/v1/webhooks/twilio/status      // Call status updates
POST   /api/v1/webhooks/stripe/payment     // Payment webhooks
```

## 6. Core Services Implementation

### 6.1 Twilio Service

```typescript
// src/services/twilio.service.ts
import { Twilio } from 'twilio';
import { config } from '../config/twilio.config';

export class TwilioService {
  private client: Twilio;

  constructor() {
    this.client = new Twilio(
      config.accountSid,
      config.authToken
    );
  }

  async searchNumbers(params: NumberSearchParams): Promise<AvailableNumber[]> {
    try {
      const numbers = await this.client.availablePhoneNumbers(params.countryCode)
        .local.list({
          areaCode: params.areaCode,
          contains: params.contains,
          nearLatLong: params.coordinates,
          distance: params.distance,
          limit: params.limit || 20
        });

      return numbers.map(this.mapTwilioNumber);
    } catch (error) {
      throw new TwilioError('Failed to search numbers', error);
    }
  }

  async purchaseNumber(phoneNumber: string, config?: NumberConfig): Promise<PurchasedNumber> {
    try {
      const number = await this.client.incomingPhoneNumbers.create({
        phoneNumber,
        voiceUrl: config?.voiceUrl,
        voiceMethod: config?.voiceMethod,
        statusCallback: config?.statusCallback,
        friendlyName: config?.friendlyName
      });

      return this.mapPurchasedNumber(number);
    } catch (error) {
      throw new TwilioError('Failed to purchase number', error);
    }
  }

  async configureNumber(sid: string, config: NumberConfig): Promise<void> {
    try {
      await this.client.incomingPhoneNumbers(sid).update(config);
    } catch (error) {
      throw new TwilioError('Failed to configure number', error);
    }
  }

  async releaseNumber(sid: string): Promise<void> {
    try {
      await this.client.incomingPhoneNumbers(sid).remove();
    } catch (error) {
      throw new TwilioError('Failed to release number', error);
    }
  }

  private mapTwilioNumber(twilioNumber: any): AvailableNumber {
    return {
      phoneNumber: twilioNumber.phoneNumber,
      friendlyName: twilioNumber.friendlyName,
      locality: twilioNumber.locality,
      region: twilioNumber.region,
      countryCode: twilioNumber.isoCountry,
      capabilities: twilioNumber.capabilities,
      price: {
        setup: parseFloat(twilioNumber.price),
        monthly: parseFloat(twilioNumber.monthlyPrice)
      }
    };
  }
}
```

### 6.2 Numbers Service

```typescript
// src/services/numbers.service.ts
import { PrismaClient } from '@prisma/client';
import { TwilioService } from './twilio.service';

export class NumbersService {
  constructor(
    private prisma: PrismaClient,
    private twilioService: TwilioService
  ) {}

  async searchAvailableNumbers(params: NumberSearchParams): Promise<SearchResult> {
    // Search available numbers via Twilio
    const availableNumbers = await this.twilioService.searchNumbers(params);
    
    // Filter out already purchased numbers
    const phoneNumbers = availableNumbers.map(n => n.phoneNumber);
    const existingNumbers = await this.prisma.number.findMany({
      where: { phoneNumber: { in: phoneNumbers } },
      select: { phoneNumber: true }
    });
    
    const existingSet = new Set(existingNumbers.map(n => n.phoneNumber));
    const filteredNumbers = availableNumbers.filter(
      n => !existingSet.has(n.phoneNumber)
    );

    return {
      numbers: filteredNumbers,
      total: filteredNumbers.length,
      searchParams: params
    };
  }

  async purchaseNumbers(userId: string, request: PurchaseRequest): Promise<PurchaseResult> {
    const { phoneNumbers, billingInfo } = request;
    
    // Create order
    const order = await this.prisma.order.create({
      data: {
        orderNumber: this.generateOrderNumber(),
        userId,
        status: 'PROCESSING',
        totalAmount: this.calculateTotal(phoneNumbers),
        currency: 'USD'
      }
    });

    const results: PurchaseResult[] = [];

    for (const numberRequest of phoneNumbers) {
      try {
        // Purchase via Twilio
        const purchasedNumber = await this.twilioService.purchaseNumber(
          numberRequest.phoneNumber,
          numberRequest.config
        );

        // Save to database
        const dbNumber = await this.prisma.number.create({
          data: {
            phoneNumber: purchasedNumber.phoneNumber,
            twilioSid: purchasedNumber.sid,
            userId,
            orderId: order.id,
            countryCode: purchasedNumber.countryCode,
            numberType: this.determineNumberType(purchasedNumber),
            monthlyPrice: purchasedNumber.price.monthly,
            setupPrice: purchasedNumber.price.setup,
            capabilities: purchasedNumber.capabilities,
            status: 'ACTIVE'
          }
        });

        results.push({
          phoneNumber: dbNumber.phoneNumber,
          status: 'SUCCESS',
          numberId: dbNumber.id
        });

      } catch (error) {
        results.push({
          phoneNumber: numberRequest.phoneNumber,
          status: 'FAILED',
          error: error.message
        });
      }
    }

    // Update order status
    const hasFailures = results.some(r => r.status === 'FAILED');
    await this.prisma.order.update({
      where: { id: order.id },
      data: {
        status: hasFailures ? 'PARTIAL' : 'COMPLETED',
        completedAt: new Date()
      }
    });

    return {
      orderId: order.id,
      results,
      totalPurchased: results.filter(r => r.status === 'SUCCESS').length
    };
  }

  async getUserNumbers(userId: string, filters?: NumberFilters): Promise<UserNumber[]> {
    const where = {
      userId,
      ...(filters?.status && { status: filters.status }),
      ...(filters?.numberType && { numberType: filters.numberType }),
      ...(filters?.search && {
        OR: [
          { phoneNumber: { contains: filters.search } },
          { friendlyName: { contains: filters.search, mode: 'insensitive' } }
        ]
      })
    };

    return this.prisma.number.findMany({
      where,
      include: {
        order: true,
        _count: {
          select: { callLogs: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });
  }

  async configureNumber(numberId: string, userId: string, config: NumberConfiguration): Promise<void> {
    const number = await this.prisma.number.findFirst({
      where: { id: numberId, userId }
    });

    if (!number) {
      throw new NotFoundError('Number not found');
    }

    // Update Twilio configuration
    await this.twilioService.configureNumber(number.twilioSid, config);

    // Update database
    await this.prisma.number.update({
      where: { id: numberId },
      data: {
        voiceUrl: config.voiceUrl,
        voiceMethod: config.voiceMethod,
        voiceFallbackUrl: config.voiceFallbackUrl,
        statusCallback: config.statusCallback,
        friendlyName: config.friendlyName
      }
    });
  }

  async releaseNumber(numberId: string, userId: string): Promise<void> {
    const number = await this.prisma.number.findFirst({
      where: { id: numberId, userId }
    });

    if (!number) {
      throw new NotFoundError('Number not found');
    }

    // Release from Twilio
    await this.twilioService.releaseNumber(number.twilioSid);

    // Update database status
    await this.prisma.number.update({
      where: { id: numberId },
      data: { status: 'RELEASED' }
    });
  }
}
```

## 7. Authentication & Authorization

### 7.1 JWT Implementation

```typescript
// src/services/auth.service.ts
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';

export class AuthService {
  constructor(private prisma: PrismaClient) {}

  async register(userData: RegisterRequest): Promise<AuthResponse> {
    // Check if user exists
    const existingUser = await this.prisma.user.findUnique({
      where: { email: userData.email }
    });

    if (existingUser) {
      throw new ConflictError('User already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(userData.password, 12);

    // Create user
    const user = await this.prisma.user.create({
      data: {
        ...userData,
        password: hashedPassword,
        emailVerificationToken: this.generateVerificationToken()
      }
    });

    // Generate tokens
    const tokens = await this.generateTokens(user.id);

    // Send verification email
    await this.sendVerificationEmail(user.email, user.emailVerificationToken);

    return {
      user: this.sanitizeUser(user),
      tokens
    };
  }

  async login(credentials: LoginRequest): Promise<AuthResponse> {
    const user = await this.prisma.user.findUnique({
      where: { email: credentials.email }
    });

    if (!user || !await bcrypt.compare(credentials.password, user.password)) {
      throw new UnauthorizedError('Invalid credentials');
    }

    if (!user.isActive) {
      throw new ForbiddenError('Account is deactivated');
    }

    const tokens = await this.generateTokens(user.id);

    return {
      user: this.sanitizeUser(user),
      tokens
    };
  }

  async refreshToken(refreshToken: string): Promise<TokenPair> {
    const session = await this.prisma.session.findUnique({
      where: { refreshToken },
      include: { user: true }
    });

    if (!session || session.isRevoked || session.expiresAt < new Date()) {
      throw new UnauthorizedError('Invalid refresh token');
    }

    // Generate new tokens
    const tokens = await this.generateTokens(session.userId);

    // Revoke old session
    await this.prisma.session.update({
      where: { id: session.id },
      data: { isRevoked: true }
    });

    return tokens;
  }

  private async generateTokens(userId: string): Promise<TokenPair> {
    const accessToken = jwt.sign(
      { userId, type: 'access' },
      process.env.JWT_SECRET!,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { userId, type: 'refresh' },
      process.env.JWT_REFRESH_SECRET!,
      { expiresIn: '7d' }
    );

    // Store refresh token
    await this.prisma.session.create({
      data: {
        userId,
        refreshToken,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      }
    });

    return { accessToken, refreshToken };
  }
}
```

### 7.2 Auth Middleware

```typescript
// src/middlewares/auth.middleware.ts
import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

export const authenticateToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
    
    if (decoded.type !== 'access') {
      return res.status(401).json({ error: 'Invalid token type' });
    }

    // Get user from database
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: { id: true, email: true, role: true, isActive: true }
    });

    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

export const requireRole = (roles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient privileges' });
    }
    next();
  };
};
```

## 8. Error Handling & Validation

### 8.1 Global Error Handler

```typescript
// src/middlewares/error.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { logger } from '../utils/logger';

export class AppError extends Error {
  constructor(
    public message: string,
    public statusCode: number,
    public code?: string
  ) {
    super(message);
    this.name = this.constructor.name;
  }
}

export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  logger.error('Error occurred:', {
    message: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });

  // Zod validation errors
  if (error instanceof ZodError) {
    return res.status(400).json({
      error: 'Validation error',
      details: error.errors.map(e => ({
        field: e.path.join('.'),
        message: e.message
      }))
    });
  }

  // Application errors
  if (error instanceof AppError) {
    return res.status(error.statusCode).json({
      error: error.message,
      code: error.code
    });
  }

  // Twilio errors
  if (error.name === 'TwilioError') {
    return res.status(400).json({
      error: 'Telephony service error',
      message: error.message
    });
  }

  // Database errors
  if (error.name === 'PrismaClientKnownRequestError') {
    return res.status(400).json({
      error: 'Database error',
      message: 'Invalid request parameters'
    });
  }

  // Default server error
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
};
```

### 8.2 Validation Schemas

```typescript
// src/schemas/numbers.schemas.ts
import { z } from 'zod';

export const numberSearchSchema = z.object({
  countryCode: z.string().length(2),
  areaCode: z.string().optional(),
  contains: z.string().optional(),
  nearLatLong: z.string().optional(),
  distance: z.number().min(1).max(500).optional(),
  numberType: z.enum(['local', 'tollFree', 'mobile']).optional(),
  limit: z.number().min(1).max(100).default(20)
});

export const purchaseNumberSchema = z.object({
  phoneNumbers: z.array(z.object({
    phoneNumber: z.string().regex(/^\+[1-9]\d{1,14}$/),
    friendlyName: z.string().optional(),
    config: z.object({
      voiceUrl: z.string().url().optional(),
      voiceMethod: z.enum(['GET', 'POST']).default('POST'),
      statusCallback: z.string().url().optional()
    }).optional()
  })).min(1).max(10),
  billingInfo: z.object({
    paymentMethodId: z.string().optional()
  }).optional()
});

export const configureNumberSchema = z.object({
  friendlyName: z.string().max(100).optional(),
  voiceUrl: z.string().url().optional(),
  voiceMethod: z.enum(['GET', 'POST']).optional(),
  voiceFallbackUrl: z.string().url().optional(),
  statusCallback: z.string().url().optional()
});
```

## 9. Testing Strategy

### 9.1 Test Configuration

```typescript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/types/**/*'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html']
};
```

### 9.2 Test Structure

```typescript
// tests/integration/numbers.test.ts
import request from 'supertest';
import { app } from '../../src/app';
import { prisma } from '../../src/utils/database';

describe('Numbers API', () => {
  let authToken: string;
  let userId: string;

  beforeAll(async () => {
    // Setup test user and get auth token
    const response = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'test@example.com',
        password: 'Test123!',
        firstName: 'Test',
        lastName: 'User'
      });
    
    authToken = response.body.tokens.accessToken;
    userId = response.body.user.id;
  });

  afterAll(async () => {
    // Cleanup
    await prisma.user.delete({ where: { id: userId } });
    await prisma.$disconnect();
  });

  describe('GET /api/v1/numbers/search', () => {
    it('should search available numbers', async () => {
      const response = await request(app)
        .get('/api/v1/numbers/search')
        .query({ countryCode: 'US', areaCode: '415' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('numbers');
      expect(response.body.numbers).toBeInstanceOf(Array);
      expect(response.body).toHaveProperty('total');
    });

    it('should validate search parameters', async () => {
      await request(app)
        .get('/api/v1/numbers/search')
        .query({ countryCode: 'INVALID' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(400);
    });
  });

  describe('POST /api/v1/numbers/purchase', () => {
    it('should purchase a number successfully', async () => {
      // Mock Twilio service for testing
      jest.spyOn(twilioService, 'purchaseNumber').mockResolvedValue({
        sid: 'PN123',
        phoneNumber: '+14155551234',
        countryCode: 'US',
        price: { setup: 1.00, monthly: 1.00 },
        capabilities: ['voice']
      });

      const response = await request(app)
        .post('/api/v1/numbers/purchase')
        .send({
          phoneNumbers: [{
            phoneNumber: '+14155551234',
            friendlyName: 'Test Number'
          }]
        })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(201);

      expect(response.body).toHaveProperty('orderId');
      expect(response.body.results[0].status).toBe('SUCCESS');
    });
  });
});
```

## 10. Development Setup & Scripts

### 10.1 Package.json Scripts

```json
{
  "scripts": {
    "dev": "nodemon src/app.ts",
    "build": "tsc",
    "start": "node dist/app.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "db:migrate": "prisma migrate dev",
    "db:generate": "prisma generate",
    "db:seed": "ts-node prisma/seed.ts",
    "db:studio": "prisma studio",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix",
    "docs": "swagger-jsdoc -d docs/swagger.config.js src/routes/*.ts -o docs/api.yaml"
  }
}
```

### 10.2 Environment Configuration

```bash
# .env.example
# Database
DATABASE_URL="postgresql://username:password@localhost:5432/did_buy_db"

# Redis
REDIS_URL="redis://localhost:6379"

# JWT
JWT_SECRET="your-super-secret-jwt-key"
JWT_REFRESH_SECRET="your-super-secret-refresh-key"

# Twilio
TWILIO_ACCOUNT_SID="your-twilio-account-sid"
TWILIO_AUTH_TOKEN="your-twilio-auth-token"
TWILIO_WEBHOOK_SECRET="your-webhook-secret"

# Stripe
STRIPE_SECRET_KEY="your-stripe-secret-key"
STRIPE_WEBHOOK_SECRET="your-stripe-webhook-secret"

# Email
SMTP_HOST="smtp.gmail.com"
SMTP_PORT=587
SMTP_USER="your-email@gmail.com"
SMTP_PASS="your-app-password"

# App
NODE_ENV="development"
PORT=3000
API_BASE_URL="http://localhost:3000"
FRONTEND_URL="http://localhost:3001"

# Logging
LOG_LEVEL="debug"
```

## 11. Deployment & DevOps

### 11.1 Docker Configuration

```dockerfile
# Dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY prisma ./prisma/

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Generate Prisma client
RUN npx prisma generate

# Build application
RUN npm run build

# Expose port
EXPOSE 3000

# Start application
CMD ["npm", "start"]
```

### 11.2 Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://postgres:password@db:5432/did_buy_db
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=did_buy_db
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

### 11.3 CI/CD Pipeline (GitHub Actions)

```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: password
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run Prisma migrations
      run: npx prisma migrate deploy
      env:
        DATABASE_URL: postgresql://postgres:password@localhost:5432/test_db
    
    - name: Run tests
      run: npm run test:coverage
      env:
        DATABASE_URL: postgresql://postgres:password@localhost:5432/test_db
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Deploy to production
      run: |
        # Add deployment script here
        echo "Deploying to production..."
```

## 12. Monitoring & Logging

### 12.1 Logger Configuration

```typescript
// src/utils/logger.ts
import winston from 'winston';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'did-buy-api' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

export { logger };
```

### 12.2 Health Check Endpoint

```typescript
// src/routes/health.routes.ts
import { Router } from 'express';
import { prisma } from '../utils/database';

const router = Router();

router.get('/health', async (req, res) => {
  try {
    // Check database connection
    await prisma.$queryRaw`SELECT 1`;
    
    // Check Twilio connection
    const twilioHealth = await twilioService.checkHealth();
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      services: {
        database: 'up',
        twilio: twilioHealth ? 'up' : 'down',
        redis: 'up' // Add Redis check
      }
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

export { router as healthRoutes };
```

## 13. Development Timeline

### Phase 1: Foundation (Weeks 1-2)
- [ ] Project setup and configuration
- [ ] Database schema design and migrations
- [ ] Basic authentication system
- [ ] Twilio service integration
- [ ] Basic error handling and logging

### Phase 2: Core Features (Weeks 3-4)
- [ ] Number search functionality
- [ ] Number purchase workflow
- [ ] Order management system
- [ ] Basic number configuration
- [ ] Unit and integration tests

### Phase 3: Advanced Features (Weeks 5-6)
- [ ] Call routing configuration
- [ ] Webhook handling for call events
- [ ] Analytics and reporting endpoints
- [ ] Billing system integration
- [ ] Advanced validation and error handling

### Phase 4: Production Ready (Weeks 7-8)
- [ ] Performance optimization
- [ ] Security hardening
- [ ] Comprehensive testing
- [ ] Documentation completion
- [ ] Deployment pipeline setup
- [ ] Monitoring and alerting

## 14. Success Metrics

- **API Response Time**: < 200ms for 95% of requests
- **Test Coverage**: > 80% code coverage
- **Uptime**: 99.9% availability
- **Error Rate**: < 0.1% of requests
- **Number Purchase Success Rate**: > 99%
- **Webhook Processing**: < 5 second processing time

This comprehensive development plan provides a solid foundation for building a production-ready DID buy system with Twilio integration. The modular architecture, comprehensive testing strategy, and well-defined implementation phases ensure a scalable and maintainable solution.
