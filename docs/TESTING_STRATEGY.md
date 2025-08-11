# Testing Strategy - Complete TypeScript Implementation

## 1. Overview

This document provides a comprehensive testing strategy for the DID buy system, including unit tests, integration tests, end-to-end tests, and performance testing with complete TypeScript implementations using Jest, Supertest, and other testing frameworks.

## 2. Testing Architecture

### 2.1 Testing Pyramid Structure

```typescript
// src/types/testing.types.ts
export interface TestConfiguration {
  testEnvironment: 'development' | 'testing' | 'staging' | 'production';
  databaseUrl: string;
  redisUrl: string;
  twilioConfig: {
    accountSid: string;
    authToken: string;
    testCredentials: boolean;
  };
  enableMocking: boolean;
  timeouts: {
    unit: number;
    integration: number;
    e2e: number;
  };
  coverage: {
    threshold: number;
    branches: number;
    functions: number;
    lines: number;
    statements: number;
  };
}

export interface TestContext {
  prisma: PrismaClient;
  redis: Redis;
  app: Express;
  cleanup: () => Promise<void>;
}

export interface MockContext {
  twilioClient: jest.Mocked<Twilio>;
  emailService: jest.Mocked<EmailService>;
  paymentService: jest.Mocked<PaymentService>;
}

export interface TestUser {
  id: string;
  email: string;
  password: string;
  role: UserRole;
  accessToken: string;
  refreshToken: string;
}

export interface TestNumber {
  id: string;
  phoneNumber: string;
  twilioSid: string;
  userId: string;
  status: NumberStatus;
}
```

### 2.2 Test Configuration

```typescript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: [
    '**/__tests__/**/*.test.ts',
    '**/*.test.ts',
    '**/*.spec.ts'
  ],
  transform: {
    '^.+\\.ts$': 'ts-jest'
  },
  setupFilesAfterEnv: [
    '<rootDir>/tests/setup.ts'
  ],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.interface.ts',
    '!src/**/*.type.ts',
    '!src/types/**/*',
    '!src/**/*.config.ts'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html', 'json'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  },
  testTimeout: 30000,
  verbose: true,
  detectOpenHandles: true,
  forceExit: true,
  globals: {
    'ts-jest': {
      tsconfig: 'tsconfig.test.json'
    }
  }
};
```

### 2.3 Test Setup and Utilities

```typescript
// tests/setup.ts
import { PrismaClient } from '@prisma/client';
import { Redis } from 'ioredis';
import { execSync } from 'child_process';

// Global test setup
let prisma: PrismaClient;
let redis: Redis;

beforeAll(async () => {
  // Setup test database
  process.env.DATABASE_URL = process.env.TEST_DATABASE_URL || 'postgresql://test:test@localhost:5432/did_buy_test';
  process.env.REDIS_URL = process.env.TEST_REDIS_URL || 'redis://localhost:6379/1';
  
  // Reset database
  execSync('npx prisma migrate reset --force', { stdio: 'inherit' });
  execSync('npx prisma migrate deploy', { stdio: 'inherit' });
  
  // Initialize connections
  prisma = new PrismaClient();
  redis = new Redis(process.env.REDIS_URL);
  
  // Seed test data
  await seedTestData();
});

afterAll(async () => {
  // Cleanup
  await prisma.$disconnect();
  await redis.disconnect();
});

beforeEach(async () => {
  // Clear Redis between tests
  await redis.flushdb();
});

afterEach(async () => {
  // Clean up test data created during tests
  await cleanupTestData();
});

async function seedTestData() {
  // Create test users
  await prisma.user.createMany({
    data: [
      {
        id: 'test-user-1',
        email: 'test@example.com',
        password: '$2b$12$hashed_password',
        firstName: 'Test',
        lastName: 'User',
        role: 'USER',
        emailVerified: true,
        isActive: true
      },
      {
        id: 'test-admin-1',
        email: 'admin@example.com',
        password: '$2b$12$hashed_password',
        firstName: 'Admin',
        lastName: 'User',
        role: 'ADMIN',
        emailVerified: true,
        isActive: true
      }
    ]
  });
}

async function cleanupTestData() {
  // Clean up in reverse order of dependencies
  await prisma.callLog.deleteMany({});
  await prisma.number.deleteMany({});
  await prisma.orderItem.deleteMany({});
  await prisma.order.deleteMany({});
  await prisma.session.deleteMany({});
  await prisma.apiKey.deleteMany({});
  // Don't delete test users as they're needed for multiple tests
}

// Export for use in tests
export { prisma, redis };
```

### 2.4 Test Utilities and Helpers

```typescript
// tests/utils/test-helpers.ts
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { Express } from 'express';
import { PrismaClient } from '@prisma/client';

export class TestHelpers {
  constructor(
    private app: Express,
    private prisma: PrismaClient
  ) {}

  async createTestUser(overrides: Partial<any> = {}): Promise<TestUser> {
    const userData = {
      email: `test-${Date.now()}@example.com`,
      password: 'Test123!',
      firstName: 'Test',
      lastName: 'User',
      role: 'USER',
      ...overrides
    };

    const response = await request(this.app)
      .post('/api/v1/auth/register')
      .send(userData)
      .expect(201);

    return {
      id: response.body.data.user.id,
      email: userData.email,
      password: userData.password,
      role: userData.role,
      accessToken: response.body.data.tokens.accessToken,
      refreshToken: response.body.data.tokens.refreshToken
    };
  }

  async loginUser(email: string, password: string): Promise<TestUser> {
    const response = await request(this.app)
      .post('/api/v1/auth/login')
      .send({ email, password })
      .expect(200);

    return {
      id: response.body.data.user.id,
      email,
      password,
      role: response.body.data.user.role,
      accessToken: response.body.data.tokens.accessToken,
      refreshToken: response.body.data.tokens.refreshToken
    };
  }

  async createTestNumber(userId: string, overrides: Partial<any> = {}): Promise<TestNumber> {
    const numberData = {
      phoneNumber: `+1415555${Math.floor(Math.random() * 9000) + 1000}`,
      twilioSid: `PN${Math.random().toString(36).substr(2, 9)}`,
      userId,
      countryCode: 'US',
      numberType: 'LOCAL',
      capabilities: ['voice', 'sms'],
      monthlyPrice: 1.00,
      setupPrice: 1.00,
      status: 'ACTIVE',
      ...overrides
    };

    const number = await this.prisma.number.create({
      data: numberData
    });

    return {
      id: number.id,
      phoneNumber: number.phoneNumber,
      twilioSid: number.twilioSid,
      userId: number.userId,
      status: number.status
    };
  }

  async createTestOrder(userId: string, overrides: Partial<any> = {}): Promise<any> {
    const orderData = {
      orderNumber: `ORDER-${Date.now()}`,
      userId,
      status: 'COMPLETED',
      subtotalAmount: 10.00,
      totalAmount: 10.80,
      currency: 'USD',
      ...overrides
    };

    return this.prisma.order.create({
      data: orderData
    });
  }

  generateAuthHeader(token: string): Record<string, string> {
    return {
      'Authorization': `Bearer ${token}`
    };
  }

  generateTestJWT(userId: string, expiresIn: string = '1h'): string {
    return jwt.sign(
      {
        userId,
        type: 'access',
        permissions: ['read:own_numbers', 'write:own_numbers']
      },
      process.env.JWT_SECRET || 'test-secret',
      { expiresIn }
    );
  }

  async waitFor(condition: () => Promise<boolean>, timeout: number = 5000): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      if (await condition()) {
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error('Condition not met within timeout');
  }

  mockTwilioResponse(method: string, response: any): jest.Mock {
    return jest.fn().mockResolvedValue(response);
  }

  expectValidationError(response: any, field: string, code?: string): void {
    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(response.body.error.type).toBe('VALIDATION_ERROR');
    
    const fieldError = response.body.error.details.find(
      (detail: any) => detail.field === field
    );
    expect(fieldError).toBeDefined();
    
    if (code) {
      expect(fieldError.code).toBe(code);
    }
  }

  expectAuthError(response: any, expectedCode: number = 401): void {
    expect(response.status).toBe(expectedCode);
    expect(response.body.success).toBe(false);
    expect(['AUTHENTICATION_ERROR', 'AUTHORIZATION_ERROR']).toContain(
      response.body.error.type
    );
  }
}
```

## 3. Unit Testing

### 3.1 Service Layer Unit Tests

```typescript
// tests/unit/services/auth.service.test.ts
import { AuthService } from '../../../src/services/auth.service';
import { PrismaClient } from '@prisma/client';
import { Redis } from 'ioredis';
import { Logger } from 'winston';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// Mock dependencies
jest.mock('bcrypt');
jest.mock('jsonwebtoken');

const mockPrisma = {
  user: {
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  },
  session: {
    create: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
    updateMany: jest.fn(),
  },
  billingAccount: {
    create: jest.fn(),
  },
  auditLog: {
    create: jest.fn(),
  },
} as unknown as jest.Mocked<PrismaClient>;

const mockRedis = {
  setex: jest.fn(),
  get: jest.fn(),
  del: jest.fn(),
  exists: jest.fn(),
} as unknown as jest.Mocked<Redis>;

const mockLogger = {
  info: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
  warn: jest.fn(),
} as unknown as jest.Mocked<Logger>;

const mockEmailService = {
  sendVerificationEmail: jest.fn(),
  sendPasswordResetEmail: jest.fn(),
} as any;

const mockConfig = {
  jwt: {
    secret: 'test-secret',
    refreshSecret: 'test-refresh-secret',
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
  },
  password: {
    saltRounds: 12,
    minLength: 8,
    requireSpecialChar: true,
  },
  session: {
    maxActiveSessions: 5,
    extendOnActivity: true,
  },
  verification: {
    emailTokenExpiry: 3600000,
    passwordResetExpiry: 3600000,
  },
};

describe('AuthService', () => {
  let authService: AuthService;

  beforeEach(() => {
    jest.clearAllMocks();
    authService = new AuthService({
      prisma: mockPrisma,
      redis: mockRedis,
      logger: mockLogger,
      emailService: mockEmailService,
      config: mockConfig,
    });
  });

  describe('register', () => {
    const validRegistrationData = {
      email: 'test@example.com',
      password: 'Test123!',
      firstName: 'Test',
      lastName: 'User',
      acceptTerms: true,
    };

    it('should successfully register a new user', async () => {
      // Arrange
      mockPrisma.user.findUnique.mockResolvedValue(null);
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed_password');
      (jwt.sign as jest.Mock)
        .mockReturnValueOnce('access_token')
        .mockReturnValueOnce('refresh_token');

      const createdUser = {
        id: 'user_123',
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        emailVerified: false,
        role: 'USER',
      };

      const createdSession = {
        id: 'session_123',
        expiresAt: new Date(),
      };

      mockPrisma.user.create.mockResolvedValue(createdUser as any);
      mockPrisma.session.create.mockResolvedValue(createdSession as any);
      mockEmailService.sendVerificationEmail.mockResolvedValue(undefined);

      // Act
      const result = await authService.register(validRegistrationData);

      // Assert
      expect(result.success).toBe(true);
      expect(result.data.user.id).toBe('user_123');
      expect(result.data.tokens.accessToken).toBe('access_token');
      expect(result.data.tokens.refreshToken).toBe('refresh_token');

      expect(mockPrisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'test@example.com' }
      });
      expect(bcrypt.hash).toHaveBeenCalledWith('Test123!', 12);
      expect(mockPrisma.user.create).toHaveBeenCalled();
      expect(mockEmailService.sendVerificationEmail).toHaveBeenCalled();
    });

    it('should throw error if user already exists', async () => {
      // Arrange
      mockPrisma.user.findUnique.mockResolvedValue({ id: 'existing_user' } as any);

      // Act & Assert
      await expect(authService.register(validRegistrationData))
        .rejects
        .toThrow('User already exists');

      expect(mockPrisma.user.create).not.toHaveBeenCalled();
    });

    it('should validate email format', async () => {
      // Arrange
      const invalidData = {
        ...validRegistrationData,
        email: 'invalid-email'
      };

      // Act & Assert
      await expect(authService.register(invalidData))
        .rejects
        .toThrow('Invalid email address');
    });

    it('should validate password strength', async () => {
      // Arrange
      const weakPasswordData = {
        ...validRegistrationData,
        password: 'weak'
      };

      // Act & Assert
      await expect(authService.register(weakPasswordData))
        .rejects
        .toThrow('Password must be at least 8 characters');
    });

    it('should validate required fields', async () => {
      // Arrange
      const incompleteData = {
        ...validRegistrationData,
        firstName: ''
      };

      // Act & Assert
      await expect(authService.register(incompleteData))
        .rejects
        .toThrow('First name is required');
    });
  });

  describe('login', () => {
    const validLoginData = {
      email: 'test@example.com',
      password: 'Test123!',
      deviceInfo: {
        platform: 'web',
        browser: 'chrome',
        version: '91.0'
      }
    };

    it('should successfully login with valid credentials', async () => {
      // Arrange
      const user = {
        id: 'user_123',
        email: 'test@example.com',
        password: 'hashed_password',
        isActive: true,
        isSuspended: false,
        role: 'USER',
        billingAccount: { id: 'billing_123' }
      };

      mockPrisma.user.findUnique.mockResolvedValue(user as any);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);
      (jwt.sign as jest.Mock)
        .mockReturnValueOnce('access_token')
        .mockReturnValueOnce('refresh_token');

      const session = { id: 'session_123', expiresAt: new Date() };
      mockPrisma.session.create.mockResolvedValue(session as any);
      mockPrisma.user.update.mockResolvedValue(user as any);

      // Act
      const result = await authService.login(validLoginData);

      // Assert
      expect(result.success).toBe(true);
      expect(result.data.user.id).toBe('user_123');
      expect(result.data.tokens.accessToken).toBe('access_token');

      expect(bcrypt.compare).toHaveBeenCalledWith('Test123!', 'hashed_password');
      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { id: 'user_123' },
        data: { lastLoginAt: expect.any(Date) }
      });
    });

    it('should reject invalid credentials', async () => {
      // Arrange
      mockPrisma.user.findUnique.mockResolvedValue(null);

      // Act & Assert
      await expect(authService.login(validLoginData))
        .rejects
        .toThrow('Invalid credentials');
    });

    it('should reject inactive user', async () => {
      // Arrange
      const inactiveUser = {
        id: 'user_123',
        email: 'test@example.com',
        password: 'hashed_password',
        isActive: false,
        isSuspended: false
      };

      mockPrisma.user.findUnique.mockResolvedValue(inactiveUser as any);

      // Act & Assert
      await expect(authService.login(validLoginData))
        .rejects
        .toThrow('Account is deactivated');
    });

    it('should reject suspended user', async () => {
      // Arrange
      const suspendedUser = {
        id: 'user_123',
        email: 'test@example.com',
        password: 'hashed_password',
        isActive: true,
        isSuspended: true,
        suspensionReason: 'Policy violation'
      };

      mockPrisma.user.findUnique.mockResolvedValue(suspendedUser as any);

      // Act & Assert
      await expect(authService.login(validLoginData))
        .rejects
        .toThrow('Account is suspended');
    });
  });

  describe('refreshToken', () => {
    it('should successfully refresh valid token', async () => {
      // Arrange
      const refreshToken = 'valid_refresh_token';
      const session = {
        id: 'session_123',
        userId: 'user_123',
        refreshToken,
        isRevoked: false,
        expiresAt: new Date(Date.now() + 3600000),
        user: {
          id: 'user_123',
          isActive: true,
          isSuspended: false
        }
      };

      mockPrisma.session.findUnique.mockResolvedValue(session as any);
      (jwt.sign as jest.Mock)
        .mockReturnValueOnce('new_access_token')
        .mockReturnValueOnce('new_refresh_token');

      mockPrisma.session.update.mockResolvedValue(session as any);

      // Act
      const result = await authService.refreshToken(refreshToken);

      // Assert
      expect(result.success).toBe(true);
      expect(result.data.accessToken).toBe('new_access_token');
      expect(result.data.refreshToken).toBe('new_refresh_token');

      expect(mockPrisma.session.update).toHaveBeenCalledWith({
        where: { id: 'session_123' },
        data: {
          refreshToken: 'new_refresh_token',
          expiresAt: expect.any(Date)
        }
      });
    });

    it('should reject expired refresh token', async () => {
      // Arrange
      const refreshToken = 'expired_refresh_token';
      const expiredSession = {
        id: 'session_123',
        userId: 'user_123',
        refreshToken,
        isRevoked: false,
        expiresAt: new Date(Date.now() - 3600000), // Expired
        user: { isActive: true, isSuspended: false }
      };

      mockPrisma.session.findUnique.mockResolvedValue(expiredSession as any);

      // Act & Assert
      await expect(authService.refreshToken(refreshToken))
        .rejects
        .toThrow('Invalid refresh token');
    });

    it('should reject revoked refresh token', async () => {
      // Arrange
      const refreshToken = 'revoked_refresh_token';
      const revokedSession = {
        id: 'session_123',
        userId: 'user_123',
        refreshToken,
        isRevoked: true,
        expiresAt: new Date(Date.now() + 3600000),
        user: { isActive: true, isSuspended: false }
      };

      mockPrisma.session.findUnique.mockResolvedValue(revokedSession as any);

      // Act & Assert
      await expect(authService.refreshToken(refreshToken))
        .rejects
        .toThrow('Invalid refresh token');
    });
  });
});
```

### 3.2 Twilio Service Unit Tests

```typescript
// tests/unit/services/twilio.service.test.ts
import { TwilioService } from '../../../src/services/twilio.service';
import { Twilio } from 'twilio';

// Mock Twilio
jest.mock('twilio');

const mockTwilioClient = {
  availablePhoneNumbers: jest.fn(),
  incomingPhoneNumbers: {
    create: jest.fn(),
    list: jest.fn(),
  },
  calls: jest.fn(),
  messages: {
    create: jest.fn(),
  },
  api: {
    accounts: jest.fn(),
  },
} as any;

const mockLogger = {
  info: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
  warn: jest.fn(),
} as any;

const mockRedis = {
  get: jest.fn(),
  setex: jest.fn(),
} as any;

const mockConfig = {
  accountSid: 'test_account_sid',
  authToken: 'test_auth_token',
  webhookSecret: 'test_webhook_secret',
  baseUrl: 'https://api.twilio.com',
  timeout: 30000,
  retryAttempts: 3,
  cacheTimeout: 300,
};

describe('TwilioService', () => {
  let twilioService: TwilioService;

  beforeEach(() => {
    jest.clearAllMocks();
    (Twilio as jest.Mock).mockReturnValue(mockTwilioClient);
    
    twilioService = new TwilioService({
      logger: mockLogger,
      redis: mockRedis,
      config: mockConfig,
    });
  });

  describe('searchNumbers', () => {
    const searchParams = {
      countryCode: 'US',
      areaCode: '415',
      limit: 20,
    };

    it('should successfully search for available numbers', async () => {
      // Arrange
      const mockAvailableNumbers = [
        {
          phoneNumber: '+14155551234',
          friendlyName: 'San Francisco Number',
          locality: 'San Francisco',
          region: 'CA',
          isoCountry: 'US',
          capabilities: { voice: true, sms: true },
        },
        {
          phoneNumber: '+14155555678',
          friendlyName: 'Another SF Number',
          locality: 'San Francisco',
          region: 'CA',
          isoCountry: 'US',
          capabilities: { voice: true, sms: true },
        },
      ];

      const mockLocalNumbers = {
        list: jest.fn().mockResolvedValue(mockAvailableNumbers),
      };

      mockTwilioClient.availablePhoneNumbers.mockReturnValue({
        local: mockLocalNumbers,
      });

      mockRedis.get.mockResolvedValue(null); // No cache

      // Act
      const result = await twilioService.searchNumbers(searchParams);

      // Assert
      expect(result.success).toBe(true);
      expect(result.data).toHaveLength(2);
      expect(result.data[0].phoneNumber).toBe('+14155551234');
      expect(result.data[0].locality).toBe('San Francisco');

      expect(mockTwilioClient.availablePhoneNumbers).toHaveBeenCalledWith('US');
      expect(mockLocalNumbers.list).toHaveBeenCalledWith({
        areaCode: '415',
        contains: undefined,
        nearLatLong: undefined,
        distance: undefined,
        limit: 20,
      });
    });

    it('should return cached results when available', async () => {
      // Arrange
      const cachedResults = [
        {
          phoneNumber: '+14155551234',
          friendlyName: 'Cached Number',
          locality: 'San Francisco',
          region: 'CA',
          countryCode: 'US',
          capabilities: { voice: true, sms: true },
        },
      ];

      mockRedis.get.mockResolvedValue(JSON.stringify(cachedResults));

      // Act
      const result = await twilioService.searchNumbers(searchParams);

      // Assert
      expect(result.success).toBe(true);
      expect(result.data).toEqual(cachedResults);
      expect(mockTwilioClient.availablePhoneNumbers).not.toHaveBeenCalled();
    });

    it('should handle Twilio API errors', async () => {
      // Arrange
      const mockError = new Error('Twilio API Error');
      mockError.code = 20003;

      const mockLocalNumbers = {
        list: jest.fn().mockRejectedValue(mockError),
      };

      mockTwilioClient.availablePhoneNumbers.mockReturnValue({
        local: mockLocalNumbers,
      });

      mockRedis.get.mockResolvedValue(null);

      // Act & Assert
      await expect(twilioService.searchNumbers(searchParams))
        .rejects
        .toThrow('Number search failed');

      expect(mockLogger.error).toHaveBeenCalledWith(
        'Number search failed',
        expect.objectContaining({
          params: searchParams,
          error: mockError,
        })
      );
    });

    it('should cache successful results', async () => {
      // Arrange
      const mockAvailableNumbers = [
        {
          phoneNumber: '+14155551234',
          friendlyName: 'Test Number',
          locality: 'San Francisco',
          region: 'CA',
          isoCountry: 'US',
          capabilities: { voice: true, sms: true },
        },
      ];

      const mockLocalNumbers = {
        list: jest.fn().mockResolvedValue(mockAvailableNumbers),
      };

      mockTwilioClient.availablePhoneNumbers.mockReturnValue({
        local: mockLocalNumbers,
      });

      mockRedis.get.mockResolvedValue(null);

      // Act
      await twilioService.searchNumbers(searchParams);

      // Assert
      expect(mockRedis.setex).toHaveBeenCalledWith(
        expect.stringContaining('search:'),
        300, // cache timeout
        expect.any(String)
      );
    });
  });

  describe('purchaseNumber', () => {
    const purchaseRequest = {
      phoneNumber: '+14155551234',
      friendlyName: 'Test Number',
      voiceUrl: 'https://example.com/voice',
      voiceMethod: 'POST' as const,
    };

    it('should successfully purchase a number', async () => {
      // Arrange
      const mockPurchasedNumber = {
        sid: 'PN123456789',
        phoneNumber: '+14155551234',
        friendlyName: 'Test Number',
        origin: 'US',
        capabilities: { voice: true, sms: true },
      };

      mockTwilioClient.incomingPhoneNumbers.create.mockResolvedValue(mockPurchasedNumber);

      // Act
      const result = await twilioService.purchaseNumber(purchaseRequest);

      // Assert
      expect(result.success).toBe(true);
      expect(result.data.sid).toBe('PN123456789');
      expect(result.data.phoneNumber).toBe('+14155551234');

      expect(mockTwilioClient.incomingPhoneNumbers.create).toHaveBeenCalledWith({
        phoneNumber: '+14155551234',
        friendlyName: 'Test Number',
        voiceUrl: 'https://example.com/voice',
        voiceMethod: 'POST',
        statusCallback: undefined,
      });
    });

    it('should handle number not available error', async () => {
      // Arrange
      const mockError = new Error('Phone number not available');
      mockError.code = 21422;

      mockTwilioClient.incomingPhoneNumbers.create.mockRejectedValue(mockError);

      // Act & Assert
      await expect(twilioService.purchaseNumber(purchaseRequest))
        .rejects
        .toThrow('Phone number is not available');
    });

    it('should handle insufficient balance error', async () => {
      // Arrange
      const mockError = new Error('Insufficient balance');
      mockError.code = 21450;

      mockTwilioClient.incomingPhoneNumbers.create.mockRejectedValue(mockError);

      // Act & Assert
      await expect(twilioService.purchaseNumber(purchaseRequest))
        .rejects
        .toThrow('Insufficient account balance');
    });
  });

  describe('configureNumber', () => {
    const numberSid = 'PN123456789';
    const configuration = {
      voiceUrl: 'https://example.com/new-voice',
      voiceMethod: 'POST' as const,
      statusCallback: 'https://example.com/status',
    };

    it('should successfully configure a number', async () => {
      // Arrange
      const mockUpdate = jest.fn().mockResolvedValue({});
      mockTwilioClient.incomingPhoneNumbers.mockReturnValue({
        update: mockUpdate,
      });

      // Act
      const result = await twilioService.configureNumber(numberSid, configuration);

      // Assert
      expect(result.success).toBe(true);
      expect(mockTwilioClient.incomingPhoneNumbers).toHaveBeenCalledWith(numberSid);
      expect(mockUpdate).toHaveBeenCalledWith(configuration);
    });

    it('should handle number not found error', async () => {
      // Arrange
      const mockError = new Error('Number not found');
      mockError.code = 20404;

      const mockUpdate = jest.fn().mockRejectedValue(mockError);
      mockTwilioClient.incomingPhoneNumbers.mockReturnValue({
        update: mockUpdate,
      });

      // Act & Assert
      await expect(twilioService.configureNumber(numberSid, configuration))
        .rejects
        .toThrow('Phone number not found');
    });
  });

  describe('releaseNumber', () => {
    const numberSid = 'PN123456789';

    it('should successfully release a number', async () => {
      // Arrange
      const mockRemove = jest.fn().mockResolvedValue({});
      mockTwilioClient.incomingPhoneNumbers.mockReturnValue({
        remove: mockRemove,
      });

      // Act
      const result = await twilioService.releaseNumber(numberSid);

      // Assert
      expect(result.success).toBe(true);
      expect(mockTwilioClient.incomingPhoneNumbers).toHaveBeenCalledWith(numberSid);
      expect(mockRemove).toHaveBeenCalled();
    });

    it('should handle number not found error', async () => {
      // Arrange
      const mockError = new Error('Number not found');
      mockError.code = 20404;

      const mockRemove = jest.fn().mockRejectedValue(mockError);
      mockTwilioClient.incomingPhoneNumbers.mockReturnValue({
        remove: mockRemove,
      });

      // Act & Assert
      await expect(twilioService.releaseNumber(numberSid))
        .rejects
        .toThrow('Phone number not found');
    });
  });
});
```

## 4. Integration Testing

### 4.1 API Integration Tests

```typescript
// tests/integration/api/auth.test.ts
import request from 'supertest';
import { app } from '../../../src/app';
import { prisma } from '../../setup';
import { TestHelpers } from '../../utils/test-helpers';

describe('Auth API Integration Tests', () => {
  let testHelpers: TestHelpers;

  beforeAll(() => {
    testHelpers = new TestHelpers(app, prisma);
  });

  describe('POST /api/v1/auth/register', () => {
    const validRegistrationData = {
      email: 'newuser@example.com',
      password: 'Test123!',
      firstName: 'New',
      lastName: 'User',
      company: 'Test Company',
      acceptTerms: true,
    };

    it('should register a new user successfully', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(validRegistrationData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user).toMatchObject({
        email: 'newuser@example.com',
        firstName: 'New',
        lastName: 'User',
        role: 'USER',
        emailVerified: false,
      });
      expect(response.body.data.tokens).toMatchObject({
        accessToken: expect.any(String),
        refreshToken: expect.any(String),
        expiresIn: expect.any(Number),
      });

      // Verify user was created in database
      const user = await prisma.user.findUnique({
        where: { email: 'newuser@example.com' },
      });
      expect(user).toBeTruthy();
      expect(user.password).not.toBe('Test123!'); // Should be hashed
    });

    it('should create billing account for new user', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          ...validRegistrationData,
          email: 'billing@example.com',
        })
        .expect(201);

      const billingAccount = await prisma.billingAccount.findUnique({
        where: { userId: response.body.data.user.id },
      });
      expect(billingAccount).toBeTruthy();
      expect(billingAccount.currency).toBe('USD');
    });

    it('should reject duplicate email registration', async () => {
      // First registration
      await request(app)
        .post('/api/v1/auth/register')
        .send(validRegistrationData)
        .expect(201);

      // Second registration with same email
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(validRegistrationData)
        .expect(409);

      testHelpers.expectValidationError(response, 'email', 'EMAIL_EXISTS');
    });

    it('should validate email format', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          ...validRegistrationData,
          email: 'invalid-email',
        })
        .expect(400);

      testHelpers.expectValidationError(response, 'email');
    });

    it('should validate password requirements', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          ...validRegistrationData,
          password: 'weak',
        })
        .expect(400);

      testHelpers.expectValidationError(response, 'password');
    });

    it('should require terms acceptance', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          ...validRegistrationData,
          acceptTerms: false,
        })
        .expect(400);

      testHelpers.expectValidationError(response, 'acceptTerms');
    });
  });

  describe('POST /api/v1/auth/login', () => {
    let testUser: TestUser;

    beforeEach(async () => {
      testUser = await testHelpers.createTestUser({
        email: 'login@example.com',
        password: 'Test123!',
      });
    });

    it('should login with valid credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'login@example.com',
          password: 'Test123!',
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe('login@example.com');
      expect(response.body.data.tokens.accessToken).toBeTruthy();

      // Verify last login was updated
      const user = await prisma.user.findUnique({
        where: { id: testUser.id },
      });
      expect(user.lastLoginAt).toBeTruthy();
    });

    it('should reject invalid email', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'Test123!',
        })
        .expect(401);

      testHelpers.expectAuthError(response);
    });

    it('should reject invalid password', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'login@example.com',
          password: 'WrongPassword',
        })
        .expect(401);

      testHelpers.expectAuthError(response);
    });

    it('should reject login for inactive user', async () => {
      // Deactivate user
      await prisma.user.update({
        where: { id: testUser.id },
        data: { isActive: false },
      });

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'login@example.com',
          password: 'Test123!',
        })
        .expect(403);

      testHelpers.expectAuthError(response, 403);
    });

    it('should reject login for suspended user', async () => {
      // Suspend user
      await prisma.user.update({
        where: { id: testUser.id },
        data: { isSuspended: true, suspensionReason: 'Policy violation' },
      });

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'login@example.com',
          password: 'Test123!',
        })
        .expect(403);

      testHelpers.expectAuthError(response, 403);
    });
  });

  describe('POST /api/v1/auth/refresh', () => {
    let testUser: TestUser;

    beforeEach(async () => {
      testUser = await testHelpers.createTestUser();
    });

    it('should refresh tokens with valid refresh token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({
          refreshToken: testUser.refreshToken,
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.accessToken).toBeTruthy();
      expect(response.body.data.refreshToken).toBeTruthy();
      expect(response.body.data.accessToken).not.toBe(testUser.accessToken);
    });

    it('should reject invalid refresh token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({
          refreshToken: 'invalid_token',
        })
        .expect(401);

      testHelpers.expectAuthError(response);
    });

    it('should reject expired refresh token', async () => {
      // Create expired session
      const expiredSession = await prisma.session.create({
        data: {
          userId: testUser.id,
          refreshToken: 'expired_token',
          expiresAt: new Date(Date.now() - 3600000), // 1 hour ago
        },
      });

      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({
          refreshToken: 'expired_token',
        })
        .expect(401);

      testHelpers.expectAuthError(response);
    });
  });

  describe('POST /api/v1/auth/logout', () => {
    let testUser: TestUser;

    beforeEach(async () => {
      testUser = await testHelpers.createTestUser();
    });

    it('should logout successfully', async () => {
      const response = await request(app)
        .post('/api/v1/auth/logout')
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .send({
          refreshToken: testUser.refreshToken,
        })
        .expect(200);

      expect(response.body.success).toBe(true);

      // Verify session was revoked
      const session = await prisma.session.findUnique({
        where: { refreshToken: testUser.refreshToken },
      });
      expect(session.isRevoked).toBe(true);
    });

    it('should logout from all devices', async () => {
      // Create multiple sessions
      const session2 = await prisma.session.create({
        data: {
          userId: testUser.id,
          refreshToken: 'another_refresh_token',
          expiresAt: new Date(Date.now() + 3600000),
        },
      });

      const response = await request(app)
        .post('/api/v1/auth/logout')
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .send({
          refreshToken: testUser.refreshToken,
          allDevices: true,
        })
        .expect(200);

      // Verify all sessions were revoked
      const sessions = await prisma.session.findMany({
        where: { userId: testUser.id },
      });
      expect(sessions.every(s => s.isRevoked)).toBe(true);
    });
  });
});
```

### 4.2 Number Management Integration Tests

```typescript
// tests/integration/api/numbers.test.ts
import request from 'supertest';
import { app } from '../../../src/app';
import { prisma } from '../../setup';
import { TestHelpers } from '../../utils/test-helpers';

// Mock Twilio service
jest.mock('../../../src/services/twilio.service');

describe('Numbers API Integration Tests', () => {
  let testHelpers: TestHelpers;
  let testUser: TestUser;
  let adminUser: TestUser;

  beforeAll(async () => {
    testHelpers = new TestHelpers(app, prisma);
  });

  beforeEach(async () => {
    testUser = await testHelpers.createTestUser();
    adminUser = await testHelpers.createTestUser({ role: 'ADMIN' });
  });

  describe('GET /api/v1/numbers/search', () => {
    it('should search for available numbers', async () => {
      // Mock Twilio response
      const mockNumbers = [
        {
          phoneNumber: '+14155551234',
          friendlyName: 'San Francisco Number',
          locality: 'San Francisco',
          region: 'CA',
          countryCode: 'US',
          capabilities: { voice: true, sms: true },
          pricing: { monthlyPrice: '1.00', currency: 'USD' },
          restrictions: [],
        },
      ];

      // Mock the Twilio service method
      require('../../../src/services/twilio.service').TwilioService.prototype.searchNumbers = jest
        .fn()
        .mockResolvedValue({ success: true, data: mockNumbers });

      const response = await request(app)
        .get('/api/v1/numbers/search')
        .query({
          countryCode: 'US',
          areaCode: '415',
          limit: 20,
        })
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].phoneNumber).toBe('+14155551234');
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .get('/api/v1/numbers/search')
        .query({ countryCode: 'US' })
        .expect(401);

      testHelpers.expectAuthError(response);
    });

    it('should validate search parameters', async () => {
      const response = await request(app)
        .get('/api/v1/numbers/search')
        .query({
          countryCode: 'INVALID',
        })
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .expect(400);

      testHelpers.expectValidationError(response, 'countryCode');
    });

    it('should filter out already owned numbers', async () => {
      // Create a number that user already owns
      await testHelpers.createTestNumber(testUser.id, {
        phoneNumber: '+14155551234',
      });

      const mockNumbers = [
        {
          phoneNumber: '+14155551234', // This should be filtered out
          friendlyName: 'Owned Number',
          locality: 'San Francisco',
          region: 'CA',
          countryCode: 'US',
          capabilities: { voice: true, sms: true },
        },
        {
          phoneNumber: '+14155555678', // This should be included
          friendlyName: 'Available Number',
          locality: 'San Francisco',
          region: 'CA',
          countryCode: 'US',
          capabilities: { voice: true, sms: true },
        },
      ];

      require('../../../src/services/twilio.service').TwilioService.prototype.searchNumbers = jest
        .fn()
        .mockResolvedValue({ success: true, data: mockNumbers });

      const response = await request(app)
        .get('/api/v1/numbers/search')
        .query({ countryCode: 'US' })
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .expect(200);

      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].phoneNumber).toBe('+14155555678');
    });
  });

  describe('POST /api/v1/numbers/purchase', () => {
    const validPurchaseRequest = {
      numbers: [
        {
          phoneNumber: '+14155551234',
          friendlyName: 'Test Number',
          configuration: {
            voiceUrl: 'https://example.com/voice',
            voiceMethod: 'POST',
          },
        },
      ],
    };

    it('should purchase numbers successfully', async () => {
      // Mock Twilio purchase response
      require('../../../src/services/twilio.service').TwilioService.prototype.purchaseNumber = jest
        .fn()
        .mockResolvedValue({
          success: true,
          data: {
            sid: 'PN123456789',
            phoneNumber: '+14155551234',
            friendlyName: 'Test Number',
            countryCode: 'US',
            capabilities: ['voice', 'sms'],
            price: { setup: 1.0, monthly: 1.0 },
          },
        });

      const response = await request(app)
        .post('/api/v1/numbers/purchase')
        .send(validPurchaseRequest)
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.results[0].status).toBe('SUCCESS');
      expect(response.body.data.results[0].phoneNumber).toBe('+14155551234');

      // Verify number was saved to database
      const savedNumber = await prisma.number.findFirst({
        where: { phoneNumber: '+14155551234' },
      });
      expect(savedNumber).toBeTruthy();
      expect(savedNumber.userId).toBe(testUser.id);
      expect(savedNumber.twilioSid).toBe('PN123456789');
    });

    it('should create order for purchase', async () => {
      require('../../../src/services/twilio.service').TwilioService.prototype.purchaseNumber = jest
        .fn()
        .mockResolvedValue({
          success: true,
          data: {
            sid: 'PN123456789',
            phoneNumber: '+14155551234',
            friendlyName: 'Test Number',
            countryCode: 'US',
            capabilities: ['voice', 'sms'],
            price: { setup: 1.0, monthly: 1.0 },
          },
        });

      const response = await request(app)
        .post('/api/v1/numbers/purchase')
        .send(validPurchaseRequest)
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .expect(201);

      // Verify order was created
      const order = await prisma.order.findUnique({
        where: { id: response.body.data.orderId },
        include: { numbers: true },
      });
      expect(order).toBeTruthy();
      expect(order.userId).toBe(testUser.id);
      expect(order.status).toBe('COMPLETED');
      expect(order.numbers).toHaveLength(1);
    });

    it('should handle Twilio purchase failure', async () => {
      require('../../../src/services/twilio.service').TwilioService.prototype.purchaseNumber = jest
        .fn()
        .mockRejectedValue(new Error('Number not available'));

      const response = await request(app)
        .post('/api/v1/numbers/purchase')
        .send(validPurchaseRequest)
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .expect(201); // Still returns 201 but with failed results

      expect(response.body.data.results[0].status).toBe('FAILED');
      expect(response.body.data.results[0].error).toContain('Number not available');
    });

    it('should validate purchase limits', async () => {
      const tooManyNumbers = {
        numbers: Array.from({ length: 11 }, (_, i) => ({
          phoneNumber: `+141555${i.toString().padStart(4, '0')}`,
          friendlyName: `Number ${i}`,
        })),
      };

      const response = await request(app)
        .post('/api/v1/numbers/purchase')
        .send(tooManyNumbers)
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .expect(400);

      testHelpers.expectValidationError(response, 'numbers');
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .post('/api/v1/numbers/purchase')
        .send(validPurchaseRequest)
        .expect(401);

      testHelpers.expectAuthError(response);
    });
  });

  describe('GET /api/v1/numbers', () => {
    let userNumber: TestNumber;
    let otherUserNumber: TestNumber;

    beforeEach(async () => {
      userNumber = await testHelpers.createTestNumber(testUser.id);
      
      const otherUser = await testHelpers.createTestUser({
        email: 'other@example.com',
      });
      otherUserNumber = await testHelpers.createTestNumber(otherUser.id);
    });

    it('should return user\'s numbers only', async () => {
      const response = await request(app)
        .get('/api/v1/numbers')
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.numbers).toHaveLength(1);
      expect(response.body.data.numbers[0].id).toBe(userNumber.id);
      expect(response.body.data.numbers[0].phoneNumber).toBe(userNumber.phoneNumber);
    });

    it('should support pagination', async () => {
      // Create more numbers
      await Promise.all([
        testHelpers.createTestNumber(testUser.id),
        testHelpers.createTestNumber(testUser.id),
        testHelpers.createTestNumber(testUser.id),
      ]);

      const response = await request(app)
        .get('/api/v1/numbers')
        .query({ page: 1, limit: 2 })
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .expect(200);

      expect(response.body.data.numbers).toHaveLength(2);
      expect(response.body.data.pagination.total).toBe(4);
      expect(response.body.data.pagination.totalPages).toBe(2);
    });

    it('should support filtering by status', async () => {
      // Create a suspended number
      await testHelpers.createTestNumber(testUser.id, {
        status: 'SUSPENDED',
      });

      const response = await request(app)
        .get('/api/v1/numbers')
        .query({ status: 'ACTIVE' })
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .expect(200);

      expect(response.body.data.numbers).toHaveLength(1);
      expect(response.body.data.numbers[0].status).toBe('ACTIVE');
    });

    it('should support search', async () => {
      const response = await request(app)
        .get('/api/v1/numbers')
        .query({ search: userNumber.phoneNumber.slice(-4) })
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .expect(200);

      expect(response.body.data.numbers).toHaveLength(1);
      expect(response.body.data.numbers[0].phoneNumber).toBe(userNumber.phoneNumber);
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .get('/api/v1/numbers')
        .expect(401);

      testHelpers.expectAuthError(response);
    });
  });

  describe('GET /api/v1/numbers/:id', () => {
    let userNumber: TestNumber;

    beforeEach(async () => {
      userNumber = await testHelpers.createTestNumber(testUser.id);
    });

    it('should return number details for owner', async () => {
      const response = await request(app)
        .get(`/api/v1/numbers/${userNumber.id}`)
        .set(testHelpers.generateAuthHeader(testUser.accessToken))
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.id).toBe(userNumber.id);
      expect(response.body.data.phoneNumber).toBe(userNumber.phoneNumber);
    });

    it('should deny access to other user\'s numbers', async () => {
      const otherUser = await testHelpers.createTestUser({
        email: 'other@example.com',
      });

      const response = await request(app)
        .get(`/api/v1/numbers/${userNumber.id}`)
        .set(testHelpers.generateAuthHeader(otherUser.accessToken))
        .expect(404);

      expect(response.body.success).toBe(false);
    });

    it('should allow admin access to any number', async () => {
      const response = await request(app)
        .get(`/api/v1/numbers/${userNumber.id}`)
        .set(testHelpers.generateAuthHeader(adminUser.accessToken))
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.id).toBe(userNumber.id);
    });
  });
});
```

## 5. End-to-End Testing

### 5.1 Complete User Journey Tests

```typescript
// tests/e2e/user-journey.test.ts
import request from 'supertest';
import { app } from '../../src/app';
import { prisma } from '../setup';
import { TestHelpers } from '../utils/test-helpers';

describe('Complete User Journey E2E Tests', () => {
  let testHelpers: TestHelpers;

  beforeAll(() => {
    testHelpers = new TestHelpers(app, prisma);
  });

  describe('New User Complete Flow', () => {
    it('should complete full user registration to number purchase flow', async () => {
      // Step 1: User Registration
      const registrationData = {
        email: 'journey@example.com',
        password: 'Test123!',
        firstName: 'Journey',
        lastName: 'User',
        company: 'Test Company',
        acceptTerms: true,
      };

      const registrationResponse = await request(app)
        .post('/api/v1/auth/register')
        .send(registrationData)
        .expect(201);

      expect(registrationResponse.body.success).toBe(true);
      const { user, tokens } = registrationResponse.body.data;

      // Step 2: Search for available numbers
      require('../../src/services/twilio.service').TwilioService.prototype.searchNumbers = jest
        .fn()
        .mockResolvedValue({
          success: true,
          data: [
            {
              phoneNumber: '+14155551234',
              friendlyName: 'San Francisco Number',
              locality: 'San Francisco',
              region: 'CA',
              countryCode: 'US',
              capabilities: { voice: true, sms: true },
              pricing: { monthlyPrice: '1.00', currency: 'USD' },
            },
          ],
        });

      const searchResponse = await request(app)
        .get('/api/v1/numbers/search')
        .query({ countryCode: 'US', areaCode: '415' })
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .expect(200);

      expect(searchResponse.body.data).toHaveLength(1);
      const availableNumber = searchResponse.body.data[0];

      // Step 3: Purchase the number
      require('../../src/services/twilio.service').TwilioService.prototype.purchaseNumber = jest
        .fn()
        .mockResolvedValue({
          success: true,
          data: {
            sid: 'PN123456789',
            phoneNumber: availableNumber.phoneNumber,
            friendlyName: availableNumber.friendlyName,
            countryCode: 'US',
            capabilities: ['voice', 'sms'],
            price: { setup: 1.0, monthly: 1.0 },
          },
        });

      const purchaseResponse = await request(app)
        .post('/api/v1/numbers/purchase')
        .send({
          numbers: [
            {
              phoneNumber: availableNumber.phoneNumber,
              friendlyName: 'My First Number',
            },
          ],
        })
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .expect(201);

      expect(purchaseResponse.body.data.results[0].status).toBe('SUCCESS');
      const orderId = purchaseResponse.body.data.orderId;

      // Step 4: Verify order was created
      const orderResponse = await request(app)
        .get(`/api/v1/orders/${orderId}`)
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .expect(200);

      expect(orderResponse.body.data.status).toBe('COMPLETED');
      expect(orderResponse.body.data.numbers).toHaveLength(1);

      // Step 5: Check user's numbers
      const numbersResponse = await request(app)
        .get('/api/v1/numbers')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .expect(200);

      expect(numbersResponse.body.data.numbers).toHaveLength(1);
      expect(numbersResponse.body.data.numbers[0].phoneNumber).toBe(availableNumber.phoneNumber);

      // Step 6: Configure the number
      const configurationResponse = await request(app)
        .put(`/api/v1/numbers/${numbersResponse.body.data.numbers[0].id}`)
        .send({
          voiceUrl: 'https://myapp.com/voice',
          voiceMethod: 'POST',
          friendlyName: 'My Configured Number',
        })
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .expect(200);

      expect(configurationResponse.body.success).toBe(true);

      // Step 7: Check billing account
      const billingResponse = await request(app)
        .get('/api/v1/billing/account')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .expect(200);

      expect(billingResponse.body.data.userId).toBe(user.id);

      // Step 8: Get usage statistics
      const analyticsResponse = await request(app)
        .get('/api/v1/analytics/dashboard')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .expect(200);

      expect(analyticsResponse.body.data.summary.totalNumbers).toBe(1);
    });

    it('should handle complete error recovery flow', async () => {
      const testUser = await testHelpers.createTestUser();

      // Simulate failed purchase
      require('../../src/services/twilio.service').TwilioService.prototype.purchaseNumber = jest
        .fn()
        .mockRejectedValueOnce(new Error('Service temporarily unavailable'))
        .mockResolvedValueOnce({
          success: true,
          data: {
            sid: 'PN123456789',
            phoneNumber: '+14155551234',
            friendlyName: 'Retry Success',
            countryCode: 'US',
            capabilities: ['voice', 'sms'],
            price: { setup: 1.0, monthly: 1.0 },
          },
        });

      // First attempt should fail
      const failedResponse = await request(app)
        .post('/api/v1/numbers/purchase')
        .send({
          numbers: [
            {
              phoneNumber: '+14155551234',
              friendlyName: 'Test Number',
            },
          ],
        })
        .set('Authorization', `Bearer ${testUser.accessToken}`)
        .expect(201);

      expect(failedResponse.body.data.results[0].status).toBe('FAILED');

      // Retry should succeed
      const retryResponse = await request(app)
        .post('/api/v1/numbers/purchase')
        .send({
          numbers: [
            {
              phoneNumber: '+14155551234',
              friendlyName: 'Test Number',
            },
          ],
        })
        .set('Authorization', `Bearer ${testUser.accessToken}`)
        .expect(201);

      expect(retryResponse.body.data.results[0].status).toBe('SUCCESS');
    });
  });

  describe('Admin Management Flow', () => {
    it('should complete admin user management flow', async () => {
      const adminUser = await testHelpers.createTestUser({ role: 'ADMIN' });
      const regularUser = await testHelpers.createTestUser({
        email: 'managed@example.com',
      });

      // Admin views all users
      const usersResponse = await request(app)
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${adminUser.accessToken}`)
        .expect(200);

      expect(usersResponse.body.data.users.length).toBeGreaterThan(0);

      // Admin views specific user details
      const userDetailsResponse = await request(app)
        .get(`/api/v1/admin/users/${regularUser.id}`)
        .set('Authorization', `Bearer ${adminUser.accessToken}`)
        .expect(200);

      expect(userDetailsResponse.body.data.user.id).toBe(regularUser.id);

      // Admin suspends user
      const suspendResponse = await request(app)
        .put(`/api/v1/admin/users/${regularUser.id}/suspend`)
        .send({
          reason: 'Policy violation',
          duration: 7,
          notifyUser: true,
        })
        .set('Authorization', `Bearer ${adminUser.accessToken}`)
        .expect(200);

      expect(suspendResponse.body.success).toBe(true);

      // Verify user cannot login while suspended
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'managed@example.com',
          password: 'Test123!',
        })
        .expect(403);

      testHelpers.expectAuthError(loginResponse, 403);

      // Admin reactivates user
      const reactivateResponse = await request(app)
        .put(`/api/v1/admin/users/${regularUser.id}/reactivate`)
        .set('Authorization', `Bearer ${adminUser.accessToken}`)
        .expect(200);

      expect(reactivateResponse.body.success).toBe(true);

      // User can login again
      const successLoginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'managed@example.com',
          password: 'Test123!',
        })
        .expect(200);

      expect(successLoginResponse.body.success).toBe(true);
    });
  });
});
```

## 6. Performance Testing

### 6.1 Load Testing Configuration

```typescript
// tests/performance/load-test.config.ts
export interface LoadTestConfig {
  duration: string;
  vus: number; // Virtual users
  rampUpTime: string;
  rampDownTime: string;
  thresholds: {
    httpReqDuration: string[];
    httpReqFailed: string[];
    iterations: string[];
  };
}

export const loadTestConfigs: Record<string, LoadTestConfig> = {
  smoke: {
    duration: '1m',
    vus: 1,
    rampUpTime: '30s',
    rampDownTime: '30s',
    thresholds: {
      httpReqDuration: ['p(95)<500'],
      httpReqFailed: ['rate<0.1'],
      iterations: ['count>10'],
    },
  },
  
  load: {
    duration: '5m',
    vus: 100,
    rampUpTime: '2m',
    rampDownTime: '2m',
    thresholds: {
      httpReqDuration: ['p(95)<1000'],
      httpReqFailed: ['rate<0.1'],
      iterations: ['count>1000'],
    },
  },
  
  stress: {
    duration: '10m',
    vus: 500,
    rampUpTime: '5m',
    rampDownTime: '5m',
    thresholds: {
      httpReqDuration: ['p(95)<2000'],
      httpReqFailed: ['rate<0.2'],
      iterations: ['count>5000'],
    },
  },
  
  spike: {
    duration: '2m',
    vus: 1000,
    rampUpTime: '30s',
    rampDownTime: '30s',
    thresholds: {
      httpReqDuration: ['p(95)<3000'],
      httpReqFailed: ['rate<0.3'],
      iterations: ['count>1000'],
    },
  },
};
```

### 6.2 K6 Performance Tests

```javascript
// tests/performance/auth-load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');

export let options = {
  stages: [
    { duration: '2m', target: 100 }, // Ramp up
    { duration: '5m', target: 100 }, // Stay at 100 users
    { duration: '2m', target: 200 }, // Ramp up to 200 users
    { duration: '5m', target: 200 }, // Stay at 200 users
    { duration: '2m', target: 0 },   // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests under 500ms
    http_req_failed: ['rate<0.1'],    // Error rate under 10%
    errors: ['rate<0.1'],             // Custom error rate under 10%
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

export default function () {
  // Test data
  const email = `testuser${Math.random()}@example.com`;
  const password = 'Test123!';
  
  // Register user
  let registerPayload = JSON.stringify({
    email: email,
    password: password,
    firstName: 'Load',
    lastName: 'Test',
    acceptTerms: true,
  });

  let registerParams = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  let registerResponse = http.post(
    `${BASE_URL}/api/v1/auth/register`,
    registerPayload,
    registerParams
  );

  let registerSuccess = check(registerResponse, {
    'registration status is 201': (r) => r.status === 201,
    'registration response has token': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.data && body.data.tokens && body.data.tokens.accessToken;
      } catch {
        return false;
      }
    },
  });

  if (!registerSuccess) {
    errorRate.add(1);
    return;
  }

  const registerBody = JSON.parse(registerResponse.body);
  const accessToken = registerBody.data.tokens.accessToken;

  sleep(1);

  // Login user
  let loginPayload = JSON.stringify({
    email: email,
    password: password,
  });

  let loginResponse = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    loginPayload,
    registerParams
  );

  let loginSuccess = check(loginResponse, {
    'login status is 200': (r) => r.status === 200,
    'login response has token': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.data && body.data.tokens && body.data.tokens.accessToken;
      } catch {
        return false;
      }
    },
  });

  if (!loginSuccess) {
    errorRate.add(1);
    return;
  }

  sleep(1);

  // Search for numbers
  let searchParams = {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  };

  let searchResponse = http.get(
    `${BASE_URL}/api/v1/numbers/search?countryCode=US&areaCode=415&limit=10`,
    searchParams
  );

  let searchSuccess = check(searchResponse, {
    'search status is 200': (r) => r.status === 200,
    'search response has numbers': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.data && Array.isArray(body.data);
      } catch {
        return false;
      }
    },
  });

  if (!searchSuccess) {
    errorRate.add(1);
  }

  sleep(1);

  // Get user's numbers
  let numbersResponse = http.get(
    `${BASE_URL}/api/v1/numbers`,
    searchParams
  );

  let numbersSuccess = check(numbersResponse, {
    'numbers status is 200': (r) => r.status === 200,
    'numbers response is valid': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.data && body.data.numbers && Array.isArray(body.data.numbers);
      } catch {
        return false;
      }
    },
  });

  if (!numbersSuccess) {
    errorRate.add(1);
  }

  sleep(2);
}

export function handleSummary(data) {
  return {
    'auth-load-test-results.json': JSON.stringify(data, null, 2),
  };
}
```

### 6.3 Memory and Resource Testing

```typescript
// tests/performance/memory-leak-test.ts
import { app } from '../../src/app';
import { TestHelpers } from '../utils/test-helpers';
import { performance, PerformanceObserver } from 'perf_hooks';

describe('Memory and Resource Tests', () => {
  let testHelpers: TestHelpers;
  let initialMemory: NodeJS.MemoryUsage;

  beforeAll(() => {
    testHelpers = new TestHelpers(app, prisma);
    initialMemory = process.memoryUsage();
  });

  it('should not leak memory during repeated operations', async () => {
    const iterations = 1000;
    const memoryMeasurements: number[] = [];

    // Warm up
    for (let i = 0; i < 10; i++) {
      await performOperations();
    }

    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }

    const startMemory = process.memoryUsage().heapUsed;

    // Perform repeated operations
    for (let i = 0; i < iterations; i++) {
      await performOperations();
      
      if (i % 100 === 0) {
        if (global.gc) {
          global.gc();
        }
        memoryMeasurements.push(process.memoryUsage().heapUsed);
      }
    }

    if (global.gc) {
      global.gc();
    }

    const endMemory = process.memoryUsage().heapUsed;
    const memoryIncrease = endMemory - startMemory;
    const memoryIncreasePercentage = (memoryIncrease / startMemory) * 100;

    console.log(`Memory increase: ${memoryIncrease} bytes (${memoryIncreasePercentage.toFixed(2)}%)`);
    console.log(`Memory measurements:`, memoryMeasurements);

    // Memory should not increase by more than 50%
    expect(memoryIncreasePercentage).toBeLessThan(50);
  });

  it('should handle database connection pool efficiently', async () => {
    const concurrentOperations = 50;
    const operationsPerConnection = 10;

    const startTime = Date.now();
    const promises = [];

    for (let i = 0; i < concurrentOperations; i++) {
      promises.push(performDatabaseOperations(operationsPerConnection));
    }

    await Promise.all(promises);
    const endTime = Date.now();
    const totalTime = endTime - startTime;

    console.log(`Completed ${concurrentOperations * operationsPerConnection} database operations in ${totalTime}ms`);

    // Should complete within reasonable time (adjust based on your requirements)
    expect(totalTime).toBeLessThan(30000); // 30 seconds
  });

  it('should handle concurrent API requests efficiently', async () => {
    const concurrentUsers = 100;
    const requestsPerUser = 5;

    const users = await Promise.all(
      Array.from({ length: concurrentUsers }, () => testHelpers.createTestUser())
    );

    const startTime = Date.now();
    const promises = [];

    for (const user of users) {
      promises.push(performUserRequests(user, requestsPerUser));
    }

    const results = await Promise.all(promises);
    const endTime = Date.now();
    const totalTime = endTime - startTime;

    const totalRequests = concurrentUsers * requestsPerUser;
    const requestsPerSecond = totalRequests / (totalTime / 1000);

    console.log(`Processed ${totalRequests} requests in ${totalTime}ms (${requestsPerSecond.toFixed(2)} req/s)`);

    // Check that all requests succeeded
    const allSuccessful = results.every(result => result.every(r => r.success));
    expect(allSuccessful).toBe(true);

    // Should handle at least 10 requests per second
    expect(requestsPerSecond).toBeGreaterThan(10);
  });

  async function performOperations() {
    // Simulate typical application operations
    const testUser = await testHelpers.createTestUser();
    
    // Simulate some database operations
    await prisma.user.findUnique({ where: { id: testUser.id } });
    await prisma.number.findMany({ where: { userId: testUser.id } });
    await prisma.order.findMany({ where: { userId: testUser.id } });
    
    // Clean up
    await prisma.user.delete({ where: { id: testUser.id } });
  }

  async function performDatabaseOperations(count: number) {
    for (let i = 0; i < count; i++) {
      await prisma.user.findMany({ take: 10 });
      await prisma.number.findMany({ take: 10 });
      await prisma.order.findMany({ take: 10 });
    }
  }

  async function performUserRequests(user: TestUser, count: number): Promise<{ success: boolean }[]> {
    const results = [];
    
    for (let i = 0; i < count; i++) {
      try {
        const response = await request(app)
          .get('/api/v1/numbers')
          .set('Authorization', `Bearer ${user.accessToken}`);
        
        results.push({ success: response.status === 200 });
      } catch (error) {
        results.push({ success: false });
      }
    }
    
    return results;
  }
});
```

This comprehensive testing strategy provides complete coverage for unit testing, integration testing, end-to-end testing, and performance testing with TypeScript implementations for the DID buy system.
