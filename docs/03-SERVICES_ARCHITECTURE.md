# Services Architecture - TypeScript Implementation

## 1. Overview

This document provides comprehensive documentation for all service layer implementations in the DID buy system, focusing on TypeScript-based architecture with proper separation of concerns, dependency injection, and business logic encapsulation.

## 2. Service Architecture Principles

### 2.1 Design Patterns
- **Dependency Injection**: Constructor-based dependency injection
- **Repository Pattern**: Data access abstraction
- **Service Layer Pattern**: Business logic encapsulation
- **Factory Pattern**: Complex object creation
- **Observer Pattern**: Event-driven architecture
- **Strategy Pattern**: Configurable algorithms

### 2.2 Core Service Structure

```typescript
// src/types/service.types.ts
export interface BaseService {
  readonly name: string;
  initialize(): Promise<void>;
  destroy(): Promise<void>;
}

export interface ServiceContext {
  prisma: PrismaClient;
  redis: Redis;
  logger: Logger;
  config: AppConfig;
}

export interface ServiceResult<T = any> {
  success: boolean;
  data?: T;
  error?: ServiceError;
  meta?: {
    timestamp: Date;
    duration: number;
    source: string;
  };
}

export class ServiceError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 500,
    public details?: Record<string, any>
  ) {
    super(message);
    this.name = 'ServiceError';
  }
}
```

## 3. Authentication Service

### 3.1 Auth Service Implementation

```typescript
// src/services/auth.service.ts
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { randomBytes, createHash } from 'crypto';
import { PrismaClient, User, Session } from '@prisma/client';
import { Redis } from 'ioredis';
import { Logger } from 'winston';

export interface AuthServiceDependencies {
  prisma: PrismaClient;
  redis: Redis;
  logger: Logger;
  emailService: EmailService;
  config: AuthConfig;
}

export interface AuthConfig {
  jwt: {
    secret: string;
    refreshSecret: string;
    accessTokenExpiry: string;
    refreshTokenExpiry: string;
  };
  password: {
    saltRounds: number;
    minLength: number;
    requireSpecialChar: boolean;
  };
  session: {
    maxActiveSessions: number;
    extendOnActivity: boolean;
  };
  verification: {
    emailTokenExpiry: number;
    passwordResetExpiry: number;
  };
}

export interface RegisterRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  company?: string;
  phone?: string;
  timezone?: string;
  acceptTerms: boolean;
  marketingConsent?: boolean;
}

export interface LoginRequest {
  email: string;
  password: string;
  rememberMe?: boolean;
  deviceInfo?: DeviceInfo;
  ipAddress?: string;
  userAgent?: string;
}

export interface AuthResult {
  user: Omit<User, 'password'>;
  tokens: TokenPair;
  session: {
    id: string;
    expiresAt: Date;
  };
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export class AuthService implements BaseService {
  readonly name = 'AuthService';

  constructor(private deps: AuthServiceDependencies) {}

  async initialize(): Promise<void> {
    this.deps.logger.info('AuthService initialized');
  }

  async destroy(): Promise<void> {
    this.deps.logger.info('AuthService destroyed');
  }

  async register(request: RegisterRequest): Promise<ServiceResult<AuthResult>> {
    const startTime = Date.now();
    
    try {
      // Validate input
      await this.validateRegistrationInput(request);
      
      // Check if user already exists
      const existingUser = await this.deps.prisma.user.findUnique({
        where: { email: request.email.toLowerCase() }
      });

      if (existingUser) {
        throw new ServiceError(
          'User already exists',
          'USER_EXISTS',
          409
        );
      }

      // Hash password
      const hashedPassword = await this.hashPassword(request.password);

      // Generate email verification token
      const emailVerificationToken = this.generateSecureToken();
      const emailVerificationExpires = new Date(
        Date.now() + this.deps.config.verification.emailTokenExpiry
      );

      // Create user
      const user = await this.deps.prisma.user.create({
        data: {
          email: request.email.toLowerCase(),
          password: hashedPassword,
          firstName: request.firstName,
          lastName: request.lastName,
          company: request.company,
          phone: request.phone,
          timezone: request.timezone || 'UTC',
          emailVerificationToken,
          emailVerificationExpires,
          preferences: this.getDefaultUserPreferences(),
        }
      });

      // Generate tokens and create session
      const tokens = await this.generateTokens(user.id);
      const session = await this.createSession(user.id, tokens.refreshToken);

      // Send verification email
      await this.deps.emailService.sendVerificationEmail(
        user.email,
        emailVerificationToken,
        user.firstName
      );

      // Create billing account
      await this.createBillingAccount(user.id);

      // Log registration
      await this.logUserActivity(user.id, 'USER_REGISTERED', {
        email: user.email,
        source: 'registration'
      });

      const result: AuthResult = {
        user: this.sanitizeUser(user),
        tokens,
        session: {
          id: session.id,
          expiresAt: session.expiresAt
        }
      };

      return {
        success: true,
        data: result,
        meta: {
          timestamp: new Date(),
          duration: Date.now() - startTime,
          source: 'AuthService.register'
        }
      };

    } catch (error) {
      this.deps.logger.error('Registration failed', {
        email: request.email,
        error: error.message,
        stack: error.stack
      });

      if (error instanceof ServiceError) {
        throw error;
      }

      throw new ServiceError(
        'Registration failed',
        'REGISTRATION_ERROR',
        500,
        { originalError: error.message }
      );
    }
  }

  async login(request: LoginRequest): Promise<ServiceResult<AuthResult>> {
    const startTime = Date.now();

    try {
      // Find user
      const user = await this.deps.prisma.user.findUnique({
        where: { email: request.email.toLowerCase() },
        include: { billingAccount: true }
      });

      if (!user) {
        throw new ServiceError(
          'Invalid credentials',
          'INVALID_CREDENTIALS',
          401
        );
      }

      // Check if user is active
      if (!user.isActive) {
        throw new ServiceError(
          'Account is deactivated',
          'ACCOUNT_DEACTIVATED',
          403
        );
      }

      if (user.isSuspended) {
        throw new ServiceError(
          'Account is suspended',
          'ACCOUNT_SUSPENDED',
          403,
          { reason: user.suspensionReason }
        );
      }

      // Verify password
      const isPasswordValid = await bcrypt.compare(request.password, user.password);
      if (!isPasswordValid) {
        await this.logFailedLogin(request.email, request.ipAddress);
        throw new ServiceError(
          'Invalid credentials',
          'INVALID_CREDENTIALS',
          401
        );
      }

      // Check session limits
      await this.enforceSessionLimits(user.id);

      // Generate tokens and create session
      const tokens = await this.generateTokens(user.id);
      const session = await this.createSession(
        user.id,
        tokens.refreshToken,
        request.deviceInfo,
        request.ipAddress,
        request.userAgent
      );

      // Update last login
      await this.deps.prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() }
      });

      // Log successful login
      await this.logUserActivity(user.id, 'USER_LOGIN', {
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        deviceInfo: request.deviceInfo
      });

      const result: AuthResult = {
        user: this.sanitizeUser(user),
        tokens,
        session: {
          id: session.id,
          expiresAt: session.expiresAt
        }
      };

      return {
        success: true,
        data: result,
        meta: {
          timestamp: new Date(),
          duration: Date.now() - startTime,
          source: 'AuthService.login'
        }
      };

    } catch (error) {
      this.deps.logger.error('Login failed', {
        email: request.email,
        error: error.message
      });

      if (error instanceof ServiceError) {
        throw error;
      }

      throw new ServiceError(
        'Login failed',
        'LOGIN_ERROR',
        500
      );
    }
  }

  async refreshToken(refreshToken: string): Promise<ServiceResult<TokenPair>> {
    try {
      // Find and validate session
      const session = await this.deps.prisma.session.findUnique({
        where: { refreshToken },
        include: { user: true }
      });

      if (!session || session.isRevoked || session.expiresAt < new Date()) {
        throw new ServiceError(
          'Invalid refresh token',
          'INVALID_REFRESH_TOKEN',
          401
        );
      }

      if (!session.user.isActive || session.user.isSuspended) {
        throw new ServiceError(
          'User account is not active',
          'ACCOUNT_INACTIVE',
          403
        );
      }

      // Generate new tokens
      const tokens = await this.generateTokens(session.userId);

      // Update session
      await this.deps.prisma.session.update({
        where: { id: session.id },
        data: {
          refreshToken: tokens.refreshToken,
          expiresAt: new Date(Date.now() + this.parseExpiry(this.deps.config.jwt.refreshTokenExpiry))
        }
      });

      return {
        success: true,
        data: tokens
      };

    } catch (error) {
      if (error instanceof ServiceError) {
        throw error;
      }

      throw new ServiceError(
        'Token refresh failed',
        'TOKEN_REFRESH_ERROR',
        500
      );
    }
  }

  async logout(refreshToken: string, allDevices: boolean = false): Promise<ServiceResult<void>> {
    try {
      if (allDevices) {
        // Find user by refresh token and revoke all sessions
        const session = await this.deps.prisma.session.findUnique({
          where: { refreshToken }
        });

        if (session) {
          await this.deps.prisma.session.updateMany({
            where: { userId: session.userId },
            data: { isRevoked: true, revokedAt: new Date() }
          });

          await this.logUserActivity(session.userId, 'USER_LOGOUT_ALL');
        }
      } else {
        // Revoke specific session
        const session = await this.deps.prisma.session.update({
          where: { refreshToken },
          data: { isRevoked: true, revokedAt: new Date() }
        });

        await this.logUserActivity(session.userId, 'USER_LOGOUT');
      }

      return { success: true };

    } catch (error) {
      throw new ServiceError(
        'Logout failed',
        'LOGOUT_ERROR',
        500
      );
    }
  }

  async forgotPassword(email: string): Promise<ServiceResult<void>> {
    try {
      const user = await this.deps.prisma.user.findUnique({
        where: { email: email.toLowerCase() }
      });

      if (!user) {
        // Don't reveal that user doesn't exist
        return { success: true };
      }

      // Generate reset token
      const resetToken = this.generateSecureToken();
      const resetExpires = new Date(
        Date.now() + this.deps.config.verification.passwordResetExpiry
      );

      // Update user with reset token
      await this.deps.prisma.user.update({
        where: { id: user.id },
        data: {
          passwordResetToken: resetToken,
          passwordResetExpires: resetExpires
        }
      });

      // Send reset email
      await this.deps.emailService.sendPasswordResetEmail(
        user.email,
        resetToken,
        user.firstName
      );

      await this.logUserActivity(user.id, 'PASSWORD_RESET_REQUESTED');

      return { success: true };

    } catch (error) {
      throw new ServiceError(
        'Password reset request failed',
        'PASSWORD_RESET_ERROR',
        500
      );
    }
  }

  async resetPassword(token: string, newPassword: string): Promise<ServiceResult<void>> {
    try {
      // Find user by reset token
      const user = await this.deps.prisma.user.findFirst({
        where: {
          passwordResetToken: token,
          passwordResetExpires: { gte: new Date() }
        }
      });

      if (!user) {
        throw new ServiceError(
          'Invalid or expired reset token',
          'INVALID_RESET_TOKEN',
          400
        );
      }

      // Validate new password
      this.validatePassword(newPassword);

      // Hash new password
      const hashedPassword = await this.hashPassword(newPassword);

      // Update user
      await this.deps.prisma.user.update({
        where: { id: user.id },
        data: {
          password: hashedPassword,
          passwordResetToken: null,
          passwordResetExpires: null
        }
      });

      // Revoke all sessions
      await this.deps.prisma.session.updateMany({
        where: { userId: user.id },
        data: { isRevoked: true, revokedAt: new Date() }
      });

      await this.logUserActivity(user.id, 'PASSWORD_RESET_COMPLETED');

      return { success: true };

    } catch (error) {
      if (error instanceof ServiceError) {
        throw error;
      }

      throw new ServiceError(
        'Password reset failed',
        'PASSWORD_RESET_ERROR',
        500
      );
    }
  }

  async verifyEmail(token: string): Promise<ServiceResult<void>> {
    try {
      const user = await this.deps.prisma.user.findFirst({
        where: {
          emailVerificationToken: token,
          emailVerificationExpires: { gte: new Date() }
        }
      });

      if (!user) {
        throw new ServiceError(
          'Invalid or expired verification token',
          'INVALID_VERIFICATION_TOKEN',
          400
        );
      }

      await this.deps.prisma.user.update({
        where: { id: user.id },
        data: {
          emailVerified: true,
          emailVerificationToken: null,
          emailVerificationExpires: null
        }
      });

      await this.logUserActivity(user.id, 'EMAIL_VERIFIED');

      return { success: true };

    } catch (error) {
      if (error instanceof ServiceError) {
        throw error;
      }

      throw new ServiceError(
        'Email verification failed',
        'EMAIL_VERIFICATION_ERROR',
        500
      );
    }
  }

  // Private helper methods
  private async validateRegistrationInput(request: RegisterRequest): Promise<void> {
    if (!request.email || !this.isValidEmail(request.email)) {
      throw new ServiceError('Invalid email address', 'INVALID_EMAIL', 400);
    }

    this.validatePassword(request.password);

    if (!request.firstName?.trim()) {
      throw new ServiceError('First name is required', 'MISSING_FIRST_NAME', 400);
    }

    if (!request.lastName?.trim()) {
      throw new ServiceError('Last name is required', 'MISSING_LAST_NAME', 400);
    }

    if (!request.acceptTerms) {
      throw new ServiceError('Terms acceptance is required', 'TERMS_NOT_ACCEPTED', 400);
    }
  }

  private validatePassword(password: string): void {
    if (!password || password.length < this.deps.config.password.minLength) {
      throw new ServiceError(
        `Password must be at least ${this.deps.config.password.minLength} characters`,
        'WEAK_PASSWORD',
        400
      );
    }

    if (this.deps.config.password.requireSpecialChar) {
      const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
      if (!hasSpecialChar) {
        throw new ServiceError(
          'Password must contain at least one special character',
          'WEAK_PASSWORD',
          400
        );
      }
    }
  }

  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  private async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.deps.config.password.saltRounds);
  }

  private generateSecureToken(): string {
    return randomBytes(32).toString('hex');
  }

  private async generateTokens(userId: string): Promise<TokenPair> {
    const accessTokenPayload = {
      userId,
      type: 'access',
      iat: Math.floor(Date.now() / 1000)
    };

    const refreshTokenPayload = {
      userId,
      type: 'refresh',
      iat: Math.floor(Date.now() / 1000)
    };

    const accessToken = jwt.sign(
      accessTokenPayload,
      this.deps.config.jwt.secret,
      { expiresIn: this.deps.config.jwt.accessTokenExpiry }
    );

    const refreshToken = jwt.sign(
      refreshTokenPayload,
      this.deps.config.jwt.refreshSecret,
      { expiresIn: this.deps.config.jwt.refreshTokenExpiry }
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: this.parseExpiry(this.deps.config.jwt.accessTokenExpiry)
    };
  }

  private async createSession(
    userId: string,
    refreshToken: string,
    deviceInfo?: DeviceInfo,
    ipAddress?: string,
    userAgent?: string
  ): Promise<Session> {
    return this.deps.prisma.session.create({
      data: {
        userId,
        refreshToken,
        expiresAt: new Date(Date.now() + this.parseExpiry(this.deps.config.jwt.refreshTokenExpiry)),
        deviceInfo: deviceInfo ? JSON.stringify(deviceInfo) : null,
        ipAddress,
        userAgent
      }
    });
  }

  private async enforceSessionLimits(userId: string): Promise<void> {
    const activeSessions = await this.deps.prisma.session.count({
      where: {
        userId,
        isRevoked: false,
        expiresAt: { gte: new Date() }
      }
    });

    if (activeSessions >= this.deps.config.session.maxActiveSessions) {
      // Revoke oldest session
      const oldestSession = await this.deps.prisma.session.findFirst({
        where: {
          userId,
          isRevoked: false,
          expiresAt: { gte: new Date() }
        },
        orderBy: { createdAt: 'asc' }
      });

      if (oldestSession) {
        await this.deps.prisma.session.update({
          where: { id: oldestSession.id },
          data: { isRevoked: true, revokedAt: new Date() }
        });
      }
    }
  }

  private async createBillingAccount(userId: string): Promise<void> {
    await this.deps.prisma.billingAccount.create({
      data: {
        userId,
        currency: 'USD',
        billingAddress: JSON.stringify({
          country: 'US'
        })
      }
    });
  }

  private sanitizeUser(user: User): Omit<User, 'password'> {
    const { password, ...sanitizedUser } = user;
    return sanitizedUser;
  }

  private getDefaultUserPreferences(): UserPreferences {
    return {
      theme: 'light',
      language: 'en',
      timezone: 'UTC',
      notifications: {
        email: true,
        sms: false,
        push: true,
        marketing: false
      },
      dashboard: {
        defaultView: 'numbers',
        chartsType: 'line'
      },
      calling: {
        recordByDefault: false,
        transcribeByDefault: false,
        blockAnonymous: false
      }
    };
  }

  private async logUserActivity(
    userId: string,
    action: string,
    details?: Record<string, any>
  ): Promise<void> {
    try {
      await this.deps.prisma.auditLog.create({
        data: {
          userId,
          action,
          resource: 'user',
          resourceId: userId,
          newValues: JSON.stringify(details || {}),
          success: true
        }
      });
    } catch (error) {
      this.deps.logger.error('Failed to log user activity', { userId, action, error });
    }
  }

  private async logFailedLogin(email: string, ipAddress?: string): Promise<void> {
    try {
      await this.deps.prisma.auditLog.create({
        data: {
          action: 'LOGIN_FAILED',
          resource: 'user',
          newValues: JSON.stringify({ email, ipAddress }),
          success: false,
          ipAddress
        }
      });
    } catch (error) {
      this.deps.logger.error('Failed to log failed login', { email, error });
    }
  }

  private parseExpiry(expiry: string): number {
    // Parse expiry strings like '15m', '7d', '1h'
    const match = expiry.match(/(\d+)([smhd])/);
    if (!match) return 15 * 60 * 1000; // Default 15 minutes

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case 's': return value * 1000;
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      default: return 15 * 60 * 1000;
    }
  }
}
```

## 4. Twilio Integration Service

### 4.1 Twilio Service Implementation

```typescript
// src/services/twilio.service.ts
import { Twilio } from 'twilio';
import { Logger } from 'winston';
import { Redis } from 'ioredis';

export interface TwilioServiceDependencies {
  logger: Logger;
  redis: Redis;
  config: TwilioConfig;
}

export interface TwilioConfig {
  accountSid: string;
  authToken: string;
  webhookSecret: string;
  baseUrl: string;
  timeout: number;
  retryAttempts: number;
  cacheTimeout: number;
}

export interface NumberSearchParams {
  countryCode: string;
  areaCode?: string;
  contains?: string;
  nearLatLong?: string;
  distance?: number;
  numberType?: 'local' | 'tollFree' | 'mobile';
  limit?: number;
}

export interface AvailablePhoneNumber {
  phoneNumber: string;
  friendlyName: string;
  locality: string;
  region: string;
  countryCode: string;
  capabilities: string[];
  price: {
    setup: number;
    monthly: number;
  };
  restrictions?: string[];
}

export interface PurchaseNumberRequest {
  phoneNumber: string;
  friendlyName?: string;
  voiceUrl?: string;
  voiceMethod?: 'GET' | 'POST';
  smsUrl?: string;
  statusCallback?: string;
}

export interface PurchasedNumber {
  sid: string;
  phoneNumber: string;
  friendlyName: string;
  countryCode: string;
  capabilities: string[];
  price: {
    setup: number;
    monthly: number;
  };
}

export interface CallDetails {
  sid: string;
  from: string;
  to: string;
  direction: 'inbound' | 'outbound';
  status: string;
  duration?: number;
  price?: number;
  priceUnit?: string;
  startTime?: Date;
  endTime?: Date;
}

export class TwilioService implements BaseService {
  readonly name = 'TwilioService';
  private client: Twilio;
  private isInitialized = false;

  constructor(private deps: TwilioServiceDependencies) {
    this.client = new Twilio(
      this.deps.config.accountSid,
      this.deps.config.authToken,
      {
        logLevel: 'debug',
        timeout: this.deps.config.timeout
      }
    );
  }

  async initialize(): Promise<void> {
    try {
      // Test connection
      await this.client.api.accounts(this.deps.config.accountSid).fetch();
      this.isInitialized = true;
      this.deps.logger.info('TwilioService initialized successfully');
    } catch (error) {
      this.deps.logger.error('Failed to initialize TwilioService', error);
      throw new ServiceError(
        'Twilio service initialization failed',
        'TWILIO_INIT_ERROR',
        500
      );
    }
  }

  async destroy(): Promise<void> {
    this.isInitialized = false;
    this.deps.logger.info('TwilioService destroyed');
  }

  async searchNumbers(params: NumberSearchParams): Promise<ServiceResult<AvailablePhoneNumber[]>> {
    this.ensureInitialized();
    
    try {
      const cacheKey = `search:${JSON.stringify(params)}`;
      
      // Check cache first
      const cached = await this.deps.redis.get(cacheKey);
      if (cached) {
        return {
          success: true,
          data: JSON.parse(cached)
        };
      }

      let searchMethod;
      const searchOptions: any = {
        areaCode: params.areaCode,
        contains: params.contains,
        nearLatLong: params.nearLatLong,
        distance: params.distance,
        limit: params.limit || 20
      };

      // Determine search method based on number type
      switch (params.numberType) {
        case 'local':
          searchMethod = this.client.availablePhoneNumbers(params.countryCode).local;
          break;
        case 'tollFree':
          searchMethod = this.client.availablePhoneNumbers(params.countryCode).tollFree;
          delete searchOptions.areaCode; // Toll-free doesn't use area codes
          break;
        case 'mobile':
          searchMethod = this.client.availablePhoneNumbers(params.countryCode).mobile;
          break;
        default:
          searchMethod = this.client.availablePhoneNumbers(params.countryCode).local;
      }

      const numbers = await searchMethod.list(searchOptions);
      
      const mappedNumbers: AvailablePhoneNumber[] = numbers.map(this.mapTwilioNumber);

      // Cache results for 5 minutes
      await this.deps.redis.setex(
        cacheKey,
        this.deps.config.cacheTimeout,
        JSON.stringify(mappedNumbers)
      );

      return {
        success: true,
        data: mappedNumbers
      };

    } catch (error) {
      this.deps.logger.error('Number search failed', { params, error });
      
      if (error.code && error.code >= 20000 && error.code < 30000) {
        throw new ServiceError(
          'Invalid search parameters',
          'INVALID_SEARCH_PARAMS',
          400,
          { twilioError: error.message }
        );
      }

      throw new ServiceError(
        'Number search failed',
        'SEARCH_ERROR',
        500,
        { twilioError: error.message }
      );
    }
  }

  async purchaseNumber(request: PurchaseNumberRequest): Promise<ServiceResult<PurchasedNumber>> {
    this.ensureInitialized();

    try {
      const purchaseOptions: any = {
        phoneNumber: request.phoneNumber,
        friendlyName: request.friendlyName,
        voiceUrl: request.voiceUrl,
        voiceMethod: request.voiceMethod || 'POST',
        smsUrl: request.smsUrl,
        statusCallback: request.statusCallback
      };

      const purchasedNumber = await this.client.incomingPhoneNumbers.create(purchaseOptions);

      const result: PurchasedNumber = {
        sid: purchasedNumber.sid,
        phoneNumber: purchasedNumber.phoneNumber,
        friendlyName: purchasedNumber.friendlyName || '',
        countryCode: purchasedNumber.origin || '',
        capabilities: this.extractCapabilities(purchasedNumber),
        price: {
          setup: 0, // Twilio doesn't provide setup cost in response
          monthly: 0 // Will be filled from pricing API
        }
      };

      // Get pricing information
      try {
        const pricing = await this.getNumberPricing(
          request.phoneNumber,
          purchasedNumber.origin || 'US'
        );
        result.price = pricing;
      } catch (pricingError) {
        this.deps.logger.warn('Failed to get pricing info', { 
          phoneNumber: request.phoneNumber,
          error: pricingError 
        });
      }

      this.deps.logger.info('Number purchased successfully', {
        phoneNumber: request.phoneNumber,
        sid: purchasedNumber.sid
      });

      return {
        success: true,
        data: result
      };

    } catch (error) {
      this.deps.logger.error('Number purchase failed', { request, error });

      if (error.code === 21422) {
        throw new ServiceError(
          'Phone number is not available',
          'NUMBER_NOT_AVAILABLE',
          400
        );
      }

      if (error.code === 21450) {
        throw new ServiceError(
          'Insufficient account balance',
          'INSUFFICIENT_BALANCE',
          402
        );
      }

      throw new ServiceError(
        'Number purchase failed',
        'PURCHASE_ERROR',
        500,
        { twilioError: error.message }
      );
    }
  }

  async configureNumber(
    sid: string, 
    configuration: Partial<PurchaseNumberRequest>
  ): Promise<ServiceResult<void>> {
    this.ensureInitialized();

    try {
      await this.client.incomingPhoneNumbers(sid).update(configuration);

      this.deps.logger.info('Number configured successfully', { sid, configuration });

      return { success: true };

    } catch (error) {
      this.deps.logger.error('Number configuration failed', { sid, configuration, error });

      if (error.code === 20404) {
        throw new ServiceError(
          'Phone number not found',
          'NUMBER_NOT_FOUND',
          404
        );
      }

      throw new ServiceError(
        'Number configuration failed',
        'CONFIGURATION_ERROR',
        500,
        { twilioError: error.message }
      );
    }
  }

  async releaseNumber(sid: string): Promise<ServiceResult<void>> {
    this.ensureInitialized();

    try {
      await this.client.incomingPhoneNumbers(sid).remove();

      this.deps.logger.info('Number released successfully', { sid });

      return { success: true };

    } catch (error) {
      this.deps.logger.error('Number release failed', { sid, error });

      if (error.code === 20404) {
        throw new ServiceError(
          'Phone number not found',
          'NUMBER_NOT_FOUND',
          404
        );
      }

      throw new ServiceError(
        'Number release failed',
        'RELEASE_ERROR',
        500,
        { twilioError: error.message }
      );
    }
  }

  async getCallDetails(callSid: string): Promise<ServiceResult<CallDetails>> {
    this.ensureInitialized();

    try {
      const call = await this.client.calls(callSid).fetch();

      const callDetails: CallDetails = {
        sid: call.sid,
        from: call.from,
        to: call.to,
        direction: call.direction as 'inbound' | 'outbound',
        status: call.status,
        duration: call.duration ? parseInt(call.duration) : undefined,
        price: call.price ? parseFloat(call.price) : undefined,
        priceUnit: call.priceUnit || undefined,
        startTime: call.startTime || undefined,
        endTime: call.endTime || undefined
      };

      return {
        success: true,
        data: callDetails
      };

    } catch (error) {
      this.deps.logger.error('Failed to get call details', { callSid, error });

      throw new ServiceError(
        'Failed to get call details',
        'CALL_DETAILS_ERROR',
        500,
        { twilioError: error.message }
      );
    }
  }

  async validateWebhook(payload: string, signature: string): Promise<boolean> {
    try {
      const expectedSignature = Twilio.validateRequest(
        this.deps.config.authToken,
        payload,
        this.deps.config.baseUrl,
        signature
      );

      return expectedSignature;
    } catch (error) {
      this.deps.logger.error('Webhook validation failed', { error });
      return false;
    }
  }

  async makeCall(from: string, to: string, twiml: string): Promise<ServiceResult<string>> {
    this.ensureInitialized();

    try {
      const call = await this.client.calls.create({
        from,
        to,
        twiml
      });

      return {
        success: true,
        data: call.sid
      };

    } catch (error) {
      this.deps.logger.error('Failed to make call', { from, to, error });

      throw new ServiceError(
        'Failed to make call',
        'CALL_ERROR',
        500,
        { twilioError: error.message }
      );
    }
  }

  async sendSms(from: string, to: string, body: string): Promise<ServiceResult<string>> {
    this.ensureInitialized();

    try {
      const message = await this.client.messages.create({
        from,
        to,
        body
      });

      return {
        success: true,
        data: message.sid
      };

    } catch (error) {
      this.deps.logger.error('Failed to send SMS', { from, to, error });

      throw new ServiceError(
        'Failed to send SMS',
        'SMS_ERROR',
        500,
        { twilioError: error.message }
      );
    }
  }

  async checkHealth(): Promise<boolean> {
    try {
      await this.client.api.accounts(this.deps.config.accountSid).fetch();
      return true;
    } catch (error) {
      this.deps.logger.error('Twilio health check failed', error);
      return false;
    }
  }

  // Private helper methods
  private ensureInitialized(): void {
    if (!this.isInitialized) {
      throw new ServiceError(
        'Twilio service not initialized',
        'SERVICE_NOT_INITIALIZED',
        500
      );
    }
  }

  private mapTwilioNumber(twilioNumber: any): AvailablePhoneNumber {
    return {
      phoneNumber: twilioNumber.phoneNumber,
      friendlyName: twilioNumber.friendlyName || '',
      locality: twilioNumber.locality || '',
      region: twilioNumber.region || '',
      countryCode: twilioNumber.isoCountry || '',
      capabilities: Object.keys(twilioNumber.capabilities || {}),
      price: {
        setup: 0, // Twilio doesn't provide setup cost in search
        monthly: 0 // Will be filled from pricing API
      },
      restrictions: twilioNumber.beta ? ['beta'] : undefined
    };
  }

  private extractCapabilities(purchasedNumber: any): string[] {
    const capabilities = [];
    if (purchasedNumber.capabilities?.voice) capabilities.push('voice');
    if (purchasedNumber.capabilities?.sms) capabilities.push('sms');
    if (purchasedNumber.capabilities?.mms) capabilities.push('mms');
    if (purchasedNumber.capabilities?.fax) capabilities.push('fax');
    return capabilities;
  }

  private async getNumberPricing(phoneNumber: string, country: string): Promise<{ setup: number; monthly: number }> {
    try {
      // This would typically call Twilio's pricing API
      // For now, return default pricing
      return {
        setup: 1.00,
        monthly: 1.00
      };
    } catch (error) {
      this.deps.logger.warn('Failed to get pricing', { phoneNumber, country, error });
      return {
        setup: 0,
        monthly: 0
      };
    }
  }
}
```

## 5. Numbers Management Service

### 5.1 Numbers Service Implementation

```typescript
// src/services/numbers.service.ts
import { PrismaClient, Number, NumberStatus, NumberType } from '@prisma/client';
import { Logger } from 'winston';
import { TwilioService } from './twilio.service';
import { EventEmitter } from 'events';

export interface NumbersServiceDependencies {
  prisma: PrismaClient;
  twilioService: TwilioService;
  logger: Logger;
  eventEmitter: EventEmitter;
}

export interface PurchaseNumbersRequest {
  numbers: {
    phoneNumber: string;
    friendlyName?: string;
    configuration?: NumberConfiguration;
  }[];
  billingInfo?: {
    paymentMethodId?: string;
    promoCode?: string;
  };
}

export interface NumberConfiguration {
  voiceUrl?: string;
  voiceMethod?: 'GET' | 'POST';
  voiceFallbackUrl?: string;
  smsUrl?: string;
  statusCallback?: string;
  recordCalls?: boolean;
  transcribeCalls?: boolean;
  callScreening?: boolean;
}

export interface PurchaseResult {
  orderId: string;
  results: {
    phoneNumber: string;
    status: 'SUCCESS' | 'FAILED' | 'PENDING';
    numberId?: string;
    error?: string;
  }[];
  summary: {
    totalRequested: number;
    successful: number;
    failed: number;
    pending: number;
  };
}

export interface NumberSearchFilters {
  status?: NumberStatus[];
  numberType?: NumberType[];
  search?: string;
  tags?: string[];
}

export class NumbersService implements BaseService {
  readonly name = 'NumbersService';

  constructor(private deps: NumbersServiceDependencies) {}

  async initialize(): Promise<void> {
    this.deps.logger.info('NumbersService initialized');
  }

  async destroy(): Promise<void> {
    this.deps.logger.info('NumbersService destroyed');
  }

  async searchAvailableNumbers(
    params: NumberSearchParams
  ): Promise<ServiceResult<AvailablePhoneNumber[]>> {
    try {
      const twilioResult = await this.deps.twilioService.searchNumbers(params);
      
      if (!twilioResult.success || !twilioResult.data) {
        throw new ServiceError(
          'Failed to search numbers',
          'SEARCH_ERROR',
          500
        );
      }

      // Filter out already purchased numbers
      const phoneNumbers = twilioResult.data.map(n => n.phoneNumber);
      const existingNumbers = await this.deps.prisma.number.findMany({
        where: { 
          phoneNumber: { in: phoneNumbers },
          status: { not: 'RELEASED' }
        },
        select: { phoneNumber: true }
      });

      const existingSet = new Set(existingNumbers.map(n => n.phoneNumber));
      const availableNumbers = twilioResult.data.filter(
        n => !existingSet.has(n.phoneNumber)
      );

      return {
        success: true,
        data: availableNumbers
      };

    } catch (error) {
      this.deps.logger.error('Number search failed', { params, error });

      if (error instanceof ServiceError) {
        throw error;
      }

      throw new ServiceError(
        'Number search failed',
        'SEARCH_ERROR',
        500
      );
    }
  }

  async purchaseNumbers(
    userId: string,
    request: PurchaseNumbersRequest
  ): Promise<ServiceResult<PurchaseResult>> {
    const { numbers, billingInfo } = request;

    try {
      // Create order first
      const order = await this.deps.prisma.order.create({
        data: {
          orderNumber: this.generateOrderNumber(),
          userId,
          status: 'PROCESSING',
          subtotalAmount: this.calculateSubtotal(numbers),
          totalAmount: this.calculateTotal(numbers),
          currency: 'USD',
          orderSource: 'api'
        }
      });

      const results: PurchaseResult['results'] = [];
      let successCount = 0;
      let failedCount = 0;

      // Process each number purchase
      for (const numberRequest of numbers) {
        try {
          // Purchase via Twilio
          const twilioResult = await this.deps.twilioService.purchaseNumber({
            phoneNumber: numberRequest.phoneNumber,
            friendlyName: numberRequest.friendlyName,
            ...numberRequest.configuration
          });

          if (!twilioResult.success || !twilioResult.data) {
            throw new Error('Twilio purchase failed');
          }

          const purchasedNumber = twilioResult.data;

          // Save to database
          const dbNumber = await this.deps.prisma.number.create({
            data: {
              phoneNumber: purchasedNumber.phoneNumber,
              friendlyName: purchasedNumber.friendlyName,
              twilioSid: purchasedNumber.sid,
              twilioAccountSid: this.deps.twilioService.deps.config.accountSid,
              userId,
              orderId: order.id,
              countryCode: purchasedNumber.countryCode,
              numberType: this.determineNumberType(purchasedNumber.phoneNumber),
              capabilities: purchasedNumber.capabilities,
              monthlyPrice: purchasedNumber.price.monthly,
              setupPrice: purchasedNumber.price.setup,
              status: 'ACTIVE',
              voiceUrl: numberRequest.configuration?.voiceUrl,
              voiceMethod: numberRequest.configuration?.voiceMethod,
              smsUrl: numberRequest.configuration?.smsUrl,
              statusCallback: numberRequest.configuration?.statusCallback
            }
          });

          results.push({
            phoneNumber: numberRequest.phoneNumber,
            status: 'SUCCESS',
            numberId: dbNumber.id
          });

          successCount++;

          // Emit event
          this.deps.eventEmitter.emit('number.purchased', {
            userId,
            numberId: dbNumber.id,
            phoneNumber: dbNumber.phoneNumber,
            orderId: order.id
          });

        } catch (error) {
          this.deps.logger.error('Individual number purchase failed', {
            phoneNumber: numberRequest.phoneNumber,
            error: error.message
          });

          results.push({
            phoneNumber: numberRequest.phoneNumber,
            status: 'FAILED',
            error: error.message
          });

          failedCount++;
        }
      }

      // Update order status
      const finalStatus = failedCount === 0 ? 'COMPLETED' : 
                         successCount === 0 ? 'FAILED' : 'PARTIAL';

      await this.deps.prisma.order.update({
        where: { id: order.id },
        data: {
          status: finalStatus,
          completedAt: new Date()
        }
      });

      const result: PurchaseResult = {
        orderId: order.id,
        results,
        summary: {
          totalRequested: numbers.length,
          successful: successCount,
          failed: failedCount,
          pending: 0
        }
      };

      return {
        success: true,
        data: result
      };

    } catch (error) {
      this.deps.logger.error('Purchase numbers failed', { userId, request, error });

      if (error instanceof ServiceError) {
        throw error;
      }

      throw new ServiceError(
        'Purchase numbers failed',
        'PURCHASE_ERROR',
        500
      );
    }
  }

  async getUserNumbers(
    userId: string,
    filters?: NumberSearchFilters,
    pagination?: { page: number; limit: number }
  ): Promise<ServiceResult<{ numbers: Number[]; total: number }>> {
    try {
      const where: any = { userId };

      if (filters?.status?.length) {
        where.status = { in: filters.status };
      }

      if (filters?.numberType?.length) {
        where.numberType = { in: filters.numberType };
      }

      if (filters?.search) {
        where.OR = [
          { phoneNumber: { contains: filters.search } },
          { friendlyName: { contains: filters.search, mode: 'insensitive' } }
        ];
      }

      if (filters?.tags?.length) {
        where.tags = { hasSome: filters.tags };
      }

      const [numbers, total] = await Promise.all([
        this.deps.prisma.number.findMany({
          where,
          include: {
            _count: {
              select: {
                callLogs: true,
                smsLogs: true
              }
            }
          },
          orderBy: { createdAt: 'desc' },
          skip: pagination ? (pagination.page - 1) * pagination.limit : 0,
          take: pagination?.limit
        }),
        this.deps.prisma.number.count({ where })
      ]);

      return {
        success: true,
        data: { numbers, total }
      };

    } catch (error) {
      this.deps.logger.error('Get user numbers failed', { userId, filters, error });

      throw new ServiceError(
        'Failed to get user numbers',
        'GET_NUMBERS_ERROR',
        500
      );
    }
  }

  async getNumberDetails(
    numberId: string,
    userId: string
  ): Promise<ServiceResult<NumberWithDetails>> {
    try {
      const number = await this.deps.prisma.number.findFirst({
        where: { id: numberId, userId },
        include: {
          user: true,
          order: true,
          configurations: true,
          callLogs: {
            orderBy: { createdAt: 'desc' },
            take: 10
          },
          _count: {
            select: {
              callLogs: true,
              smsLogs: true
            }
          }
        }
      });

      if (!number) {
        throw new ServiceError(
          'Number not found',
          'NUMBER_NOT_FOUND',
          404
        );
      }

      // Get analytics data
      const analytics = await this.getNumberAnalytics(numberId);

      const result: NumberWithDetails = {
        ...number,
        analytics
      };

      return {
        success: true,
        data: result
      };

    } catch (error) {
      this.deps.logger.error('Get number details failed', { numberId, userId, error });

      if (error instanceof ServiceError) {
        throw error;
      }

      throw new ServiceError(
        'Failed to get number details',
        'GET_NUMBER_DETAILS_ERROR',
        500
      );
    }
  }

  async updateNumber(
    numberId: string,
    userId: string,
    updates: Partial<NumberConfiguration> & {
      friendlyName?: string;
      tags?: string[];
      notes?: string;
    }
  ): Promise<ServiceResult<void>> {
    try {
      const number = await this.deps.prisma.number.findFirst({
        where: { id: numberId, userId }
      });

      if (!number) {
        throw new ServiceError(
          'Number not found',
          'NUMBER_NOT_FOUND',
          404
        );
      }

      // Update Twilio configuration if needed
      const twilioUpdates: any = {};
      if (updates.voiceUrl !== undefined) twilioUpdates.voiceUrl = updates.voiceUrl;
      if (updates.voiceMethod !== undefined) twilioUpdates.voiceMethod = updates.voiceMethod;
      if (updates.smsUrl !== undefined) twilioUpdates.smsUrl = updates.smsUrl;
      if (updates.statusCallback !== undefined) twilioUpdates.statusCallback = updates.statusCallback;

      if (Object.keys(twilioUpdates).length > 0) {
        const twilioResult = await this.deps.twilioService.configureNumber(
          number.twilioSid,
          twilioUpdates
        );

        if (!twilioResult.success) {
          throw new ServiceError(
            'Failed to update Twilio configuration',
            'TWILIO_UPDATE_ERROR',
            500
          );
        }
      }

      // Update database
      await this.deps.prisma.number.update({
        where: { id: numberId },
        data: {
          friendlyName: updates.friendlyName,
          voiceUrl: updates.voiceUrl,
          voiceMethod: updates.voiceMethod,
          smsUrl: updates.smsUrl,
          statusCallback: updates.statusCallback,
          tags: updates.tags,
          notes: updates.notes
        }
      });

      // Emit event
      this.deps.eventEmitter.emit('number.updated', {
        userId,
        numberId,
        updates
      });

      return { success: true };

    } catch (error) {
      this.deps.logger.error('Update number failed', { numberId, userId, updates, error });

      if (error instanceof ServiceError) {
        throw error;
      }

      throw new ServiceError(
        'Failed to update number',
        'UPDATE_NUMBER_ERROR',
        500
      );
    }
  }

  async releaseNumber(
    numberId: string,
    userId: string,
    reason?: string
  ): Promise<ServiceResult<void>> {
    try {
      const number = await this.deps.prisma.number.findFirst({
        where: { id: numberId, userId }
      });

      if (!number) {
        throw new ServiceError(
          'Number not found',
          'NUMBER_NOT_FOUND',
          404
        );
      }

      if (number.status === 'RELEASED') {
        throw new ServiceError(
          'Number already released',
          'NUMBER_ALREADY_RELEASED',
          400
        );
      }

      // Release from Twilio
      const twilioResult = await this.deps.twilioService.releaseNumber(number.twilioSid);

      if (!twilioResult.success) {
        throw new ServiceError(
          'Failed to release number from Twilio',
          'TWILIO_RELEASE_ERROR',
          500
        );
      }

      // Update database
      await this.deps.prisma.number.update({
        where: { id: numberId },
        data: {
          status: 'RELEASED',
          releasedAt: new Date(),
          notes: reason ? `Released: ${reason}` : number.notes
        }
      });

      // Emit event
      this.deps.eventEmitter.emit('number.released', {
        userId,
        numberId,
        phoneNumber: number.phoneNumber,
        reason
      });

      this.deps.logger.info('Number released successfully', {
        numberId,
        phoneNumber: number.phoneNumber,
        userId,
        reason
      });

      return { success: true };

    } catch (error) {
      this.deps.logger.error('Release number failed', { numberId, userId, error });

      if (error instanceof ServiceError) {
        throw error;
      }

      throw new ServiceError(
        'Failed to release number',
        'RELEASE_NUMBER_ERROR',
        500
      );
    }
  }

  // Private helper methods
  private generateOrderNumber(): string {
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = Math.random().toString(36).substr(2, 4).toUpperCase();
    return `ORD-${timestamp}-${random}`;
  }

  private calculateSubtotal(numbers: { phoneNumber: string }[]): number {
    // This would typically calculate based on current pricing
    return numbers.length * 1.00; // $1 per number
  }

  private calculateTotal(numbers: { phoneNumber: string }[]): number {
    const subtotal = this.calculateSubtotal(numbers);
    const tax = subtotal * 0.08; // 8% tax
    return subtotal + tax;
  }

  private determineNumberType(phoneNumber: string): NumberType {
    // Simple logic to determine number type
    if (phoneNumber.startsWith('+1800') || phoneNumber.startsWith('+1888') || 
        phoneNumber.startsWith('+1877') || phoneNumber.startsWith('+1866')) {
      return 'TOLL_FREE';
    }
    
    if (phoneNumber.startsWith('+1')) {
      return 'LOCAL';
    }
    
    return 'INTERNATIONAL';
  }

  private async getNumberAnalytics(numberId: string): Promise<any> {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    
    const [callStats, smsStats] = await Promise.all([
      this.deps.prisma.callLog.aggregate({
        where: {
          numberId,
          createdAt: { gte: thirtyDaysAgo }
        },
        _count: { id: true },
        _sum: { duration: true }
      }),
      this.deps.prisma.smsLog.aggregate({
        where: {
          numberId,
          createdAt: { gte: thirtyDaysAgo }
        },
        _count: { id: true }
      })
    ]);

    return {
      last30Days: {
        calls: callStats._count.id || 0,
        minutes: Math.round((callStats._sum.duration || 0) / 60),
        sms: smsStats._count.id || 0
      }
    };
  }
}
```

This comprehensive services architecture documentation provides the foundation for implementing all core business logic in the DID buy system with proper TypeScript typing, error handling, and separation of concerns.
