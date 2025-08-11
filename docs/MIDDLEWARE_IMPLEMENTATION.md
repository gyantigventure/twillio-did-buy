# Middleware Implementation - TypeScript Guide

## 1. Overview

This document provides comprehensive middleware implementations for the DID buy system, including authentication, validation, rate limiting, error handling, logging, and security middleware with complete TypeScript implementations.

## 2. Middleware Architecture

### 2.1 Base Middleware Interface

```typescript
// src/types/middleware.types.ts
import { Request, Response, NextFunction } from 'express';

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
  session?: SessionInfo;
  requestId: string;
  startTime: number;
}

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: UserRole;
  permissions: string[];
  isActive: boolean;
}

export interface SessionInfo {
  id: string;
  userId: string;
  expiresAt: Date;
  deviceInfo?: DeviceInfo;
}

export interface MiddlewareContext {
  prisma: PrismaClient;
  redis: Redis;
  logger: Logger;
  config: AppConfig;
}

export type MiddlewareFunction = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => Promise<void> | void;

export interface MiddlewareOptions {
  skipPaths?: string[];
  skipMethods?: string[];
  enableCaching?: boolean;
  cacheTimeout?: number;
}
```

### 2.2 Middleware Factory Pattern

```typescript
// src/middleware/factory/middleware.factory.ts
export class MiddlewareFactory {
  constructor(private context: MiddlewareContext) {}

  createAuthMiddleware(options?: AuthMiddlewareOptions): MiddlewareFunction {
    return new AuthenticationMiddleware(this.context, options).handle.bind(
      new AuthenticationMiddleware(this.context, options)
    );
  }

  createValidationMiddleware(schema: ZodSchema): MiddlewareFunction {
    return new ValidationMiddleware(this.context, schema).handle.bind(
      new ValidationMiddleware(this.context, schema)
    );
  }

  createRateLimitMiddleware(options: RateLimitOptions): MiddlewareFunction {
    return new RateLimitMiddleware(this.context, options).handle.bind(
      new RateLimitMiddleware(this.context, options)
    );
  }

  createPermissionMiddleware(
    resource: string,
    action: string
  ): MiddlewareFunction {
    return new PermissionMiddleware(this.context, resource, action).handle.bind(
      new PermissionMiddleware(this.context, resource, action)
    );
  }

  createLoggingMiddleware(options?: LoggingOptions): MiddlewareFunction {
    return new RequestLoggingMiddleware(this.context, options).handle.bind(
      new RequestLoggingMiddleware(this.context, options)
    );
  }
}

export abstract class BaseMiddleware {
  constructor(protected context: MiddlewareContext) {}

  abstract handle(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> | void;

  protected shouldSkip(
    req: AuthenticatedRequest,
    options?: MiddlewareOptions
  ): boolean {
    if (!options) return false;

    if (options.skipPaths?.some(path => req.path.startsWith(path))) {
      return true;
    }

    if (options.skipMethods?.includes(req.method)) {
      return true;
    }

    return false;
  }

  protected sendError(res: Response, statusCode: number, message: string, details?: any): void {
    res.status(statusCode).json({
      success: false,
      error: {
        message,
        details,
        timestamp: new Date().toISOString()
      }
    });
  }
}
```

## 3. Authentication Middleware

### 3.1 JWT Authentication Middleware

```typescript
// src/middleware/auth/authentication.middleware.ts
import jwt from 'jsonwebtoken';
import { AuthenticationMiddleware as BaseAuth } from './base-auth.middleware';

export interface AuthMiddlewareOptions extends MiddlewareOptions {
  requireAuth?: boolean;
  allowApiKey?: boolean;
  allowRefreshToken?: boolean;
  validateSession?: boolean;
  extendSession?: boolean;
}

export class AuthenticationMiddleware extends BaseMiddleware {
  constructor(
    context: MiddlewareContext,
    private options: AuthMiddlewareOptions = {}
  ) {
    super(context);
  }

  async handle(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      // Skip authentication for certain paths
      if (this.shouldSkip(req, this.options)) {
        return next();
      }

      // Extract token from request
      const token = this.extractToken(req);
      
      if (!token) {
        if (this.options.requireAuth !== false) {
          return this.sendError(res, 401, 'Authentication token required');
        }
        return next();
      }

      // Determine token type and validate
      const tokenType = this.determineTokenType(req, token);
      let user: AuthenticatedUser;

      switch (tokenType) {
        case 'bearer':
          user = await this.validateBearerToken(token);
          break;
        case 'api_key':
          if (!this.options.allowApiKey) {
            return this.sendError(res, 401, 'API key authentication not allowed');
          }
          user = await this.validateApiKey(token);
          break;
        case 'refresh':
          if (!this.options.allowRefreshToken) {
            return this.sendError(res, 401, 'Refresh token not allowed');
          }
          user = await this.validateRefreshToken(token);
          break;
        default:
          return this.sendError(res, 401, 'Invalid token type');
      }

      // Validate session if required
      if (this.options.validateSession) {
        const session = await this.validateUserSession(user.id, req);
        if (!session) {
          return this.sendError(res, 401, 'Invalid session');
        }
        req.session = session;

        // Extend session if configured
        if (this.options.extendSession) {
          await this.extendUserSession(session.id);
        }
      }

      // Attach user to request
      req.user = user;

      // Log authentication success
      this.context.logger.debug('Authentication successful', {
        userId: user.id,
        email: user.email,
        role: user.role,
        path: req.path,
        method: req.method,
        requestId: req.requestId
      });

      next();

    } catch (error) {
      this.context.logger.error('Authentication failed', {
        error: error.message,
        path: req.path,
        method: req.method,
        requestId: req.requestId
      });

      if (error instanceof jwt.JsonWebTokenError) {
        return this.sendError(res, 401, 'Invalid token');
      }

      if (error instanceof jwt.TokenExpiredError) {
        return this.sendError(res, 401, 'Token expired');
      }

      return this.sendError(res, 500, 'Authentication error');
    }
  }

  private extractToken(req: AuthenticatedRequest): string | null {
    // Check Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    // Check API key header
    const apiKey = req.headers['x-api-key'] as string;
    if (apiKey) {
      return apiKey;
    }

    // Check query parameter (for webhooks)
    const queryToken = req.query.token as string;
    if (queryToken) {
      return queryToken;
    }

    return null;
  }

  private determineTokenType(req: AuthenticatedRequest, token: string): string {
    if (req.headers.authorization?.startsWith('Bearer ')) {
      return 'bearer';
    }

    if (req.headers['x-api-key']) {
      return 'api_key';
    }

    if (req.query.token) {
      return 'refresh';
    }

    return 'bearer'; // Default
  }

  private async validateBearerToken(token: string): Promise<AuthenticatedUser> {
    try {
      const payload = jwt.verify(token, this.context.config.jwt.secret) as any;
      
      if (payload.type !== 'access') {
        throw new Error('Invalid token type');
      }

      // Check if token is blacklisted
      const isBlacklisted = await this.context.redis.exists(`blacklisted_token:${this.hashToken(token)}`);
      if (isBlacklisted) {
        throw new Error('Token has been revoked');
      }

      // Get user from database
      const user = await this.context.prisma.user.findUnique({
        where: { id: payload.userId },
        select: {
          id: true,
          email: true,
          role: true,
          isActive: true,
          isSuspended: true
        }
      });

      if (!user || !user.isActive || user.isSuspended) {
        throw new Error('User not found or inactive');
      }

      return {
        id: user.id,
        email: user.email,
        role: user.role,
        permissions: payload.permissions || [],
        isActive: user.isActive
      };

    } catch (error) {
      throw error;
    }
  }

  private async validateApiKey(apiKey: string): Promise<AuthenticatedUser> {
    const keyHash = this.hashToken(apiKey);
    
    const dbApiKey = await this.context.prisma.apiKey.findUnique({
      where: { keyHash },
      include: { user: true }
    });

    if (!dbApiKey || !dbApiKey.isActive) {
      throw new Error('Invalid API key');
    }

    if (dbApiKey.expiresAt && dbApiKey.expiresAt < new Date()) {
      throw new Error('API key expired');
    }

    if (!dbApiKey.user.isActive || dbApiKey.user.isSuspended) {
      throw new Error('User account inactive');
    }

    // Update usage tracking
    await this.context.prisma.apiKey.update({
      where: { id: dbApiKey.id },
      data: {
        lastUsedAt: new Date(),
        usageCount: { increment: 1 }
      }
    });

    return {
      id: dbApiKey.user.id,
      email: dbApiKey.user.email,
      role: dbApiKey.user.role,
      permissions: dbApiKey.permissions,
      isActive: dbApiKey.user.isActive
    };
  }

  private async validateRefreshToken(token: string): Promise<AuthenticatedUser> {
    const payload = jwt.verify(token, this.context.config.jwt.refreshSecret) as any;
    
    if (payload.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    const session = await this.context.prisma.session.findUnique({
      where: { refreshToken: token },
      include: { user: true }
    });

    if (!session || session.isRevoked || session.expiresAt < new Date()) {
      throw new Error('Invalid refresh token');
    }

    return {
      id: session.user.id,
      email: session.user.email,
      role: session.user.role,
      permissions: [], // Would need to fetch from user role
      isActive: session.user.isActive
    };
  }

  private async validateUserSession(
    userId: string,
    req: AuthenticatedRequest
  ): Promise<SessionInfo | null> {
    // Get session from JWT payload if available
    const authHeader = req.headers.authorization;
    if (!authHeader) return null;

    try {
      const token = authHeader.substring(7);
      const payload = jwt.decode(token) as any;
      
      if (!payload.sessionId) return null;

      const session = await this.context.prisma.session.findUnique({
        where: { id: payload.sessionId }
      });

      if (!session || session.isRevoked || session.expiresAt < new Date()) {
        return null;
      }

      return {
        id: session.id,
        userId: session.userId,
        expiresAt: session.expiresAt,
        deviceInfo: session.deviceInfo ? JSON.parse(session.deviceInfo) : undefined
      };

    } catch (error) {
      return null;
    }
  }

  private async extendUserSession(sessionId: string): Promise<void> {
    try {
      const newExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
      
      await this.context.prisma.session.update({
        where: { id: sessionId },
        data: { expiresAt: newExpiresAt }
      });
    } catch (error) {
      this.context.logger.warn('Failed to extend session', { sessionId, error });
    }
  }

  private hashToken(token: string): string {
    return require('crypto').createHash('sha256').update(token).digest('hex');
  }
}
```

### 3.2 Permission Middleware

```typescript
// src/middleware/auth/permission.middleware.ts
export class PermissionMiddleware extends BaseMiddleware {
  constructor(
    context: MiddlewareContext,
    private resource: string,
    private action: string,
    private options: PermissionMiddlewareOptions = {}
  ) {
    super(context);
  }

  async handle(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      if (!req.user) {
        return this.sendError(res, 401, 'Authentication required');
      }

      // Check permission
      const hasPermission = await this.checkUserPermission(
        req.user,
        this.resource,
        this.action,
        req
      );

      if (!hasPermission) {
        this.context.logger.warn('Permission denied', {
          userId: req.user.id,
          resource: this.resource,
          action: this.action,
          path: req.path,
          method: req.method
        });

        return this.sendError(res, 403, 'Insufficient permissions', {
          resource: this.resource,
          action: this.action,
          userRole: req.user.role
        });
      }

      next();

    } catch (error) {
      this.context.logger.error('Permission check failed', {
        error: error.message,
        userId: req.user?.id,
        resource: this.resource,
        action: this.action
      });

      return this.sendError(res, 500, 'Permission check error');
    }
  }

  private async checkUserPermission(
    user: AuthenticatedUser,
    resource: string,
    action: string,
    req: AuthenticatedRequest
  ): Promise<boolean> {
    // Check explicit permissions first
    const permissionString = `${resource}:${action}`;
    if (user.permissions.includes(permissionString) || user.permissions.includes('*:*')) {
      return true;
    }

    // Check wildcard permissions
    if (user.permissions.includes(`${resource}:*`) || user.permissions.includes(`*:${action}`)) {
      return true;
    }

    // Check resource-specific context permissions
    const context = this.buildPermissionContext(req);
    
    // For own resources, check if user owns the resource
    if (this.isOwnResourcePermission(user.permissions, resource, action)) {
      return this.checkResourceOwnership(user.id, resource, req, context);
    }

    // Check role-based permissions
    return this.checkRolePermission(user.role, resource, action);
  }

  private buildPermissionContext(req: AuthenticatedRequest): Record<string, any> {
    return {
      userId: req.user?.id,
      params: req.params,
      query: req.query,
      body: req.body,
      path: req.path,
      method: req.method
    };
  }

  private isOwnResourcePermission(permissions: string[], resource: string, action: string): boolean {
    const ownPermissions = [
      `own_${resource}:${action}`,
      `${resource}:own_${action}`,
      `read:own_${resource}`,
      `write:own_${resource}`
    ];

    return ownPermissions.some(perm => permissions.includes(perm));
  }

  private async checkResourceOwnership(
    userId: string,
    resource: string,
    req: AuthenticatedRequest,
    context: Record<string, any>
  ): Promise<boolean> {
    try {
      // Resource ownership checks
      switch (resource) {
        case 'number':
          return this.checkNumberOwnership(userId, req);
        case 'order':
          return this.checkOrderOwnership(userId, req);
        case 'billing':
          return this.checkBillingOwnership(userId, req);
        case 'profile':
          return this.checkProfileOwnership(userId, req);
        default:
          return false;
      }
    } catch (error) {
      this.context.logger.error('Resource ownership check failed', {
        userId,
        resource,
        error
      });
      return false;
    }
  }

  private async checkNumberOwnership(userId: string, req: AuthenticatedRequest): Promise<boolean> {
    const numberId = req.params.id || req.params.numberId;
    if (!numberId) return false;

    const number = await this.context.prisma.number.findFirst({
      where: { id: numberId, userId },
      select: { id: true }
    });

    return !!number;
  }

  private async checkOrderOwnership(userId: string, req: AuthenticatedRequest): Promise<boolean> {
    const orderId = req.params.id || req.params.orderId;
    if (!orderId) return false;

    const order = await this.context.prisma.order.findFirst({
      where: { id: orderId, userId },
      select: { id: true }
    });

    return !!order;
  }

  private async checkBillingOwnership(userId: string, req: AuthenticatedRequest): Promise<boolean> {
    // For billing, user can only access their own billing account
    const billingAccount = await this.context.prisma.billingAccount.findUnique({
      where: { userId },
      select: { id: true }
    });

    return !!billingAccount;
  }

  private async checkProfileOwnership(userId: string, req: AuthenticatedRequest): Promise<boolean> {
    const profileUserId = req.params.id || req.params.userId;
    return !profileUserId || profileUserId === userId;
  }

  private checkRolePermission(role: UserRole, resource: string, action: string): boolean {
    const rolePermissions = {
      [UserRole.SUPER_ADMIN]: () => true,
      [UserRole.ADMIN]: () => {
        // Admins can access most resources except super admin functions
        const restrictedResources = ['system', 'admin_user'];
        return !restrictedResources.includes(resource);
      },
      [UserRole.USER]: () => {
        // Users can only access their own resources
        const allowedResources = ['number', 'order', 'billing', 'profile'];
        return allowedResources.includes(resource) && action !== 'admin';
      },
      [UserRole.DEVELOPER]: () => {
        // Developers have similar access to users plus API management
        const allowedResources = ['number', 'order', 'billing', 'profile', 'webhook', 'api_key'];
        return allowedResources.includes(resource) && action !== 'admin';
      },
      [UserRole.SUPPORT]: () => {
        // Support can read most resources but not modify
        return action === 'read';
      }
    };

    const checkFunction = rolePermissions[role];
    return checkFunction ? checkFunction() : false;
  }
}

interface PermissionMiddlewareOptions extends MiddlewareOptions {
  requireOwnership?: boolean;
  allowRoleOverride?: boolean;
}
```

## 4. Validation Middleware

### 4.1 Request Validation Middleware

```typescript
// src/middleware/validation/validation.middleware.ts
import { z, ZodSchema, ZodError } from 'zod';

export interface ValidationOptions {
  validateBody?: boolean;
  validateQuery?: boolean;
  validateParams?: boolean;
  validateHeaders?: boolean;
  allowUnknown?: boolean;
  stripUnknown?: boolean;
  coerceTypes?: boolean;
}

export class ValidationMiddleware extends BaseMiddleware {
  constructor(
    context: MiddlewareContext,
    private schemas: {
      body?: ZodSchema;
      query?: ZodSchema;
      params?: ZodSchema;
      headers?: ZodSchema;
    },
    private options: ValidationOptions = {}
  ) {
    super(context);
  }

  async handle(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const validationResults: Record<string, any> = {};

      // Validate request body
      if (this.schemas.body && (this.options.validateBody !== false)) {
        validationResults.body = await this.validateData(
          req.body,
          this.schemas.body,
          'body'
        );
        req.body = validationResults.body;
      }

      // Validate query parameters
      if (this.schemas.query && (this.options.validateQuery !== false)) {
        validationResults.query = await this.validateData(
          req.query,
          this.schemas.query,
          'query'
        );
        req.query = validationResults.query;
      }

      // Validate route parameters
      if (this.schemas.params && (this.options.validateParams !== false)) {
        validationResults.params = await this.validateData(
          req.params,
          this.schemas.params,
          'params'
        );
        req.params = validationResults.params;
      }

      // Validate headers
      if (this.schemas.headers && (this.options.validateHeaders !== false)) {
        validationResults.headers = await this.validateData(
          req.headers,
          this.schemas.headers,
          'headers'
        );
      }

      this.context.logger.debug('Request validation successful', {
        path: req.path,
        method: req.method,
        validatedFields: Object.keys(validationResults)
      });

      next();

    } catch (error) {
      this.context.logger.warn('Request validation failed', {
        path: req.path,
        method: req.method,
        error: error.message,
        validationErrors: error instanceof ZodError ? error.errors : undefined
      });

      if (error instanceof ZodError) {
        return this.sendValidationError(res, error);
      }

      return this.sendError(res, 400, 'Validation error');
    }
  }

  private async validateData(
    data: any,
    schema: ZodSchema,
    fieldName: string
  ): Promise<any> {
    try {
      if (this.options.coerceTypes) {
        // Pre-process data for type coercion
        data = this.coerceDataTypes(data);
      }

      const result = await schema.parseAsync(data);

      if (this.options.stripUnknown) {
        return this.stripUnknownFields(result, schema);
      }

      return result;

    } catch (error) {
      if (error instanceof ZodError) {
        // Enhance error messages with field context
        const enhancedErrors = error.errors.map(err => ({
          ...err,
          path: [fieldName, ...err.path],
          message: `${fieldName}.${err.path.join('.')}: ${err.message}`
        }));
        
        throw new ZodError(enhancedErrors);
      }
      throw error;
    }
  }

  private coerceDataTypes(data: any): any {
    if (typeof data !== 'object' || data === null) {
      return data;
    }

    const coerced = Array.isArray(data) ? [] : {};

    for (const [key, value] of Object.entries(data)) {
      if (typeof value === 'string') {
        // Try to coerce string values
        if (value === 'true') {
          coerced[key] = true;
        } else if (value === 'false') {
          coerced[key] = false;
        } else if (value === 'null') {
          coerced[key] = null;
        } else if (value === 'undefined') {
          coerced[key] = undefined;
        } else if (!isNaN(Number(value)) && value.trim() !== '') {
          coerced[key] = Number(value);
        } else {
          coerced[key] = value;
        }
      } else if (typeof value === 'object') {
        coerced[key] = this.coerceDataTypes(value);
      } else {
        coerced[key] = value;
      }
    }

    return coerced;
  }

  private stripUnknownFields(data: any, schema: ZodSchema): any {
    // This would need to be implemented based on the schema structure
    // For now, return data as-is since Zod already strips unknown fields by default
    return data;
  }

  private sendValidationError(res: Response, error: ZodError): void {
    const formattedErrors = error.errors.map(err => ({
      field: err.path.join('.'),
      message: err.message,
      code: err.code,
      received: err.received
    }));

    res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        type: 'VALIDATION_ERROR',
        details: formattedErrors
      },
      meta: {
        timestamp: new Date().toISOString()
      }
    });
  }
}

// Validation Schema Factory
export class ValidationSchemaFactory {
  static createNumberSearchSchema(): ZodSchema {
    return z.object({
      countryCode: z.string().length(2, 'Country code must be 2 characters'),
      areaCode: z.string().regex(/^\d{3}$/, 'Area code must be 3 digits').optional(),
      contains: z.string().min(1).max(10).optional(),
      nearLatLong: z.string().regex(/^-?\d+\.?\d*,-?\d+\.?\d*$/).optional(),
      distance: z.number().min(1).max(500).optional(),
      numberType: z.enum(['local', 'tollFree', 'mobile']).optional(),
      limit: z.number().min(1).max(100).default(20)
    });
  }

  static createNumberPurchaseSchema(): ZodSchema {
    return z.object({
      numbers: z.array(z.object({
        phoneNumber: z.string().regex(/^\+[1-9]\d{1,14}$/, 'Invalid phone number format'),
        friendlyName: z.string().max(100).optional(),
        configuration: z.object({
          voiceUrl: z.string().url().optional(),
          voiceMethod: z.enum(['GET', 'POST']).default('POST'),
          smsUrl: z.string().url().optional(),
          statusCallback: z.string().url().optional()
        }).optional()
      })).min(1).max(10),
      billingInfo: z.object({
        paymentMethodId: z.string().optional(),
        promoCode: z.string().optional()
      }).optional()
    });
  }

  static createUserRegistrationSchema(): ZodSchema {
    return z.object({
      email: z.string().email('Invalid email format'),
      password: z.string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain uppercase, lowercase, and number'),
      firstName: z.string().min(1, 'First name is required').max(50),
      lastName: z.string().min(1, 'Last name is required').max(50),
      company: z.string().max(100).optional(),
      phone: z.string().regex(/^\+[1-9]\d{1,14}$/).optional(),
      acceptTerms: z.boolean().refine(val => val === true, 'Terms must be accepted')
    });
  }

  static createPaginationSchema(): ZodSchema {
    return z.object({
      page: z.number().min(1).default(1),
      limit: z.number().min(1).max(100).default(20),
      sortBy: z.string().optional(),
      sortOrder: z.enum(['asc', 'desc']).default('desc')
    });
  }
}
```

## 5. Rate Limiting Middleware

### 5.1 Advanced Rate Limiting

```typescript
// src/middleware/rate-limit/rate-limit.middleware.ts
export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  keyGenerator?: (req: AuthenticatedRequest) => string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  skipIf?: (req: AuthenticatedRequest) => boolean;
  onLimitReached?: (req: AuthenticatedRequest, res: Response) => void;
  store?: RateLimitStore;
  headers?: boolean;
  message?: string;
  standardHeaders?: boolean;
  legacyHeaders?: boolean;
}

export interface RateLimitStore {
  incr(key: string): Promise<{ totalHits: number; timeToExpire: number }>;
  decrement(key: string): Promise<void>;
  resetKey(key: string): Promise<void>;
}

export class RedisRateLimitStore implements RateLimitStore {
  constructor(private redis: Redis) {}

  async incr(key: string): Promise<{ totalHits: number; timeToExpire: number }> {
    const pipeline = this.redis.pipeline();
    pipeline.incr(key);
    pipeline.ttl(key);
    
    const results = await pipeline.exec();
    const totalHits = results[0][1] as number;
    const ttl = results[1][1] as number;

    // Set expiry if this is the first request
    if (totalHits === 1 && ttl === -1) {
      await this.redis.expire(key, Math.floor(300)); // 5 minutes default
    }

    return {
      totalHits,
      timeToExpire: ttl > 0 ? ttl * 1000 : 0
    };
  }

  async decrement(key: string): Promise<void> {
    await this.redis.decr(key);
  }

  async resetKey(key: string): Promise<void> {
    await this.redis.del(key);
  }
}

export class RateLimitMiddleware extends BaseMiddleware {
  private store: RateLimitStore;

  constructor(
    context: MiddlewareContext,
    private options: RateLimitOptions
  ) {
    super(context);
    this.store = options.store || new RedisRateLimitStore(context.redis);
  }

  async handle(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      // Skip if condition is met
      if (this.options.skipIf && this.options.skipIf(req)) {
        return next();
      }

      // Generate rate limit key
      const key = this.generateKey(req);
      
      // Get current usage
      const { totalHits, timeToExpire } = await this.store.incr(key);
      
      // Calculate remaining requests
      const remaining = Math.max(0, this.options.maxRequests - totalHits);
      
      // Set headers if enabled
      if (this.options.headers !== false) {
        this.setRateLimitHeaders(res, totalHits, remaining, timeToExpire);
      }

      // Check if limit exceeded
      if (totalHits > this.options.maxRequests) {
        this.context.logger.warn('Rate limit exceeded', {
          key,
          totalHits,
          maxRequests: this.options.maxRequests,
          userId: req.user?.id,
          ip: req.ip,
          path: req.path
        });

        // Call custom handler if provided
        if (this.options.onLimitReached) {
          this.options.onLimitReached(req, res);
        }

        return this.sendRateLimitError(res, timeToExpire);
      }

      // Log successful request
      this.context.logger.debug('Rate limit check passed', {
        key,
        totalHits,
        remaining,
        userId: req.user?.id
      });

      next();

    } catch (error) {
      this.context.logger.error('Rate limiting error', {
        error: error.message,
        path: req.path,
        userId: req.user?.id
      });

      // On error, allow request to proceed
      next();
    }
  }

  private generateKey(req: AuthenticatedRequest): string {
    if (this.options.keyGenerator) {
      return this.options.keyGenerator(req);
    }

    // Default key generation strategy
    const identifier = req.user?.id || req.ip || 'anonymous';
    const endpoint = req.route?.path || req.path;
    
    return `rate_limit:${identifier}:${endpoint}`;
  }

  private setRateLimitHeaders(
    res: Response,
    totalHits: number,
    remaining: number,
    timeToExpire: number
  ): void {
    if (this.options.standardHeaders !== false) {
      res.set({
        'RateLimit-Limit': this.options.maxRequests.toString(),
        'RateLimit-Remaining': remaining.toString(),
        'RateLimit-Reset': new Date(Date.now() + timeToExpire).toISOString()
      });
    }

    if (this.options.legacyHeaders !== false) {
      res.set({
        'X-RateLimit-Limit': this.options.maxRequests.toString(),
        'X-RateLimit-Remaining': remaining.toString(),
        'X-RateLimit-Reset': Math.ceil((Date.now() + timeToExpire) / 1000).toString()
      });
    }
  }

  private sendRateLimitError(res: Response, timeToExpire: number): void {
    const resetTime = new Date(Date.now() + timeToExpire);
    
    res.status(429).json({
      success: false,
      error: {
        message: this.options.message || 'Too many requests',
        type: 'RATE_LIMIT_EXCEEDED',
        details: {
          limit: this.options.maxRequests,
          windowMs: this.options.windowMs,
          resetTime: resetTime.toISOString()
        }
      },
      meta: {
        timestamp: new Date().toISOString()
      }
    });
  }
}

// Rate limit configuration factory
export class RateLimitFactory {
  static createDefaultLimits(redis: Redis): Record<string, RateLimitOptions> {
    const store = new RedisRateLimitStore(redis);
    
    return {
      default: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        maxRequests: 1000,
        store,
        keyGenerator: (req) => `default:${req.user?.id || req.ip}`
      },
      
      auth: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        maxRequests: 5,
        store,
        keyGenerator: (req) => `auth:${req.ip}`,
        message: 'Too many authentication attempts'
      },
      
      search: {
        windowMs: 60 * 1000, // 1 minute
        maxRequests: 30,
        store,
        keyGenerator: (req) => `search:${req.user?.id || req.ip}`
      },
      
      purchase: {
        windowMs: 60 * 1000, // 1 minute
        maxRequests: 5,
        store,
        keyGenerator: (req) => `purchase:${req.user?.id || req.ip}`,
        message: 'Too many purchase attempts'
      },
      
      api: {
        windowMs: 60 * 1000, // 1 minute
        maxRequests: 100,
        store,
        keyGenerator: (req) => `api:${req.user?.id || req.ip}`,
        skipIf: (req) => req.user?.role === 'SUPER_ADMIN'
      }
    };
  }
}
```

## 6. Request Logging Middleware

### 6.1 Comprehensive Request Logging

```typescript
// src/middleware/logging/request-logging.middleware.ts
export interface LoggingOptions {
  logRequest?: boolean;
  logResponse?: boolean;
  logHeaders?: boolean;
  logBody?: boolean;
  logQuery?: boolean;
  excludePaths?: string[];
  excludeHeaders?: string[];
  maxBodySize?: number;
  sensitiveFields?: string[];
  includeUserInfo?: boolean;
  includePerformance?: boolean;
}

export class RequestLoggingMiddleware extends BaseMiddleware {
  constructor(
    context: MiddlewareContext,
    private options: LoggingOptions = {}
  ) {
    super(context);
  }

  async handle(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    // Skip logging for excluded paths
    if (this.shouldSkipLogging(req)) {
      return next();
    }

    // Generate request ID if not present
    req.requestId = req.requestId || this.generateRequestId();
    req.startTime = Date.now();

    // Add request ID to response headers
    res.set('X-Request-ID', req.requestId);

    // Log incoming request
    if (this.options.logRequest !== false) {
      this.logRequest(req);
    }

    // Capture response details
    const originalSend = res.send.bind(res);
    let responseBody: any;

    res.send = function(body: any) {
      responseBody = body;
      return originalSend(body);
    };

    // Log response when finished
    res.on('finish', () => {
      if (this.options.logResponse !== false) {
        this.logResponse(req, res, responseBody);
      }
    });

    next();
  }

  private shouldSkipLogging(req: AuthenticatedRequest): boolean {
    if (!this.options.excludePaths) return false;
    
    return this.options.excludePaths.some(path => 
      req.path.startsWith(path)
    );
  }

  private logRequest(req: AuthenticatedRequest): void {
    const logData: any = {
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      url: req.url,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    };

    // Add user information if available
    if (this.options.includeUserInfo && req.user) {
      logData.user = {
        id: req.user.id,
        email: req.user.email,
        role: req.user.role
      };
    }

    // Add headers if enabled
    if (this.options.logHeaders) {
      logData.headers = this.sanitizeHeaders(req.headers);
    }

    // Add query parameters if enabled
    if (this.options.logQuery && Object.keys(req.query).length > 0) {
      logData.query = req.query;
    }

    // Add request body if enabled
    if (this.options.logBody && req.body) {
      logData.body = this.sanitizeBody(req.body);
    }

    this.context.logger.info('Incoming request', logData);
  }

  private logResponse(
    req: AuthenticatedRequest,
    res: Response,
    responseBody: any
  ): void {
    const duration = Date.now() - req.startTime;
    
    const logData: any = {
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration,
      timestamp: new Date().toISOString()
    };

    // Add user information
    if (this.options.includeUserInfo && req.user) {
      logData.userId = req.user.id;
    }

    // Add performance metrics
    if (this.options.includePerformance) {
      logData.performance = {
        duration,
        slow: duration > 5000, // 5 seconds
        memory: process.memoryUsage()
      };
    }

    // Add response body if enabled and response is not too large
    if (this.options.logResponse && responseBody) {
      const bodySize = Buffer.byteLength(JSON.stringify(responseBody));
      const maxSize = this.options.maxBodySize || 10000; // 10KB default
      
      if (bodySize <= maxSize) {
        logData.responseBody = this.sanitizeBody(responseBody);
      } else {
        logData.responseBodySize = bodySize;
        logData.responseBodyTruncated = true;
      }
    }

    // Determine log level based on status code and duration
    const logLevel = this.getLogLevel(res.statusCode, duration);
    
    this.context.logger[logLevel](`Request completed`, logData);
  }

  private sanitizeHeaders(headers: any): any {
    const excludeHeaders = [
      'authorization',
      'cookie',
      'x-api-key',
      ...(this.options.excludeHeaders || [])
    ];

    const sanitized = { ...headers };
    
    excludeHeaders.forEach(header => {
      if (sanitized[header]) {
        sanitized[header] = '[REDACTED]';
      }
    });

    return sanitized;
  }

  private sanitizeBody(body: any): any {
    if (!body || typeof body !== 'object') {
      return body;
    }

    const sensitiveFields = [
      'password',
      'token',
      'secret',
      'key',
      'authorization',
      'creditCard',
      'ssn',
      ...(this.options.sensitiveFields || [])
    ];

    const sanitized = JSON.parse(JSON.stringify(body));
    
    this.recursiveSanitize(sanitized, sensitiveFields);
    
    return sanitized;
  }

  private recursiveSanitize(obj: any, sensitiveFields: string[]): void {
    if (!obj || typeof obj !== 'object') return;

    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();
      
      if (sensitiveFields.some(field => lowerKey.includes(field.toLowerCase()))) {
        obj[key] = '[REDACTED]';
      } else if (typeof value === 'object') {
        this.recursiveSanitize(value, sensitiveFields);
      }
    }
  }

  private getLogLevel(statusCode: number, duration: number): string {
    if (statusCode >= 500) return 'error';
    if (statusCode >= 400) return 'warn';
    if (duration > 10000) return 'warn'; // 10 seconds
    return 'info';
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
```

## 7. Error Handling Middleware

### 7.1 Global Error Handler

```typescript
// src/middleware/error/error-handler.middleware.ts
export class ErrorHandlerMiddleware {
  constructor(private context: MiddlewareContext) {}

  handle(
    error: Error,
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): void {
    // Log error with context
    this.context.logger.error('Unhandled error', {
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack
      },
      request: {
        id: req.requestId,
        method: req.method,
        path: req.path,
        userId: req.user?.id,
        ip: req.ip
      }
    });

    // Determine error type and response
    const errorResponse = this.buildErrorResponse(error, req);
    
    res.status(errorResponse.statusCode).json({
      success: false,
      error: errorResponse.error,
      meta: {
        requestId: req.requestId,
        timestamp: new Date().toISOString()
      }
    });
  }

  private buildErrorResponse(error: Error, req: AuthenticatedRequest) {
    // Handle known error types
    if (error instanceof ValidationError) {
      return {
        statusCode: 400,
        error: {
          message: error.message,
          type: 'VALIDATION_ERROR',
          details: error.details
        }
      };
    }

    if (error instanceof AuthenticationError) {
      return {
        statusCode: 401,
        error: {
          message: error.message,
          type: 'AUTHENTICATION_ERROR'
        }
      };
    }

    if (error instanceof AuthorizationError) {
      return {
        statusCode: 403,
        error: {
          message: error.message,
          type: 'AUTHORIZATION_ERROR'
        }
      };
    }

    if (error instanceof NotFoundError) {
      return {
        statusCode: 404,
        error: {
          message: error.message,
          type: 'NOT_FOUND_ERROR'
        }
      };
    }

    if (error instanceof TwilioServiceError) {
      return {
        statusCode: error.statusCode || 500,
        error: {
          message: error.message,
          type: 'TWILIO_SERVICE_ERROR',
          code: error.code
        }
      };
    }

    // Handle generic errors
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    return {
      statusCode: 500,
      error: {
        message: isDevelopment ? error.message : 'Internal server error',
        type: 'INTERNAL_ERROR',
        ...(isDevelopment && { stack: error.stack })
      }
    };
  }
}

// Custom error classes
export class ValidationError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends Error {
  constructor(message: string = 'Authentication required') {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends Error {
  constructor(message: string = 'Insufficient permissions') {
    super(message);
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends Error {
  constructor(message: string = 'Resource not found') {
    super(message);
    this.name = 'NotFoundError';
  }
}
```

This comprehensive middleware implementation provides a complete foundation for request processing, security, validation, and monitoring in the DID buy system with full TypeScript support and enterprise-grade features.
