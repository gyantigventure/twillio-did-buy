# Authentication System - TypeScript Implementation

## 1. Overview

This document provides comprehensive documentation for the authentication and authorization system in the DID buy platform, including JWT implementation, session management, role-based access control, and security best practices.

## 2. Authentication Architecture

### 2.1 Core Components

```typescript
// src/types/auth.types.ts
export interface AuthenticationSystem {
  tokenManager: TokenManager;
  sessionManager: SessionManager;
  permissionSystem: PermissionSystem;
  securityService: SecurityService;
}

export interface TokenManager {
  generateTokens(userId: string): Promise<TokenPair>;
  validateToken(token: string, type: TokenType): Promise<TokenPayload>;
  refreshTokens(refreshToken: string): Promise<TokenPair>;
  revokeToken(token: string): Promise<void>;
}

export interface SessionManager {
  createSession(userId: string, sessionData: SessionData): Promise<Session>;
  validateSession(sessionId: string): Promise<Session | null>;
  extendSession(sessionId: string): Promise<void>;
  revokeSession(sessionId: string): Promise<void>;
  revokeSessions(userId: string, excludeSessionId?: string): Promise<void>;
}

export interface PermissionSystem {
  checkPermission(userId: string, resource: string, action: string): Promise<boolean>;
  checkRole(userId: string, requiredRole: UserRole): Promise<boolean>;
  getUserPermissions(userId: string): Promise<Permission[]>;
  assignRole(userId: string, role: UserRole): Promise<void>;
}

export enum TokenType {
  ACCESS = 'access',
  REFRESH = 'refresh',
  EMAIL_VERIFICATION = 'email_verification',
  PASSWORD_RESET = 'password_reset',
  API_KEY = 'api_key'
}

export interface TokenPayload {
  userId: string;
  type: TokenType;
  iat: number;
  exp: number;
  permissions?: string[];
  sessionId?: string;
}

export interface SessionData {
  deviceInfo?: DeviceInfo;
  ipAddress?: string;
  userAgent?: string;
  location?: GeoLocation;
}

export interface Permission {
  id: string;
  resource: string;
  action: string;
  conditions?: PermissionCondition[];
}

export interface PermissionCondition {
  field: string;
  operator: 'eq' | 'ne' | 'in' | 'nin' | 'gt' | 'lt' | 'gte' | 'lte';
  value: any;
}
```

### 2.2 JWT Token Implementation

```typescript
// src/services/token.service.ts
import jwt from 'jsonwebtoken';
import { Redis } from 'ioredis';
import { PrismaClient } from '@prisma/client';
import { Logger } from 'winston';
import { createHash, randomBytes } from 'crypto';

export interface TokenServiceDependencies {
  redis: Redis;
  prisma: PrismaClient;
  logger: Logger;
  config: TokenConfig;
}

export interface TokenConfig {
  accessToken: {
    secret: string;
    expiresIn: string;
    algorithm: jwt.Algorithm;
  };
  refreshToken: {
    secret: string;
    expiresIn: string;
    algorithm: jwt.Algorithm;
  };
  emailVerification: {
    secret: string;
    expiresIn: string;
  };
  passwordReset: {
    secret: string;
    expiresIn: string;
  };
  apiKey: {
    secret: string;
    expiresIn?: string;
  };
}

export class TokenService implements TokenManager, BaseService {
  readonly name = 'TokenService';

  constructor(private deps: TokenServiceDependencies) {}

  async initialize(): Promise<void> {
    this.deps.logger.info('TokenService initialized');
  }

  async destroy(): Promise<void> {
    this.deps.logger.info('TokenService destroyed');
  }

  async generateTokens(userId: string, sessionId?: string): Promise<TokenPair> {
    try {
      const now = Math.floor(Date.now() / 1000);
      
      // Get user permissions for access token
      const permissions = await this.getUserPermissions(userId);
      
      const accessTokenPayload: TokenPayload = {
        userId,
        type: TokenType.ACCESS,
        iat: now,
        exp: now + this.parseExpiry(this.deps.config.accessToken.expiresIn),
        permissions,
        sessionId
      };

      const refreshTokenPayload: TokenPayload = {
        userId,
        type: TokenType.REFRESH,
        iat: now,
        exp: now + this.parseExpiry(this.deps.config.refreshToken.expiresIn),
        sessionId
      };

      const accessToken = jwt.sign(
        accessTokenPayload,
        this.deps.config.accessToken.secret,
        {
          algorithm: this.deps.config.accessToken.algorithm,
          expiresIn: this.deps.config.accessToken.expiresIn
        }
      );

      const refreshToken = jwt.sign(
        refreshTokenPayload,
        this.deps.config.refreshToken.secret,
        {
          algorithm: this.deps.config.refreshToken.algorithm,
          expiresIn: this.deps.config.refreshToken.expiresIn
        }
      );

      // Store refresh token hash in Redis for blacklisting
      const refreshTokenHash = this.hashToken(refreshToken);
      const refreshTokenTTL = this.parseExpiry(this.deps.config.refreshToken.expiresIn);
      
      await this.deps.redis.setex(
        `refresh_token:${refreshTokenHash}`,
        Math.floor(refreshTokenTTL / 1000),
        JSON.stringify({ userId, sessionId, isValid: true })
      );

      return {
        accessToken,
        refreshToken,
        expiresIn: this.parseExpiry(this.deps.config.accessToken.expiresIn)
      };

    } catch (error) {
      this.deps.logger.error('Token generation failed', { userId, error });
      throw new ServiceError(
        'Failed to generate tokens',
        'TOKEN_GENERATION_ERROR',
        500
      );
    }
  }

  async validateToken(token: string, type: TokenType): Promise<TokenPayload> {
    try {
      let secret: string;
      
      switch (type) {
        case TokenType.ACCESS:
          secret = this.deps.config.accessToken.secret;
          break;
        case TokenType.REFRESH:
          secret = this.deps.config.refreshToken.secret;
          break;
        case TokenType.EMAIL_VERIFICATION:
          secret = this.deps.config.emailVerification.secret;
          break;
        case TokenType.PASSWORD_RESET:
          secret = this.deps.config.passwordReset.secret;
          break;
        case TokenType.API_KEY:
          secret = this.deps.config.apiKey.secret;
          break;
        default:
          throw new ServiceError('Invalid token type', 'INVALID_TOKEN_TYPE', 400);
      }

      const payload = jwt.verify(token, secret) as TokenPayload;
      
      // Additional validation for refresh tokens
      if (type === TokenType.REFRESH) {
        await this.validateRefreshToken(token);
      }

      // Check if user is still active
      await this.validateUserStatus(payload.userId);

      return payload;

    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        throw new ServiceError('Invalid token', 'INVALID_TOKEN', 401);
      }
      
      if (error instanceof jwt.TokenExpiredError) {
        throw new ServiceError('Token expired', 'TOKEN_EXPIRED', 401);
      }

      if (error instanceof ServiceError) {
        throw error;
      }

      this.deps.logger.error('Token validation failed', { error });
      throw new ServiceError('Token validation failed', 'TOKEN_VALIDATION_ERROR', 500);
    }
  }

  async refreshTokens(refreshToken: string): Promise<TokenPair> {
    try {
      // Validate refresh token
      const payload = await this.validateToken(refreshToken, TokenType.REFRESH);
      
      // Generate new tokens
      const newTokens = await this.generateTokens(payload.userId, payload.sessionId);
      
      // Invalidate old refresh token
      await this.revokeToken(refreshToken);
      
      // Log token refresh
      this.deps.logger.info('Tokens refreshed', { 
        userId: payload.userId,
        sessionId: payload.sessionId 
      });

      return newTokens;

    } catch (error) {
      this.deps.logger.error('Token refresh failed', { error });
      
      if (error instanceof ServiceError) {
        throw error;
      }

      throw new ServiceError('Token refresh failed', 'TOKEN_REFRESH_ERROR', 500);
    }
  }

  async revokeToken(token: string): Promise<void> {
    try {
      const tokenHash = this.hashToken(token);
      
      // Add to blacklist
      await this.deps.redis.setex(
        `blacklisted_token:${tokenHash}`,
        86400, // 24 hours TTL
        'revoked'
      );

      // If it's a refresh token, remove from valid tokens
      await this.deps.redis.del(`refresh_token:${tokenHash}`);

    } catch (error) {
      this.deps.logger.error('Token revocation failed', { error });
      throw new ServiceError('Token revocation failed', 'TOKEN_REVOCATION_ERROR', 500);
    }
  }

  async generateEmailVerificationToken(userId: string, email: string): Promise<string> {
    try {
      const payload = {
        userId,
        email,
        type: TokenType.EMAIL_VERIFICATION,
        iat: Math.floor(Date.now() / 1000)
      };

      const token = jwt.sign(
        payload,
        this.deps.config.emailVerification.secret,
        { expiresIn: this.deps.config.emailVerification.expiresIn }
      );

      // Store token for verification
      await this.deps.redis.setex(
        `email_verification:${userId}`,
        this.parseExpiry(this.deps.config.emailVerification.expiresIn) / 1000,
        token
      );

      return token;

    } catch (error) {
      this.deps.logger.error('Email verification token generation failed', { userId, error });
      throw new ServiceError(
        'Failed to generate email verification token',
        'EMAIL_TOKEN_ERROR',
        500
      );
    }
  }

  async generatePasswordResetToken(userId: string, email: string): Promise<string> {
    try {
      const payload = {
        userId,
        email,
        type: TokenType.PASSWORD_RESET,
        iat: Math.floor(Date.now() / 1000)
      };

      const token = jwt.sign(
        payload,
        this.deps.config.passwordReset.secret,
        { expiresIn: this.deps.config.passwordReset.expiresIn }
      );

      // Store token for verification
      await this.deps.redis.setex(
        `password_reset:${userId}`,
        this.parseExpiry(this.deps.config.passwordReset.expiresIn) / 1000,
        token
      );

      return token;

    } catch (error) {
      this.deps.logger.error('Password reset token generation failed', { userId, error });
      throw new ServiceError(
        'Failed to generate password reset token',
        'PASSWORD_RESET_TOKEN_ERROR',
        500
      );
    }
  }

  // Private helper methods
  private async validateRefreshToken(token: string): Promise<void> {
    const tokenHash = this.hashToken(token);
    
    // Check if token is blacklisted
    const isBlacklisted = await this.deps.redis.exists(`blacklisted_token:${tokenHash}`);
    if (isBlacklisted) {
      throw new ServiceError('Token has been revoked', 'TOKEN_REVOKED', 401);
    }

    // Check if refresh token exists in valid tokens
    const tokenData = await this.deps.redis.get(`refresh_token:${tokenHash}`);
    if (!tokenData) {
      throw new ServiceError('Invalid refresh token', 'INVALID_REFRESH_TOKEN', 401);
    }

    const { isValid } = JSON.parse(tokenData);
    if (!isValid) {
      throw new ServiceError('Refresh token is no longer valid', 'TOKEN_INVALID', 401);
    }
  }

  private async validateUserStatus(userId: string): Promise<void> {
    const user = await this.deps.prisma.user.findUnique({
      where: { id: userId },
      select: { isActive: true, isSuspended: true }
    });

    if (!user) {
      throw new ServiceError('User not found', 'USER_NOT_FOUND', 401);
    }

    if (!user.isActive) {
      throw new ServiceError('User account is inactive', 'ACCOUNT_INACTIVE', 401);
    }

    if (user.isSuspended) {
      throw new ServiceError('User account is suspended', 'ACCOUNT_SUSPENDED', 401);
    }
  }

  private async getUserPermissions(userId: string): Promise<string[]> {
    // This would typically fetch from database based on user roles
    const user = await this.deps.prisma.user.findUnique({
      where: { id: userId },
      select: { role: true }
    });

    if (!user) {
      return [];
    }

    return this.getRolePermissions(user.role);
  }

  private getRolePermissions(role: string): string[] {
    const rolePermissions: Record<string, string[]> = {
      USER: [
        'read:own_numbers',
        'write:own_numbers',
        'read:own_orders',
        'read:own_billing',
        'write:own_profile'
      ],
      ADMIN: [
        'read:all_numbers',
        'write:all_numbers',
        'read:all_orders',
        'read:all_billing',
        'read:users',
        'write:users'
      ],
      SUPER_ADMIN: [
        'read:*',
        'write:*',
        'admin:*'
      ]
    };

    return rolePermissions[role] || rolePermissions.USER;
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private parseExpiry(expiry: string): number {
    const match = expiry.match(/^(\d+)([smhd])$/);
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

### 2.3 Session Management

```typescript
// src/services/session.service.ts
import { PrismaClient, Session } from '@prisma/client';
import { Redis } from 'ioredis';
import { Logger } from 'winston';

export interface SessionServiceDependencies {
  prisma: PrismaClient;
  redis: Redis;
  logger: Logger;
  config: SessionConfig;
}

export interface SessionConfig {
  maxActiveSessions: number;
  sessionTimeout: number;
  extendOnActivity: boolean;
  trackGeolocation: boolean;
  requireDeviceFingerprint: boolean;
}

export interface CreateSessionRequest {
  userId: string;
  refreshToken: string;
  deviceInfo?: DeviceInfo;
  ipAddress?: string;
  userAgent?: string;
  location?: GeoLocation;
}

export interface SessionInfo {
  id: string;
  userId: string;
  deviceInfo?: DeviceInfo;
  ipAddress?: string;
  location?: GeoLocation;
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
  isActive: boolean;
}

export class SessionService implements SessionManager, BaseService {
  readonly name = 'SessionService';

  constructor(private deps: SessionServiceDependencies) {}

  async initialize(): Promise<void> {
    this.deps.logger.info('SessionService initialized');
    
    // Start cleanup job for expired sessions
    this.startSessionCleanup();
  }

  async destroy(): Promise<void> {
    this.deps.logger.info('SessionService destroyed');
  }

  async createSession(
    userId: string,
    sessionData: CreateSessionRequest
  ): Promise<Session> {
    try {
      // Enforce session limits
      await this.enforceSessionLimits(userId);

      // Create session in database
      const session = await this.deps.prisma.session.create({
        data: {
          userId,
          refreshToken: sessionData.refreshToken,
          expiresAt: new Date(Date.now() + this.deps.config.sessionTimeout),
          deviceInfo: sessionData.deviceInfo ? JSON.stringify(sessionData.deviceInfo) : null,
          ipAddress: sessionData.ipAddress,
          userAgent: sessionData.userAgent
        }
      });

      // Store session in Redis for fast lookup
      await this.cacheSession(session);

      // Log session creation
      this.deps.logger.info('Session created', {
        sessionId: session.id,
        userId,
        ipAddress: sessionData.ipAddress
      });

      return session;

    } catch (error) {
      this.deps.logger.error('Session creation failed', { userId, error });
      throw new ServiceError('Failed to create session', 'SESSION_CREATE_ERROR', 500);
    }
  }

  async validateSession(sessionId: string): Promise<Session | null> {
    try {
      // Try cache first
      let session = await this.getSessionFromCache(sessionId);
      
      if (!session) {
        // Fallback to database
        session = await this.deps.prisma.session.findUnique({
          where: { id: sessionId },
          include: { user: true }
        });

        if (session) {
          await this.cacheSession(session);
        }
      }

      if (!session) {
        return null;
      }

      // Check if session is expired or revoked
      if (session.isRevoked || session.expiresAt < new Date()) {
        await this.revokeSession(sessionId);
        return null;
      }

      // Check if user is still active
      if (!session.user?.isActive || session.user?.isSuspended) {
        await this.revokeSession(sessionId);
        return null;
      }

      // Extend session if configured
      if (this.deps.config.extendOnActivity) {
        await this.extendSession(sessionId);
      }

      return session;

    } catch (error) {
      this.deps.logger.error('Session validation failed', { sessionId, error });
      return null;
    }
  }

  async extendSession(sessionId: string): Promise<void> {
    try {
      const newExpiresAt = new Date(Date.now() + this.deps.config.sessionTimeout);

      await this.deps.prisma.session.update({
        where: { id: sessionId },
        data: { expiresAt: newExpiresAt }
      });

      // Update cache
      const sessionKey = `session:${sessionId}`;
      const sessionData = await this.deps.redis.get(sessionKey);
      
      if (sessionData) {
        const session = JSON.parse(sessionData);
        session.expiresAt = newExpiresAt.toISOString();
        
        await this.deps.redis.setex(
          sessionKey,
          Math.floor(this.deps.config.sessionTimeout / 1000),
          JSON.stringify(session)
        );
      }

    } catch (error) {
      this.deps.logger.error('Session extension failed', { sessionId, error });
      // Don't throw error, just log it
    }
  }

  async revokeSession(sessionId: string): Promise<void> {
    try {
      await this.deps.prisma.session.update({
        where: { id: sessionId },
        data: {
          isRevoked: true,
          revokedAt: new Date()
        }
      });

      // Remove from cache
      await this.deps.redis.del(`session:${sessionId}`);

      this.deps.logger.info('Session revoked', { sessionId });

    } catch (error) {
      this.deps.logger.error('Session revocation failed', { sessionId, error });
      throw new ServiceError('Failed to revoke session', 'SESSION_REVOKE_ERROR', 500);
    }
  }

  async revokeSessions(userId: string, excludeSessionId?: string): Promise<void> {
    try {
      const whereClause: any = {
        userId,
        isRevoked: false
      };

      if (excludeSessionId) {
        whereClause.id = { not: excludeSessionId };
      }

      // Get sessions to revoke for cache cleanup
      const sessionsToRevoke = await this.deps.prisma.session.findMany({
        where: whereClause,
        select: { id: true }
      });

      // Revoke in database
      await this.deps.prisma.session.updateMany({
        where: whereClause,
        data: {
          isRevoked: true,
          revokedAt: new Date()
        }
      });

      // Remove from cache
      const pipeline = this.deps.redis.pipeline();
      sessionsToRevoke.forEach(session => {
        pipeline.del(`session:${session.id}`);
      });
      await pipeline.exec();

      this.deps.logger.info('Sessions revoked', {
        userId,
        count: sessionsToRevoke.length,
        excludeSessionId
      });

    } catch (error) {
      this.deps.logger.error('Sessions revocation failed', { userId, error });
      throw new ServiceError('Failed to revoke sessions', 'SESSIONS_REVOKE_ERROR', 500);
    }
  }

  async getUserSessions(userId: string): Promise<SessionInfo[]> {
    try {
      const sessions = await this.deps.prisma.session.findMany({
        where: {
          userId,
          isRevoked: false,
          expiresAt: { gte: new Date() }
        },
        orderBy: { createdAt: 'desc' }
      });

      return sessions.map(session => ({
        id: session.id,
        userId: session.userId,
        deviceInfo: session.deviceInfo ? JSON.parse(session.deviceInfo) : undefined,
        ipAddress: session.ipAddress || undefined,
        location: undefined, // Would be populated from IP geolocation
        createdAt: session.createdAt,
        lastActivityAt: session.createdAt, // Would track real activity
        expiresAt: session.expiresAt,
        isActive: !session.isRevoked && session.expiresAt > new Date()
      }));

    } catch (error) {
      this.deps.logger.error('Get user sessions failed', { userId, error });
      throw new ServiceError('Failed to get user sessions', 'GET_SESSIONS_ERROR', 500);
    }
  }

  // Private helper methods
  private async enforceSessionLimits(userId: string): Promise<void> {
    const activeSessionsCount = await this.deps.prisma.session.count({
      where: {
        userId,
        isRevoked: false,
        expiresAt: { gte: new Date() }
      }
    });

    if (activeSessionsCount >= this.deps.config.maxActiveSessions) {
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
        await this.revokeSession(oldestSession.id);
      }
    }
  }

  private async cacheSession(session: Session): Promise<void> {
    try {
      const sessionKey = `session:${session.id}`;
      const ttl = Math.floor((session.expiresAt.getTime() - Date.now()) / 1000);
      
      if (ttl > 0) {
        await this.deps.redis.setex(
          sessionKey,
          ttl,
          JSON.stringify(session)
        );
      }
    } catch (error) {
      this.deps.logger.warn('Failed to cache session', { sessionId: session.id, error });
    }
  }

  private async getSessionFromCache(sessionId: string): Promise<Session | null> {
    try {
      const sessionData = await this.deps.redis.get(`session:${sessionId}`);
      if (sessionData) {
        const session = JSON.parse(sessionData);
        session.createdAt = new Date(session.createdAt);
        session.expiresAt = new Date(session.expiresAt);
        if (session.revokedAt) {
          session.revokedAt = new Date(session.revokedAt);
        }
        return session;
      }
      return null;
    } catch (error) {
      this.deps.logger.warn('Failed to get session from cache', { sessionId, error });
      return null;
    }
  }

  private startSessionCleanup(): void {
    // Run every hour
    setInterval(async () => {
      try {
        const expiredSessionsCount = await this.deps.prisma.session.updateMany({
          where: {
            expiresAt: { lt: new Date() },
            isRevoked: false
          },
          data: {
            isRevoked: true,
            revokedAt: new Date()
          }
        });

        if (expiredSessionsCount.count > 0) {
          this.deps.logger.info('Cleaned up expired sessions', {
            count: expiredSessionsCount.count
          });
        }
      } catch (error) {
        this.deps.logger.error('Session cleanup failed', { error });
      }
    }, 60 * 60 * 1000); // 1 hour
  }
}
```

### 2.4 Permission System

```typescript
// src/services/permission.service.ts
import { PrismaClient, UserRole } from '@prisma/client';
import { Redis } from 'ioredis';
import { Logger } from 'winston';

export interface PermissionServiceDependencies {
  prisma: PrismaClient;
  redis: Redis;
  logger: Logger;
  config: PermissionConfig;
}

export interface PermissionConfig {
  cacheTimeout: number;
  enableResourceLevelPermissions: boolean;
  enableConditionBasedPermissions: boolean;
}

export interface ResourcePermission {
  resource: string;
  actions: string[];
  conditions?: PermissionCondition[];
}

export interface PermissionCheck {
  userId: string;
  resource: string;
  action: string;
  context?: Record<string, any>;
}

export class PermissionService implements PermissionSystem, BaseService {
  readonly name = 'PermissionService';

  private roleHierarchy: Record<UserRole, UserRole[]> = {
    [UserRole.USER]: [],
    [UserRole.ADMIN]: [UserRole.USER],
    [UserRole.SUPER_ADMIN]: [UserRole.ADMIN, UserRole.USER],
    [UserRole.DEVELOPER]: [UserRole.USER],
    [UserRole.SUPPORT]: [UserRole.USER]
  };

  private rolePermissions: Record<UserRole, ResourcePermission[]> = {
    [UserRole.USER]: [
      {
        resource: 'number',
        actions: ['read', 'create', 'update', 'delete'],
        conditions: [{ field: 'userId', operator: 'eq', value: '{{userId}}' }]
      },
      {
        resource: 'order',
        actions: ['read', 'create'],
        conditions: [{ field: 'userId', operator: 'eq', value: '{{userId}}' }]
      },
      {
        resource: 'billing',
        actions: ['read'],
        conditions: [{ field: 'userId', operator: 'eq', value: '{{userId}}' }]
      },
      {
        resource: 'profile',
        actions: ['read', 'update'],
        conditions: [{ field: 'id', operator: 'eq', value: '{{userId}}' }]
      }
    ],
    [UserRole.ADMIN]: [
      {
        resource: 'number',
        actions: ['read', 'create', 'update', 'delete', 'admin']
      },
      {
        resource: 'order',
        actions: ['read', 'create', 'update', 'admin']
      },
      {
        resource: 'billing',
        actions: ['read', 'update', 'admin']
      },
      {
        resource: 'user',
        actions: ['read', 'update', 'suspend']
      },
      {
        resource: 'analytics',
        actions: ['read']
      }
    ],
    [UserRole.SUPER_ADMIN]: [
      {
        resource: '*',
        actions: ['*']
      }
    ],
    [UserRole.DEVELOPER]: [
      {
        resource: 'number',
        actions: ['read', 'create', 'update', 'delete'],
        conditions: [{ field: 'userId', operator: 'eq', value: '{{userId}}' }]
      },
      {
        resource: 'webhook',
        actions: ['read', 'create', 'update', 'delete'],
        conditions: [{ field: 'userId', operator: 'eq', value: '{{userId}}' }]
      },
      {
        resource: 'api_key',
        actions: ['read', 'create', 'update', 'delete'],
        conditions: [{ field: 'userId', operator: 'eq', value: '{{userId}}' }]
      }
    ],
    [UserRole.SUPPORT]: [
      {
        resource: 'user',
        actions: ['read']
      },
      {
        resource: 'number',
        actions: ['read']
      },
      {
        resource: 'order',
        actions: ['read']
      },
      {
        resource: 'billing',
        actions: ['read']
      }
    ]
  };

  constructor(private deps: PermissionServiceDependencies) {}

  async initialize(): Promise<void> {
    this.deps.logger.info('PermissionService initialized');
  }

  async destroy(): Promise<void> {
    this.deps.logger.info('PermissionService destroyed');
  }

  async checkPermission(
    userId: string,
    resource: string,
    action: string,
    context?: Record<string, any>
  ): Promise<boolean> {
    try {
      // Check cache first
      const cacheKey = `permission:${userId}:${resource}:${action}`;
      const cached = await this.deps.redis.get(cacheKey);
      
      if (cached !== null) {
        return cached === 'true';
      }

      // Get user role and permissions
      const user = await this.deps.prisma.user.findUnique({
        where: { id: userId },
        select: { role: true, isActive: true, isSuspended: true }
      });

      if (!user || !user.isActive || user.isSuspended) {
        return false;
      }

      // Check role-based permissions
      const hasPermission = await this.checkRolePermission(
        user.role,
        resource,
        action,
        { ...context, userId }
      );

      // Cache result
      await this.deps.redis.setex(
        cacheKey,
        this.deps.config.cacheTimeout,
        hasPermission.toString()
      );

      return hasPermission;

    } catch (error) {
      this.deps.logger.error('Permission check failed', {
        userId,
        resource,
        action,
        error
      });
      return false;
    }
  }

  async checkRole(userId: string, requiredRole: UserRole): Promise<boolean> {
    try {
      const user = await this.deps.prisma.user.findUnique({
        where: { id: userId },
        select: { role: true, isActive: true, isSuspended: true }
      });

      if (!user || !user.isActive || user.isSuspended) {
        return false;
      }

      return this.hasRole(user.role, requiredRole);

    } catch (error) {
      this.deps.logger.error('Role check failed', { userId, requiredRole, error });
      return false;
    }
  }

  async getUserPermissions(userId: string): Promise<Permission[]> {
    try {
      const user = await this.deps.prisma.user.findUnique({
        where: { id: userId },
        select: { role: true }
      });

      if (!user) {
        return [];
      }

      return this.getRolePermissions(user.role);

    } catch (error) {
      this.deps.logger.error('Get user permissions failed', { userId, error });
      return [];
    }
  }

  async assignRole(userId: string, role: UserRole): Promise<void> {
    try {
      await this.deps.prisma.user.update({
        where: { id: userId },
        data: { role }
      });

      // Clear permission cache for user
      await this.clearUserPermissionCache(userId);

      this.deps.logger.info('Role assigned', { userId, role });

    } catch (error) {
      this.deps.logger.error('Role assignment failed', { userId, role, error });
      throw new ServiceError('Failed to assign role', 'ROLE_ASSIGNMENT_ERROR', 500);
    }
  }

  // Private helper methods
  private async checkRolePermission(
    userRole: UserRole,
    resource: string,
    action: string,
    context: Record<string, any>
  ): Promise<boolean> {
    // Get all roles user has (including inherited)
    const userRoles = this.getUserRoles(userRole);
    
    for (const role of userRoles) {
      const permissions = this.rolePermissions[role];
      
      for (const permission of permissions) {
        // Check wildcard permissions
        if (permission.resource === '*' && permission.actions.includes('*')) {
          return true;
        }

        if (permission.resource === '*' && permission.actions.includes(action)) {
          return true;
        }

        if (permission.resource === resource && permission.actions.includes('*')) {
          return true;
        }

        // Check specific resource and action
        if (permission.resource === resource && permission.actions.includes(action)) {
          // Check conditions if enabled
          if (this.deps.config.enableConditionBasedPermissions && permission.conditions) {
            const conditionsMet = await this.evaluateConditions(
              permission.conditions,
              context
            );
            if (conditionsMet) {
              return true;
            }
          } else if (!permission.conditions) {
            return true;
          }
        }
      }
    }

    return false;
  }

  private getUserRoles(userRole: UserRole): UserRole[] {
    const roles = [userRole];
    const inheritedRoles = this.roleHierarchy[userRole] || [];
    roles.push(...inheritedRoles);
    return roles;
  }

  private hasRole(userRole: UserRole, requiredRole: UserRole): boolean {
    const userRoles = this.getUserRoles(userRole);
    return userRoles.includes(requiredRole);
  }

  private getRolePermissions(role: UserRole): Permission[] {
    const userRoles = this.getUserRoles(role);
    const permissions: Permission[] = [];
    
    for (const userRole of userRoles) {
      const rolePerms = this.rolePermissions[userRole] || [];
      
      for (const rolePerm of rolePerms) {
        for (const action of rolePerm.actions) {
          permissions.push({
            id: `${rolePerm.resource}:${action}`,
            resource: rolePerm.resource,
            action,
            conditions: rolePerm.conditions
          });
        }
      }
    }

    return permissions;
  }

  private async evaluateConditions(
    conditions: PermissionCondition[],
    context: Record<string, any>
  ): Promise<boolean> {
    for (const condition of conditions) {
      const contextValue = context[condition.field];
      let conditionValue = condition.value;

      // Replace template variables
      if (typeof conditionValue === 'string' && conditionValue.startsWith('{{') && conditionValue.endsWith('}}')) {
        const variable = conditionValue.slice(2, -2);
        conditionValue = context[variable];
      }

      const result = this.evaluateCondition(contextValue, condition.operator, conditionValue);
      
      if (!result) {
        return false;
      }
    }

    return true;
  }

  private evaluateCondition(value: any, operator: string, conditionValue: any): boolean {
    switch (operator) {
      case 'eq':
        return value === conditionValue;
      case 'ne':
        return value !== conditionValue;
      case 'in':
        return Array.isArray(conditionValue) && conditionValue.includes(value);
      case 'nin':
        return Array.isArray(conditionValue) && !conditionValue.includes(value);
      case 'gt':
        return value > conditionValue;
      case 'lt':
        return value < conditionValue;
      case 'gte':
        return value >= conditionValue;
      case 'lte':
        return value <= conditionValue;
      default:
        return false;
    }
  }

  private async clearUserPermissionCache(userId: string): Promise<void> {
    try {
      const pattern = `permission:${userId}:*`;
      const keys = await this.deps.redis.keys(pattern);
      
      if (keys.length > 0) {
        await this.deps.redis.del(...keys);
      }
    } catch (error) {
      this.deps.logger.warn('Failed to clear user permission cache', { userId, error });
    }
  }
}
```

### 2.5 Security Service

```typescript
// src/services/security.service.ts
import { Request } from 'express';
import { Redis } from 'ioredis';
import { Logger } from 'winston';
import { createHash } from 'crypto';
import geoip from 'geoip-lite';

export interface SecurityServiceDependencies {
  redis: Redis;
  logger: Logger;
  config: SecurityConfig;
}

export interface SecurityConfig {
  rateLimiting: {
    windowMs: number;
    maxRequests: number;
    skipSuccessfulRequests: boolean;
  };
  bruteForce: {
    maxAttempts: number;
    windowMs: number;
    blockDurationMs: number;
  };
  deviceFingerprinting: {
    enabled: boolean;
    trackingFields: string[];
  };
  geoLocation: {
    enabled: boolean;
    blockSuspiciousLocations: boolean;
    allowedCountries: string[];
  };
}

export interface SecurityCheck {
  isAllowed: boolean;
  reason?: string;
  remainingAttempts?: number;
  resetTime?: Date;
}

export interface DeviceFingerprint {
  userAgent: string;
  acceptLanguage: string;
  acceptEncoding: string;
  connection: string;
  fingerprint: string;
}

export interface LocationInfo {
  country: string;
  region: string;
  city: string;
  timezone: string;
  coordinates: {
    latitude: number;
    longitude: number;
  };
}

export class SecurityService implements BaseService {
  readonly name = 'SecurityService';

  constructor(private deps: SecurityServiceDependencies) {}

  async initialize(): Promise<void> {
    this.deps.logger.info('SecurityService initialized');
  }

  async destroy(): Promise<void> {
    this.deps.logger.info('SecurityService destroyed');
  }

  async checkRateLimit(
    identifier: string,
    action: string = 'default'
  ): Promise<SecurityCheck> {
    try {
      const key = `rate_limit:${action}:${identifier}`;
      const current = await this.deps.redis.incr(key);
      
      if (current === 1) {
        await this.deps.redis.expire(key, Math.floor(this.deps.config.rateLimiting.windowMs / 1000));
      }

      if (current > this.deps.config.rateLimiting.maxRequests) {
        const ttl = await this.deps.redis.ttl(key);
        
        return {
          isAllowed: false,
          reason: 'Rate limit exceeded',
          remainingAttempts: 0,
          resetTime: new Date(Date.now() + ttl * 1000)
        };
      }

      return {
        isAllowed: true,
        remainingAttempts: this.deps.config.rateLimiting.maxRequests - current
      };

    } catch (error) {
      this.deps.logger.error('Rate limit check failed', { identifier, action, error });
      return { isAllowed: true }; // Fail open
    }
  }

  async checkBruteForce(
    identifier: string,
    action: string = 'login'
  ): Promise<SecurityCheck> {
    try {
      const key = `brute_force:${action}:${identifier}`;
      const attempts = await this.deps.redis.get(key);
      const currentAttempts = attempts ? parseInt(attempts) : 0;

      if (currentAttempts >= this.deps.config.bruteForce.maxAttempts) {
        const ttl = await this.deps.redis.ttl(key);
        
        return {
          isAllowed: false,
          reason: 'Too many failed attempts',
          remainingAttempts: 0,
          resetTime: new Date(Date.now() + ttl * 1000)
        };
      }

      return {
        isAllowed: true,
        remainingAttempts: this.deps.config.bruteForce.maxAttempts - currentAttempts
      };

    } catch (error) {
      this.deps.logger.error('Brute force check failed', { identifier, action, error });
      return { isAllowed: true }; // Fail open
    }
  }

  async recordFailedAttempt(
    identifier: string,
    action: string = 'login'
  ): Promise<void> {
    try {
      const key = `brute_force:${action}:${identifier}`;
      const current = await this.deps.redis.incr(key);
      
      if (current === 1) {
        await this.deps.redis.expire(
          key,
          Math.floor(this.deps.config.bruteForce.windowMs / 1000)
        );
      }

      if (current >= this.deps.config.bruteForce.maxAttempts) {
        // Extend block duration
        await this.deps.redis.expire(
          key,
          Math.floor(this.deps.config.bruteForce.blockDurationMs / 1000)
        );
        
        this.deps.logger.warn('Brute force protection activated', {
          identifier,
          action,
          attempts: current
        });
      }

    } catch (error) {
      this.deps.logger.error('Failed to record failed attempt', { identifier, action, error });
    }
  }

  async clearFailedAttempts(
    identifier: string,
    action: string = 'login'
  ): Promise<void> {
    try {
      const key = `brute_force:${action}:${identifier}`;
      await this.deps.redis.del(key);
    } catch (error) {
      this.deps.logger.error('Failed to clear failed attempts', { identifier, action, error });
    }
  }

  generateDeviceFingerprint(req: Request): DeviceFingerprint {
    const userAgent = req.get('User-Agent') || '';
    const acceptLanguage = req.get('Accept-Language') || '';
    const acceptEncoding = req.get('Accept-Encoding') || '';
    const connection = req.get('Connection') || '';

    const fingerprintData = `${userAgent}|${acceptLanguage}|${acceptEncoding}|${connection}`;
    const fingerprint = createHash('sha256').update(fingerprintData).digest('hex');

    return {
      userAgent,
      acceptLanguage,
      acceptEncoding,
      connection,
      fingerprint
    };
  }

  getLocationInfo(ipAddress: string): LocationInfo | null {
    if (!this.deps.config.geoLocation.enabled) {
      return null;
    }

    try {
      const geo = geoip.lookup(ipAddress);
      
      if (!geo) {
        return null;
      }

      return {
        country: geo.country,
        region: geo.region,
        city: geo.city,
        timezone: geo.timezone,
        coordinates: {
          latitude: geo.ll[0],
          longitude: geo.ll[1]
        }
      };

    } catch (error) {
      this.deps.logger.error('Failed to get location info', { ipAddress, error });
      return null;
    }
  }

  async checkLocationSecurity(ipAddress: string): Promise<SecurityCheck> {
    if (!this.deps.config.geoLocation.enabled || !this.deps.config.geoLocation.blockSuspiciousLocations) {
      return { isAllowed: true };
    }

    try {
      const location = this.getLocationInfo(ipAddress);
      
      if (!location) {
        return { isAllowed: true }; // Allow if we can't determine location
      }

      // Check if country is allowed
      if (this.deps.config.geoLocation.allowedCountries.length > 0) {
        if (!this.deps.config.geoLocation.allowedCountries.includes(location.country)) {
          return {
            isAllowed: false,
            reason: `Access not allowed from country: ${location.country}`
          };
        }
      }

      return { isAllowed: true };

    } catch (error) {
      this.deps.logger.error('Location security check failed', { ipAddress, error });
      return { isAllowed: true }; // Fail open
    }
  }

  async logSecurityEvent(
    eventType: string,
    details: Record<string, any>,
    severity: 'low' | 'medium' | 'high' | 'critical' = 'medium'
  ): Promise<void> {
    try {
      const securityEvent = {
        type: eventType,
        severity,
        timestamp: new Date().toISOString(),
        details
      };

      // Log to application logger
      this.deps.logger.warn('Security event', securityEvent);

      // Store in Redis for security monitoring
      const key = `security_event:${Date.now()}:${Math.random().toString(36).substr(2, 9)}`;
      await this.deps.redis.setex(
        key,
        86400, // 24 hours
        JSON.stringify(securityEvent)
      );

      // For critical events, could trigger alerts here
      if (severity === 'critical') {
        // TODO: Implement alerting system
        this.deps.logger.error('CRITICAL SECURITY EVENT', securityEvent);
      }

    } catch (error) {
      this.deps.logger.error('Failed to log security event', { eventType, error });
    }
  }

  sanitizeInput(input: string): string {
    // Basic input sanitization
    return input
      .replace(/[<>]/g, '') // Remove angle brackets
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/on\w+=/gi, '') // Remove event handlers
      .trim();
  }

  isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 254;
  }

  isValidPhoneNumber(phoneNumber: string): boolean {
    const phoneRegex = /^\+[1-9]\d{1,14}$/;
    return phoneRegex.test(phoneNumber);
  }

  generateSecureToken(length: number = 32): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    return result;
  }
}
```

This comprehensive authentication system documentation provides a complete TypeScript-based implementation with JWT tokens, session management, role-based permissions, and security features for the DID buy platform.
