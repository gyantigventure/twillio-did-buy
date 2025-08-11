# Error Handling & Validation - Complete TypeScript Implementation

## 1. Overview

This document provides comprehensive error handling and validation strategies for the DID buy system, including custom error classes, validation frameworks, error recovery mechanisms, and monitoring with complete TypeScript implementations.

## 2. Error Handling Architecture

### 2.1 Error Classification System

```typescript
// src/types/error.types.ts
export enum ErrorSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export enum ErrorCategory {
  VALIDATION = 'validation',
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  BUSINESS_LOGIC = 'business_logic',
  EXTERNAL_SERVICE = 'external_service',
  DATABASE = 'database',
  NETWORK = 'network',
  SYSTEM = 'system'
}

export interface ErrorContext {
  userId?: string;
  requestId?: string;
  sessionId?: string;
  operation?: string;
  resource?: string;
  timestamp: Date;
  metadata?: Record<string, any>;
}

export interface ErrorDetails {
  code: string;
  message: string;
  category: ErrorCategory;
  severity: ErrorSeverity;
  context: ErrorContext;
  userMessage?: string;
  retryable?: boolean;
  recoverySuggestions?: string[];
  originalError?: Error;
}

export interface ValidationErrorDetail {
  field: string;
  value: any;
  message: string;
  code: string;
  constraint?: string;
}
```

### 2.2 Base Error Classes

```typescript
// src/errors/base.error.ts
export abstract class BaseError extends Error {
  public readonly code: string;
  public readonly category: ErrorCategory;
  public readonly severity: ErrorSeverity;
  public readonly context: ErrorContext;
  public readonly userMessage?: string;
  public readonly retryable: boolean;
  public readonly recoverySuggestions: string[];
  public readonly originalError?: Error;

  constructor(details: ErrorDetails) {
    super(details.message);
    
    this.name = this.constructor.name;
    this.code = details.code;
    this.category = details.category;
    this.severity = details.severity;
    this.context = details.context;
    this.userMessage = details.userMessage;
    this.retryable = details.retryable || false;
    this.recoverySuggestions = details.recoverySuggestions || [];
    this.originalError = details.originalError;

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  toJSON(): Record<string, any> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      category: this.category,
      severity: this.severity,
      context: this.context,
      userMessage: this.userMessage,
      retryable: this.retryable,
      recoverySuggestions: this.recoverySuggestions,
      stack: this.stack,
      originalError: this.originalError?.message
    };
  }

  getHTTPStatusCode(): number {
    switch (this.category) {
      case ErrorCategory.VALIDATION:
        return 400;
      case ErrorCategory.AUTHENTICATION:
        return 401;
      case ErrorCategory.AUTHORIZATION:
        return 403;
      case ErrorCategory.BUSINESS_LOGIC:
        return this.code === 'RESOURCE_NOT_FOUND' ? 404 : 400;
      case ErrorCategory.EXTERNAL_SERVICE:
        return this.retryable ? 503 : 502;
      case ErrorCategory.DATABASE:
        return 500;
      case ErrorCategory.NETWORK:
        return 503;
      case ErrorCategory.SYSTEM:
        return 500;
      default:
        return 500;
    }
  }
}
```

### 2.3 Specific Error Classes

```typescript
// src/errors/validation.error.ts
export class ValidationError extends BaseError {
  public readonly validationErrors: ValidationErrorDetail[];

  constructor(
    message: string,
    validationErrors: ValidationErrorDetail[] = [],
    context: Partial<ErrorContext> = {}
  ) {
    super({
      code: 'VALIDATION_ERROR',
      message,
      category: ErrorCategory.VALIDATION,
      severity: ErrorSeverity.LOW,
      context: {
        timestamp: new Date(),
        ...context
      },
      userMessage: 'Please check your input and try again.',
      retryable: false,
      recoverySuggestions: [
        'Verify all required fields are provided',
        'Check field formats and constraints',
        'Review the API documentation for valid values'
      ]
    });

    this.validationErrors = validationErrors;
  }

  static fromZodError(zodError: any, context: Partial<ErrorContext> = {}): ValidationError {
    const validationErrors: ValidationErrorDetail[] = zodError.errors.map((err: any) => ({
      field: err.path.join('.'),
      value: err.received,
      message: err.message,
      code: err.code,
      constraint: err.constraint
    }));

    return new ValidationError(
      'Input validation failed',
      validationErrors,
      context
    );
  }
}

// src/errors/business.error.ts
export class BusinessLogicError extends BaseError {
  constructor(
    code: string,
    message: string,
    context: Partial<ErrorContext> = {},
    options: {
      userMessage?: string;
      retryable?: boolean;
      severity?: ErrorSeverity;
    } = {}
  ) {
    super({
      code,
      message,
      category: ErrorCategory.BUSINESS_LOGIC,
      severity: options.severity || ErrorSeverity.MEDIUM,
      context: {
        timestamp: new Date(),
        ...context
      },
      userMessage: options.userMessage || message,
      retryable: options.retryable || false,
      recoverySuggestions: BusinessLogicError.getRecoverySuggestions(code)
    });
  }

  private static getRecoverySuggestions(code: string): string[] {
    const suggestions: Record<string, string[]> = {
      'INSUFFICIENT_BALANCE': [
        'Add funds to your account',
        'Contact support for billing assistance',
        'Check your payment method'
      ],
      'NUMBER_NOT_AVAILABLE': [
        'Try searching for alternative numbers',
        'Check if the number is already owned',
        'Contact support if you believe this is an error'
      ],
      'PURCHASE_LIMIT_EXCEEDED': [
        'Wait for the limit reset period',
        'Contact support to increase your limits',
        'Review your account plan'
      ],
      'RESOURCE_NOT_FOUND': [
        'Verify the resource ID is correct',
        'Check if you have permission to access this resource',
        'Ensure the resource hasn\'t been deleted'
      ]
    };

    return suggestions[code] || ['Contact support for assistance'];
  }
}

// src/errors/external-service.error.ts
export class ExternalServiceError extends BaseError {
  public readonly serviceName: string;
  public readonly serviceCode?: string | number;

  constructor(
    serviceName: string,
    message: string,
    context: Partial<ErrorContext> = {},
    options: {
      serviceCode?: string | number;
      retryable?: boolean;
      originalError?: Error;
    } = {}
  ) {
    super({
      code: `${serviceName.toUpperCase()}_ERROR`,
      message,
      category: ErrorCategory.EXTERNAL_SERVICE,
      severity: ErrorSeverity.HIGH,
      context: {
        timestamp: new Date(),
        ...context
      },
      userMessage: `We're experiencing issues with ${serviceName}. Please try again later.`,
      retryable: options.retryable !== false,
      recoverySuggestions: [
        'Wait a moment and try again',
        'Check service status page',
        'Contact support if the issue persists'
      ],
      originalError: options.originalError
    });

    this.serviceName = serviceName;
    this.serviceCode = options.serviceCode;
  }
}

// src/errors/authentication.error.ts
export class AuthenticationError extends BaseError {
  constructor(
    message: string = 'Authentication failed',
    context: Partial<ErrorContext> = {},
    options: {
      code?: string;
      userMessage?: string;
    } = {}
  ) {
    super({
      code: options.code || 'AUTHENTICATION_FAILED',
      message,
      category: ErrorCategory.AUTHENTICATION,
      severity: ErrorSeverity.MEDIUM,
      context: {
        timestamp: new Date(),
        ...context
      },
      userMessage: options.userMessage || 'Please log in to continue.',
      retryable: false,
      recoverySuggestions: [
        'Check your credentials and try again',
        'Reset your password if needed',
        'Contact support if you continue having issues'
      ]
    });
  }
}

// src/errors/authorization.error.ts
export class AuthorizationError extends BaseError {
  public readonly requiredRole?: string;
  public readonly requiredPermissions?: string[];

  constructor(
    message: string = 'Access denied',
    context: Partial<ErrorContext> = {},
    options: {
      requiredRole?: string;
      requiredPermissions?: string[];
      userMessage?: string;
    } = {}
  ) {
    super({
      code: 'ACCESS_DENIED',
      message,
      category: ErrorCategory.AUTHORIZATION,
      severity: ErrorSeverity.MEDIUM,
      context: {
        timestamp: new Date(),
        ...context
      },
      userMessage: options.userMessage || 'You don\'t have permission to perform this action.',
      retryable: false,
      recoverySuggestions: [
        'Contact your administrator for access',
        'Verify you\'re using the correct account',
        'Check if your account has the necessary permissions'
      ]
    });

    this.requiredRole = options.requiredRole;
    this.requiredPermissions = options.requiredPermissions;
  }
}
```

## 3. Error Handler Service

### 3.1 Centralized Error Management

```typescript
// src/services/error-handler.service.ts
import { Logger } from 'winston';
import { Redis } from 'ioredis';
import { PrismaClient } from '@prisma/client';

export interface ErrorHandlerConfig {
  enableErrorTracking: boolean;
  enableUserNotification: boolean;
  enableRetryMechanism: boolean;
  maxRetryAttempts: number;
  retryDelayMs: number;
  alertThresholds: {
    errorRate: number;
    criticalErrors: number;
    timeWindow: number;
  };
}

export interface ErrorMetrics {
  totalErrors: number;
  errorsByCategory: Record<ErrorCategory, number>;
  errorsBySeverity: Record<ErrorSeverity, number>;
  errorRate: number;
  mostFrequentErrors: Array<{
    code: string;
    count: number;
    message: string;
  }>;
}

export class ErrorHandlerService {
  constructor(
    private logger: Logger,
    private redis: Redis,
    private prisma: PrismaClient,
    private config: ErrorHandlerConfig
  ) {}

  async handleError(error: BaseError): Promise<void> {
    try {
      // Log the error
      this.logError(error);

      // Track error metrics
      if (this.config.enableErrorTracking) {
        await this.trackError(error);
      }

      // Store error in database for analysis
      await this.storeError(error);

      // Check for alert conditions
      await this.checkAlertConditions(error);

      // Notify user if enabled and appropriate
      if (this.config.enableUserNotification && this.shouldNotifyUser(error)) {
        await this.notifyUser(error);
      }

      // Attempt recovery if error is retryable
      if (this.config.enableRetryMechanism && error.retryable) {
        await this.scheduleRetry(error);
      }

    } catch (handlingError) {
      // Log error in error handling - don't throw to avoid infinite loops
      this.logger.error('Error handling failed', {
        originalError: error.toJSON(),
        handlingError: handlingError.message
      });
    }
  }

  async getErrorMetrics(
    timeWindow: number = 3600000 // 1 hour in milliseconds
  ): Promise<ErrorMetrics> {
    try {
      const now = Date.now();
      const windowStart = now - timeWindow;

      // Get error counts from Redis
      const pipeline = this.redis.pipeline();
      
      // Total errors
      pipeline.zcount('errors:timeline', windowStart, now);
      
      // Errors by category
      Object.values(ErrorCategory).forEach(category => {
        pipeline.zcount(`errors:category:${category}`, windowStart, now);
      });
      
      // Errors by severity
      Object.values(ErrorSeverity).forEach(severity => {
        pipeline.zcount(`errors:severity:${severity}`, windowStart, now);
      });

      const results = await pipeline.exec();
      let resultIndex = 0;

      const totalErrors = results[resultIndex++][1] as number;
      
      const errorsByCategory: Record<ErrorCategory, number> = {} as any;
      Object.values(ErrorCategory).forEach(category => {
        errorsByCategory[category] = results[resultIndex++][1] as number;
      });

      const errorsBySeverity: Record<ErrorSeverity, number> = {} as any;
      Object.values(ErrorSeverity).forEach(severity => {
        errorsBySeverity[severity] = results[resultIndex++][1] as number;
      });

      // Get most frequent errors
      const mostFrequentErrors = await this.getMostFrequentErrors(timeWindow);

      // Calculate error rate (errors per hour)
      const errorRate = (totalErrors / timeWindow) * 3600000;

      return {
        totalErrors,
        errorsByCategory,
        errorsBySeverity,
        errorRate,
        mostFrequentErrors
      };

    } catch (error) {
      this.logger.error('Failed to get error metrics', error);
      return this.getEmptyMetrics();
    }
  }

  async recoverFromError(
    error: BaseError,
    retryFunction: () => Promise<any>
  ): Promise<{ success: boolean; result?: any; finalError?: BaseError }> {
    let attempts = 0;
    let lastError = error;

    while (attempts < this.config.maxRetryAttempts && error.retryable) {
      attempts++;
      
      try {
        // Wait before retry
        if (attempts > 1) {
          await this.delay(this.config.retryDelayMs * attempts);
        }

        this.logger.info('Attempting error recovery', {
          errorCode: error.code,
          attempt: attempts,
          maxAttempts: this.config.maxRetryAttempts
        });

        const result = await retryFunction();
        
        this.logger.info('Error recovery successful', {
          errorCode: error.code,
          attempts
        });

        return { success: true, result };

      } catch (retryError) {
        if (retryError instanceof BaseError) {
          lastError = retryError;
        } else {
          lastError = new ExternalServiceError(
            'retry',
            retryError.message,
            error.context,
            { originalError: retryError }
          );
        }

        this.logger.warn('Error recovery attempt failed', {
          errorCode: error.code,
          attempt: attempts,
          retryError: lastError.message
        });
      }
    }

    this.logger.error('Error recovery failed after all attempts', {
      originalError: error.code,
      attempts,
      finalError: lastError.message
    });

    return { success: false, finalError: lastError };
  }

  private logError(error: BaseError): void {
    const logData = {
      error: error.toJSON(),
      context: error.context,
      stack: error.stack
    };

    switch (error.severity) {
      case ErrorSeverity.CRITICAL:
        this.logger.error(`CRITICAL ERROR: ${error.message}`, logData);
        break;
      case ErrorSeverity.HIGH:
        this.logger.error(`HIGH SEVERITY: ${error.message}`, logData);
        break;
      case ErrorSeverity.MEDIUM:
        this.logger.warn(`MEDIUM SEVERITY: ${error.message}`, logData);
        break;
      case ErrorSeverity.LOW:
        this.logger.info(`LOW SEVERITY: ${error.message}`, logData);
        break;
    }
  }

  private async trackError(error: BaseError): Promise<void> {
    try {
      const timestamp = Date.now();
      const pipeline = this.redis.pipeline();

      // Add to timeline
      pipeline.zadd('errors:timeline', timestamp, JSON.stringify({
        code: error.code,
        category: error.category,
        severity: error.severity,
        message: error.message,
        timestamp
      }));

      // Track by category
      pipeline.zadd(`errors:category:${error.category}`, timestamp, error.code);

      // Track by severity
      pipeline.zadd(`errors:severity:${error.severity}`, timestamp, error.code);

      // Track frequency
      pipeline.zincrby('errors:frequency', 1, error.code);

      // Set expiry for timeline data (24 hours)
      pipeline.expire('errors:timeline', 86400);
      pipeline.expire(`errors:category:${error.category}`, 86400);
      pipeline.expire(`errors:severity:${error.severity}`, 86400);

      await pipeline.exec();

    } catch (trackingError) {
      this.logger.warn('Failed to track error metrics', trackingError);
    }
  }

  private async storeError(error: BaseError): Promise<void> {
    try {
      await this.prisma.auditLog.create({
        data: {
          userId: error.context.userId,
          action: 'ERROR_OCCURRED',
          resource: 'system',
          resourceId: error.context.requestId,
          newValues: JSON.stringify(error.toJSON()),
          success: false,
          ipAddress: error.context.metadata?.ipAddress,
          userAgent: error.context.metadata?.userAgent,
          errorMessage: error.message
        }
      });
    } catch (storeError) {
      this.logger.warn('Failed to store error in database', storeError);
    }
  }

  private async checkAlertConditions(error: BaseError): Promise<void> {
    try {
      const metrics = await this.getErrorMetrics(this.config.alertThresholds.timeWindow);
      
      // Check error rate threshold
      if (metrics.errorRate > this.config.alertThresholds.errorRate) {
        await this.sendAlert('HIGH_ERROR_RATE', {
          currentRate: metrics.errorRate,
          threshold: this.config.alertThresholds.errorRate,
          timeWindow: this.config.alertThresholds.timeWindow
        });
      }

      // Check critical error threshold
      const criticalErrors = metrics.errorsBySeverity[ErrorSeverity.CRITICAL] || 0;
      if (criticalErrors >= this.config.alertThresholds.criticalErrors) {
        await this.sendAlert('CRITICAL_ERRORS_THRESHOLD', {
          criticalErrors,
          threshold: this.config.alertThresholds.criticalErrors,
          timeWindow: this.config.alertThresholds.timeWindow
        });
      }

    } catch (alertError) {
      this.logger.warn('Failed to check alert conditions', alertError);
    }
  }

  private shouldNotifyUser(error: BaseError): boolean {
    // Don't notify for low severity errors or system errors
    if (error.severity === ErrorSeverity.LOW || 
        error.category === ErrorCategory.SYSTEM) {
      return false;
    }

    // Always notify for user-facing errors
    return [
      ErrorCategory.VALIDATION,
      ErrorCategory.AUTHENTICATION,
      ErrorCategory.AUTHORIZATION,
      ErrorCategory.BUSINESS_LOGIC
    ].includes(error.category);
  }

  private async notifyUser(error: BaseError): Promise<void> {
    try {
      if (!error.context.userId) return;

      // Create notification for user
      await this.prisma.notification.create({
        data: {
          userId: error.context.userId,
          type: 'SYSTEM',
          title: 'Action Required',
          message: error.userMessage || error.message,
          priority: this.mapSeverityToPriority(error.severity),
          metadata: JSON.stringify({
            errorCode: error.code,
            errorCategory: error.category,
            recoverySuggestions: error.recoverySuggestions
          })
        }
      });

    } catch (notificationError) {
      this.logger.warn('Failed to notify user', notificationError);
    }
  }

  private async scheduleRetry(error: BaseError): Promise<void> {
    try {
      const retryData = {
        errorCode: error.code,
        context: error.context,
        operation: error.context.operation,
        attempts: 1,
        maxAttempts: this.config.maxRetryAttempts,
        nextRetryAt: Date.now() + this.config.retryDelayMs
      };

      await this.redis.zadd(
        'retry_queue',
        retryData.nextRetryAt,
        JSON.stringify(retryData)
      );

    } catch (retryError) {
      this.logger.warn('Failed to schedule retry', retryError);
    }
  }

  private async getMostFrequentErrors(timeWindow: number): Promise<Array<{
    code: string;
    count: number;
    message: string;
  }>> {
    try {
      const frequentErrors = await this.redis.zrevrange(
        'errors:frequency',
        0,
        9, // Top 10
        'WITHSCORES'
      );

      const result = [];
      for (let i = 0; i < frequentErrors.length; i += 2) {
        const code = frequentErrors[i];
        const count = parseInt(frequentErrors[i + 1]);
        
        result.push({
          code,
          count,
          message: `Error code ${code} occurred ${count} times`
        });
      }

      return result;

    } catch (error) {
      this.logger.warn('Failed to get frequent errors', error);
      return [];
    }
  }

  private async sendAlert(alertType: string, data: any): Promise<void> {
    this.logger.error(`ALERT: ${alertType}`, data);
    
    // Here you would integrate with your alerting system
    // (Slack, PagerDuty, email, etc.)
  }

  private mapSeverityToPriority(severity: ErrorSeverity): string {
    const mapping = {
      [ErrorSeverity.CRITICAL]: 'URGENT',
      [ErrorSeverity.HIGH]: 'HIGH',
      [ErrorSeverity.MEDIUM]: 'MEDIUM',
      [ErrorSeverity.LOW]: 'LOW'
    };
    return mapping[severity] || 'MEDIUM';
  }

  private getEmptyMetrics(): ErrorMetrics {
    return {
      totalErrors: 0,
      errorsByCategory: Object.values(ErrorCategory).reduce((acc, cat) => {
        acc[cat] = 0;
        return acc;
      }, {} as Record<ErrorCategory, number>),
      errorsBySeverity: Object.values(ErrorSeverity).reduce((acc, sev) => {
        acc[sev] = 0;
        return acc;
      }, {} as Record<ErrorSeverity, number>),
      errorRate: 0,
      mostFrequentErrors: []
    };
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

## 4. Validation Framework

### 4.1 Advanced Validation System

```typescript
// src/validation/validation.service.ts
import { z, ZodSchema, ZodError } from 'zod';

export interface ValidationRule {
  name: string;
  validator: (value: any, context?: any) => Promise<boolean> | boolean;
  message: string;
  severity: 'error' | 'warning';
}

export interface ValidationContext {
  user?: AuthenticatedUser;
  operation?: string;
  resource?: string;
  metadata?: Record<string, any>;
}

export interface ValidationResult {
  isValid: boolean;
  errors: ValidationErrorDetail[];
  warnings: ValidationErrorDetail[];
  sanitizedData?: any;
}

export class ValidationService {
  private customRules: Map<string, ValidationRule> = new Map();

  constructor(private logger: Logger) {
    this.registerDefaultRules();
  }

  registerRule(rule: ValidationRule): void {
    this.customRules.set(rule.name, rule);
  }

  async validateWithSchema(
    data: any,
    schema: ZodSchema,
    context?: ValidationContext
  ): Promise<ValidationResult> {
    try {
      // Pre-process data
      const processedData = await this.preprocessData(data, context);
      
      // Validate with Zod schema
      const result = await schema.parseAsync(processedData);
      
      // Apply custom validation rules
      const customValidation = await this.applyCustomRules(result, context);
      
      return {
        isValid: customValidation.errors.length === 0,
        errors: customValidation.errors,
        warnings: customValidation.warnings,
        sanitizedData: result
      };

    } catch (error) {
      if (error instanceof ZodError) {
        return {
          isValid: false,
          errors: this.mapZodErrors(error),
          warnings: []
        };
      }

      throw new ValidationError(
        'Validation processing failed',
        [],
        context
      );
    }
  }

  async validatePhoneNumber(phoneNumber: string): Promise<ValidationResult> {
    const errors: ValidationErrorDetail[] = [];
    
    // Basic format check
    if (!phoneNumber || typeof phoneNumber !== 'string') {
      errors.push({
        field: 'phoneNumber',
        value: phoneNumber,
        message: 'Phone number is required',
        code: 'REQUIRED'
      });
    } else {
      // E.164 format validation
      const e164Regex = /^\+[1-9]\d{1,14}$/;
      if (!e164Regex.test(phoneNumber)) {
        errors.push({
          field: 'phoneNumber',
          value: phoneNumber,
          message: 'Phone number must be in E.164 format (+1234567890)',
          code: 'INVALID_FORMAT'
        });
      }

      // Country code validation
      const countryCode = phoneNumber.substring(1, 3);
      if (!this.isValidCountryCode(countryCode)) {
        errors.push({
          field: 'phoneNumber',
          value: phoneNumber,
          message: 'Invalid country code',
          code: 'INVALID_COUNTRY_CODE'
        });
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings: []
    };
  }

  async validateBusinessRules(
    operation: string,
    data: any,
    context: ValidationContext
  ): Promise<ValidationResult> {
    const errors: ValidationErrorDetail[] = [];
    const warnings: ValidationErrorDetail[] = [];

    switch (operation) {
      case 'number_purchase':
        const purchaseValidation = await this.validateNumberPurchase(data, context);
        errors.push(...purchaseValidation.errors);
        warnings.push(...purchaseValidation.warnings);
        break;

      case 'order_creation':
        const orderValidation = await this.validateOrderCreation(data, context);
        errors.push(...orderValidation.errors);
        warnings.push(...orderValidation.warnings);
        break;

      case 'user_registration':
        const registrationValidation = await this.validateUserRegistration(data, context);
        errors.push(...registrationValidation.errors);
        warnings.push(...registrationValidation.warnings);
        break;
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  private async validateNumberPurchase(
    data: any,
    context: ValidationContext
  ): Promise<{ errors: ValidationErrorDetail[]; warnings: ValidationErrorDetail[] }> {
    const errors: ValidationErrorDetail[] = [];
    const warnings: ValidationErrorDetail[] = [];

    // Check purchase limits
    if (data.numbers && data.numbers.length > 10) {
      errors.push({
        field: 'numbers',
        value: data.numbers.length,
        message: 'Cannot purchase more than 10 numbers at once',
        code: 'PURCHASE_LIMIT_EXCEEDED'
      });
    }

    // Check user balance (if applicable)
    if (context.user) {
      const hasInsufficientBalance = await this.checkUserBalance(
        context.user.id,
        this.calculatePurchaseCost(data.numbers)
      );
      
      if (hasInsufficientBalance) {
        errors.push({
          field: 'billing',
          value: 'insufficient_balance',
          message: 'Insufficient account balance for this purchase',
          code: 'INSUFFICIENT_BALANCE'
        });
      }
    }

    // Check for duplicate numbers in request
    if (data.numbers) {
      const phoneNumbers = data.numbers.map((n: any) => n.phoneNumber);
      const duplicates = phoneNumbers.filter((num: string, index: number) => 
        phoneNumbers.indexOf(num) !== index
      );
      
      if (duplicates.length > 0) {
        errors.push({
          field: 'numbers',
          value: duplicates,
          message: 'Duplicate phone numbers in request',
          code: 'DUPLICATE_NUMBERS'
        });
      }
    }

    return { errors, warnings };
  }

  private async validateOrderCreation(
    data: any,
    context: ValidationContext
  ): Promise<{ errors: ValidationErrorDetail[]; warnings: ValidationErrorDetail[] }> {
    const errors: ValidationErrorDetail[] = [];
    const warnings: ValidationErrorDetail[] = [];

    // Validate order items
    if (!data.items || !Array.isArray(data.items) || data.items.length === 0) {
      errors.push({
        field: 'items',
        value: data.items,
        message: 'Order must contain at least one item',
        code: 'EMPTY_ORDER'
      });
    }

    // Validate total amount
    const calculatedTotal = this.calculateOrderTotal(data.items);
    if (Math.abs(calculatedTotal - data.totalAmount) > 0.01) {
      errors.push({
        field: 'totalAmount',
        value: data.totalAmount,
        message: 'Total amount does not match calculated total',
        code: 'AMOUNT_MISMATCH'
      });
    }

    return { errors, warnings };
  }

  private async validateUserRegistration(
    data: any,
    context: ValidationContext
  ): Promise<{ errors: ValidationErrorDetail[]; warnings: ValidationErrorDetail[] }> {
    const errors: ValidationErrorDetail[] = [];
    const warnings: ValidationErrorDetail[] = [];

    // Check email uniqueness
    if (data.email) {
      const emailExists = await this.checkEmailExists(data.email);
      if (emailExists) {
        errors.push({
          field: 'email',
          value: data.email,
          message: 'Email address is already registered',
          code: 'EMAIL_EXISTS'
        });
      }
    }

    // Password strength validation
    if (data.password) {
      const passwordStrength = this.calculatePasswordStrength(data.password);
      if (passwordStrength < 3) {
        warnings.push({
          field: 'password',
          value: '[REDACTED]',
          message: 'Password strength is weak. Consider using a stronger password.',
          code: 'WEAK_PASSWORD'
        });
      }
    }

    return { errors, warnings };
  }

  private async preprocessData(data: any, context?: ValidationContext): Promise<any> {
    if (!data || typeof data !== 'object') {
      return data;
    }

    const processed = { ...data };

    // Sanitize strings
    for (const [key, value] of Object.entries(processed)) {
      if (typeof value === 'string') {
        processed[key] = this.sanitizeString(value);
      } else if (typeof value === 'object' && value !== null) {
        processed[key] = await this.preprocessData(value, context);
      }
    }

    return processed;
  }

  private sanitizeString(input: string): string {
    return input
      .trim()
      .replace(/[<>]/g, '') // Remove angle brackets
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/on\w+=/gi, ''); // Remove event handlers
  }

  private async applyCustomRules(
    data: any,
    context?: ValidationContext
  ): Promise<{ errors: ValidationErrorDetail[]; warnings: ValidationErrorDetail[] }> {
    const errors: ValidationErrorDetail[] = [];
    const warnings: ValidationErrorDetail[] = [];

    for (const [name, rule] of this.customRules.entries()) {
      try {
        const isValid = await rule.validator(data, context);
        
        if (!isValid) {
          const detail: ValidationErrorDetail = {
            field: name,
            value: data,
            message: rule.message,
            code: name.toUpperCase()
          };

          if (rule.severity === 'error') {
            errors.push(detail);
          } else {
            warnings.push(detail);
          }
        }
      } catch (error) {
        this.logger.warn(`Custom validation rule '${name}' failed`, error);
      }
    }

    return { errors, warnings };
  }

  private mapZodErrors(zodError: ZodError): ValidationErrorDetail[] {
    return zodError.errors.map(error => ({
      field: error.path.join('.'),
      value: error.received,
      message: error.message,
      code: error.code.toUpperCase(),
      constraint: error.constraint
    }));
  }

  private registerDefaultRules(): void {
    this.registerRule({
      name: 'no_profanity',
      validator: (value: any) => {
        if (typeof value === 'string') {
          const profanityWords = ['spam', 'scam']; // Add your profanity list
          return !profanityWords.some(word => 
            value.toLowerCase().includes(word)
          );
        }
        return true;
      },
      message: 'Content contains inappropriate language',
      severity: 'error'
    });

    this.registerRule({
      name: 'reasonable_limits',
      validator: (data: any) => {
        if (data.numbers && Array.isArray(data.numbers)) {
          return data.numbers.length <= 100; // Reasonable limit
        }
        return true;
      },
      message: 'Request exceeds reasonable limits',
      severity: 'warning'
    });
  }

  // Helper methods
  private isValidCountryCode(code: string): boolean {
    const validCodes = ['1', '44', '49', '33', '39', '34', '81', '86']; // Add more
    return validCodes.includes(code);
  }

  private async checkUserBalance(userId: string, requiredAmount: number): Promise<boolean> {
    // Implementation would check user's actual balance
    return false; // Placeholder
  }

  private calculatePurchaseCost(numbers: any[]): number {
    return numbers.length * 1.00; // $1 per number placeholder
  }

  private calculateOrderTotal(items: any[]): number {
    return items.reduce((total, item) => total + (item.price * item.quantity), 0);
  }

  private async checkEmailExists(email: string): Promise<boolean> {
    // Implementation would check database
    return false; // Placeholder
  }

  private calculatePasswordStrength(password: string): number {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[^a-zA-Z\d]/.test(password)) strength++;
    return strength;
  }
}
```

## 5. Input Sanitization & Security

### 5.1 Security Validation Service

```typescript
// src/validation/security-validation.service.ts
export interface SecurityValidationConfig {
  enableXSSProtection: boolean;
  enableSQLInjectionProtection: boolean;
  enableCommandInjectionProtection: boolean;
  maxInputLength: number;
  allowedFileTypes: string[];
  blockedPatterns: RegExp[];
}

export class SecurityValidationService {
  private config: SecurityValidationConfig;

  constructor(config: SecurityValidationConfig) {
    this.config = config;
  }

  validateInput(input: any, fieldName: string): ValidationResult {
    const errors: ValidationErrorDetail[] = [];
    
    if (typeof input === 'string') {
      // XSS validation
      if (this.config.enableXSSProtection && this.containsXSS(input)) {
        errors.push({
          field: fieldName,
          value: '[REDACTED]',
          message: 'Input contains potentially malicious content',
          code: 'XSS_DETECTED'
        });
      }

      // SQL injection validation
      if (this.config.enableSQLInjectionProtection && this.containsSQLInjection(input)) {
        errors.push({
          field: fieldName,
          value: '[REDACTED]',
          message: 'Input contains SQL injection patterns',
          code: 'SQL_INJECTION_DETECTED'
        });
      }

      // Command injection validation
      if (this.config.enableCommandInjectionProtection && this.containsCommandInjection(input)) {
        errors.push({
          field: fieldName,
          value: '[REDACTED]',
          message: 'Input contains command injection patterns',
          code: 'COMMAND_INJECTION_DETECTED'
        });
      }

      // Length validation
      if (input.length > this.config.maxInputLength) {
        errors.push({
          field: fieldName,
          value: input.length,
          message: `Input exceeds maximum length of ${this.config.maxInputLength}`,
          code: 'INPUT_TOO_LONG'
        });
      }

      // Custom blocked patterns
      for (const pattern of this.config.blockedPatterns) {
        if (pattern.test(input)) {
          errors.push({
            field: fieldName,
            value: '[REDACTED]',
            message: 'Input contains blocked content',
            code: 'BLOCKED_PATTERN'
          });
        }
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings: [],
      sanitizedData: this.sanitizeInput(input)
    };
  }

  sanitizeInput(input: any): any {
    if (typeof input === 'string') {
      return input
        .replace(/[<>]/g, '') // Remove angle brackets
        .replace(/javascript:/gi, '') // Remove javascript: protocol
        .replace(/on\w+=/gi, '') // Remove event handlers
        .replace(/data:/gi, '') // Remove data: protocol
        .replace(/vbscript:/gi, '') // Remove vbscript: protocol
        .trim();
    }

    if (typeof input === 'object' && input !== null) {
      const sanitized: any = Array.isArray(input) ? [] : {};
      
      for (const [key, value] of Object.entries(input)) {
        sanitized[key] = this.sanitizeInput(value);
      }
      
      return sanitized;
    }

    return input;
  }

  private containsXSS(input: string): boolean {
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
      /on\w+\s*=/gi,
      /javascript:/gi,
      /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
      /<embed\b[^>]*>/gi,
      /<form\b[^<]*(?:(?!<\/form>)<[^<]*)*<\/form>/gi
    ];

    return xssPatterns.some(pattern => pattern.test(input));
  }

  private containsSQLInjection(input: string): boolean {
    const sqlPatterns = [
      /('|(\\')|(;)|(\\;)|(--)|(\s+or\s+)|(\s+and\s+)|(\s+union\s+)|(\s+select\s+)|(\s+insert\s+)|(\s+update\s+)|(\s+delete\s+)|(\s+drop\s+)|(\s+create\s+)|(\s+alter\s+))/gi,
      /(\*|%|_)/g,
      /(exec|execute|sp_|xp_)/gi
    ];

    return sqlPatterns.some(pattern => pattern.test(input));
  }

  private containsCommandInjection(input: string): boolean {
    const commandPatterns = [
      /(\||&|;|\$\(|\`)/g,
      /(rm|cat|ls|ps|kill|wget|curl|nc|netcat)/gi,
      /(\.\.\/|\.\.\\)/g
    ];

    return commandPatterns.some(pattern => pattern.test(input));
  }
}
```

This comprehensive error handling and validation system provides enterprise-grade error management, validation, and security features with complete TypeScript implementations for the DID buy system.
