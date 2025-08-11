# Twilio Integration - Complete Implementation Guide

## 1. Overview

This document provides comprehensive documentation for integrating Twilio's telephony services into the DID buy system, including TypeScript implementations, webhook handling, call routing, and advanced features.

## 2. Twilio SDK Configuration

### 2.1 Environment Setup

```typescript
// src/config/twilio.config.ts
export interface TwilioConfiguration {
  accountSid: string;
  authToken: string;
  webhookSecret: string;
  baseUrl: string;
  timeout: number;
  retryConfig: {
    maxRetries: number;
    retryDelay: number;
    backoffFactor: number;
  };
  rateLimit: {
    requestsPerSecond: number;
    burstLimit: number;
  };
  features: {
    voiceEnabled: boolean;
    smsEnabled: boolean;
    mmsEnabled: boolean;
    faxEnabled: boolean;
    recordingEnabled: boolean;
    transcriptionEnabled: boolean;
  };
}

export const twilioConfig: TwilioConfiguration = {
  accountSid: process.env.TWILIO_ACCOUNT_SID!,
  authToken: process.env.TWILIO_AUTH_TOKEN!,
  webhookSecret: process.env.TWILIO_WEBHOOK_SECRET!,
  baseUrl: process.env.TWILIO_BASE_URL || 'https://api.twilio.com',
  timeout: parseInt(process.env.TWILIO_TIMEOUT || '30000'),
  retryConfig: {
    maxRetries: 3,
    retryDelay: 1000,
    backoffFactor: 2
  },
  rateLimit: {
    requestsPerSecond: 100,
    burstLimit: 200
  },
  features: {
    voiceEnabled: true,
    smsEnabled: true,
    mmsEnabled: true,
    faxEnabled: false,
    recordingEnabled: true,
    transcriptionEnabled: true
  }
};
```

### 2.2 Twilio Client Factory

```typescript
// src/factories/twilio.factory.ts
import { Twilio } from 'twilio';
import { Logger } from 'winston';
import { TwilioConfiguration } from '../config/twilio.config';

export interface TwilioClientFactory {
  createClient(): Twilio;
  createSubaccountClient(subaccountSid: string): Twilio;
  validateCredentials(): Promise<boolean>;
}

export class TwilioClientFactoryImpl implements TwilioClientFactory {
  constructor(
    private config: TwilioConfiguration,
    private logger: Logger
  ) {}

  createClient(): Twilio {
    const client = new Twilio(
      this.config.accountSid,
      this.config.authToken,
      {
        accountSid: this.config.accountSid,
        httpRetryInterval: this.config.retryConfig.retryDelay,
        httpRetryLimit: this.config.retryConfig.maxRetries,
        timeout: this.config.timeout,
        logLevel: process.env.NODE_ENV === 'development' ? 'debug' : 'warn'
      }
    );

    this.setupClientInterceptors(client);
    return client;
  }

  createSubaccountClient(subaccountSid: string): Twilio {
    return new Twilio(
      this.config.accountSid,
      this.config.authToken,
      {
        accountSid: subaccountSid,
        timeout: this.config.timeout,
        logLevel: 'warn'
      }
    );
  }

  async validateCredentials(): Promise<boolean> {
    try {
      const client = this.createClient();
      await client.api.accounts(this.config.accountSid).fetch();
      return true;
    } catch (error) {
      this.logger.error('Twilio credentials validation failed', error);
      return false;
    }
  }

  private setupClientInterceptors(client: Twilio): void {
    // Add request/response logging and monitoring
    const originalRequest = client.request.bind(client);
    
    client.request = async (opts: any) => {
      const startTime = Date.now();
      
      this.logger.debug('Twilio API Request', {
        method: opts.method,
        uri: opts.uri,
        timestamp: new Date().toISOString()
      });

      try {
        const response = await originalRequest(opts);
        
        this.logger.debug('Twilio API Response', {
          method: opts.method,
          uri: opts.uri,
          duration: Date.now() - startTime,
          status: response.statusCode
        });

        return response;
      } catch (error) {
        this.logger.error('Twilio API Error', {
          method: opts.method,
          uri: opts.uri,
          duration: Date.now() - startTime,
          error: error.message
        });
        throw error;
      }
    };
  }
}
```

## 3. Phone Number Management

### 3.1 Advanced Number Search

```typescript
// src/services/twilio/number-search.service.ts
import { Twilio } from 'twilio';
import { Logger } from 'winston';
import { Redis } from 'ioredis';

export interface NumberSearchFilters {
  countryCode: string;
  areaCode?: string;
  contains?: string;
  excludePattern?: string;
  nearLatLong?: string;
  distance?: number;
  locality?: string;
  region?: string;
  postalCode?: string;
  inRateCenter?: string;
  inRegion?: string;
  nearNumber?: string;
  faxEnabled?: boolean;
  smsEnabled?: boolean;
  mmsEnabled?: boolean;
  voiceEnabled?: boolean;
  betaNumbers?: boolean;
  limit?: number;
}

export interface NumberSearchResult {
  phoneNumber: string;
  friendlyName: string;
  locality: string;
  region: string;
  postalCode: string;
  countryCode: string;
  capabilities: {
    voice: boolean;
    sms: boolean;
    mms: boolean;
    fax: boolean;
  };
  pricing: {
    monthlyPrice: string;
    currency: string;
  };
  restrictions: string[];
  rateCenter: string;
  latitude: number;
  longitude: number;
  lata: string;
  addressRequirements: string;
}

export class TwilioNumberSearchService {
  constructor(
    private twilioClient: Twilio,
    private redis: Redis,
    private logger: Logger
  ) {}

  async searchNumbers(filters: NumberSearchFilters): Promise<NumberSearchResult[]> {
    try {
      const cacheKey = this.generateCacheKey(filters);
      
      // Check cache first
      const cachedResults = await this.getCachedResults(cacheKey);
      if (cachedResults) {
        return cachedResults;
      }

      // Search different number types
      const searchPromises = [];
      
      if (filters.countryCode === 'US' || filters.countryCode === 'CA') {
        // Search local numbers
        searchPromises.push(this.searchLocalNumbers(filters));
        
        // Search toll-free numbers if no area code specified
        if (!filters.areaCode) {
          searchPromises.push(this.searchTollFreeNumbers(filters));
        }
        
        // Search mobile numbers
        searchPromises.push(this.searchMobileNumbers(filters));
      } else {
        // International numbers
        searchPromises.push(this.searchInternationalNumbers(filters));
      }

      const results = await Promise.allSettled(searchPromises);
      const allNumbers: NumberSearchResult[] = [];

      results.forEach((result) => {
        if (result.status === 'fulfilled') {
          allNumbers.push(...result.value);
        } else {
          this.logger.warn('Number search partial failure', result.reason);
        }
      });

      // Apply additional filtering
      const filteredNumbers = this.applyClientSideFilters(allNumbers, filters);
      
      // Sort by preference (local first, then toll-free, then mobile)
      const sortedNumbers = this.sortNumbersByPreference(filteredNumbers);
      
      // Limit results
      const limitedResults = sortedNumbers.slice(0, filters.limit || 50);

      // Cache results for 5 minutes
      await this.cacheResults(cacheKey, limitedResults, 300);

      return limitedResults;

    } catch (error) {
      this.logger.error('Number search failed', { filters, error });
      throw new TwilioServiceError('Number search failed', error);
    }
  }

  private async searchLocalNumbers(filters: NumberSearchFilters): Promise<NumberSearchResult[]> {
    const searchOptions: any = {
      areaCode: filters.areaCode,
      contains: filters.contains,
      nearLatLong: filters.nearLatLong,
      distance: filters.distance,
      locality: filters.locality,
      region: filters.region,
      postalCode: filters.postalCode,
      inRateCenter: filters.inRateCenter,
      inRegion: filters.inRegion,
      nearNumber: filters.nearNumber,
      excludeAllAddressRequired: true,
      limit: 20
    };

    const numbers = await this.twilioClient
      .availablePhoneNumbers(filters.countryCode)
      .local
      .list(searchOptions);

    return numbers.map(this.mapTwilioNumber);
  }

  private async searchTollFreeNumbers(filters: NumberSearchFilters): Promise<NumberSearchResult[]> {
    const searchOptions: any = {
      contains: filters.contains,
      limit: 10
    };

    const numbers = await this.twilioClient
      .availablePhoneNumbers(filters.countryCode)
      .tollFree
      .list(searchOptions);

    return numbers.map(this.mapTwilioNumber);
  }

  private async searchMobileNumbers(filters: NumberSearchFilters): Promise<NumberSearchResult[]> {
    try {
      const searchOptions: any = {
        areaCode: filters.areaCode,
        contains: filters.contains,
        limit: 10
      };

      const numbers = await this.twilioClient
        .availablePhoneNumbers(filters.countryCode)
        .mobile
        .list(searchOptions);

      return numbers.map(this.mapTwilioNumber);
    } catch (error) {
      // Mobile numbers might not be available in all regions
      this.logger.warn('Mobile number search failed', { filters, error });
      return [];
    }
  }

  private async searchInternationalNumbers(filters: NumberSearchFilters): Promise<NumberSearchResult[]> {
    const searchOptions: any = {
      contains: filters.contains,
      limit: 20
    };

    const numbers = await this.twilioClient
      .availablePhoneNumbers(filters.countryCode)
      .local
      .list(searchOptions);

    return numbers.map(this.mapTwilioNumber);
  }

  private mapTwilioNumber = (twilioNumber: any): NumberSearchResult => {
    return {
      phoneNumber: twilioNumber.phoneNumber,
      friendlyName: twilioNumber.friendlyName || '',
      locality: twilioNumber.locality || '',
      region: twilioNumber.region || '',
      postalCode: twilioNumber.postalCode || '',
      countryCode: twilioNumber.isoCountry || '',
      capabilities: {
        voice: twilioNumber.capabilities?.voice || false,
        sms: twilioNumber.capabilities?.sms || false,
        mms: twilioNumber.capabilities?.mms || false,
        fax: twilioNumber.capabilities?.fax || false
      },
      pricing: {
        monthlyPrice: '1.00', // Would come from pricing API
        currency: 'USD'
      },
      restrictions: twilioNumber.beta ? ['beta'] : [],
      rateCenter: twilioNumber.rateCenter || '',
      latitude: twilioNumber.latitude || 0,
      longitude: twilioNumber.longitude || 0,
      lata: twilioNumber.lata || '',
      addressRequirements: twilioNumber.addressRequirements || 'none'
    };
  };

  private applyClientSideFilters(
    numbers: NumberSearchResult[],
    filters: NumberSearchFilters
  ): NumberSearchResult[] {
    return numbers.filter(number => {
      // Filter by capabilities
      if (filters.voiceEnabled && !number.capabilities.voice) return false;
      if (filters.smsEnabled && !number.capabilities.sms) return false;
      if (filters.mmsEnabled && !number.capabilities.mms) return false;
      if (filters.faxEnabled && !number.capabilities.fax) return false;
      
      // Filter by exclusion pattern
      if (filters.excludePattern && new RegExp(filters.excludePattern).test(number.phoneNumber)) {
        return false;
      }
      
      // Filter beta numbers
      if (!filters.betaNumbers && number.restrictions.includes('beta')) {
        return false;
      }

      return true;
    });
  }

  private sortNumbersByPreference(numbers: NumberSearchResult[]): NumberSearchResult[] {
    return numbers.sort((a, b) => {
      // Prioritize by number type (local > toll-free > mobile)
      const getTypeScore = (number: NumberSearchResult): number => {
        if (number.phoneNumber.includes('800') || number.phoneNumber.includes('888') || 
            number.phoneNumber.includes('877') || number.phoneNumber.includes('866')) {
          return 2; // Toll-free
        }
        return 1; // Local/Mobile
      };

      const scoreA = getTypeScore(a);
      const scoreB = getTypeScore(b);

      if (scoreA !== scoreB) {
        return scoreA - scoreB;
      }

      // Then by capabilities (more capabilities first)
      const capCountA = Object.values(a.capabilities).filter(Boolean).length;
      const capCountB = Object.values(b.capabilities).filter(Boolean).length;

      return capCountB - capCountA;
    });
  }

  private generateCacheKey(filters: NumberSearchFilters): string {
    const normalized = {
      ...filters,
      // Normalize for consistent caching
      limit: undefined // Don't include limit in cache key
    };
    return `number_search:${Buffer.from(JSON.stringify(normalized)).toString('base64')}`;
  }

  private async getCachedResults(cacheKey: string): Promise<NumberSearchResult[] | null> {
    try {
      const cached = await this.redis.get(cacheKey);
      return cached ? JSON.parse(cached) : null;
    } catch (error) {
      this.logger.warn('Cache retrieval failed', { cacheKey, error });
      return null;
    }
  }

  private async cacheResults(
    cacheKey: string,
    results: NumberSearchResult[],
    ttlSeconds: number
  ): Promise<void> {
    try {
      await this.redis.setex(cacheKey, ttlSeconds, JSON.stringify(results));
    } catch (error) {
      this.logger.warn('Cache storage failed', { cacheKey, error });
    }
  }
}
```

### 3.2 Number Purchase and Configuration

```typescript
// src/services/twilio/number-management.service.ts
export interface NumberPurchaseOptions {
  phoneNumber: string;
  friendlyName?: string;
  voiceUrl?: string;
  voiceMethod?: 'GET' | 'POST';
  voiceFallbackUrl?: string;
  voiceFallbackMethod?: 'GET' | 'POST';
  statusCallback?: string;
  statusCallbackMethod?: 'GET' | 'POST';
  voiceCallerIdLookup?: boolean;
  smsUrl?: string;
  smsMethod?: 'GET' | 'POST';
  smsFallbackUrl?: string;
  smsFallbackMethod?: 'GET' | 'POST';
  addressSid?: string;
  emergencyStatus?: 'Active' | 'Inactive';
  emergencyAddressSid?: string;
  trunkSid?: string;
  identitySid?: string;
  bundleSid?: string;
}

export interface PurchasedNumberInfo {
  sid: string;
  phoneNumber: string;
  friendlyName: string;
  accountSid: string;
  status: string;
  capabilities: {
    voice: boolean;
    sms: boolean;
    mms: boolean;
    fax: boolean;
  };
  voiceUrl: string | null;
  smsUrl: string | null;
  statusCallback: string | null;
  dateCreated: Date;
  dateUpdated: Date;
  origin: string;
}

export class TwilioNumberManagementService {
  constructor(
    private twilioClient: Twilio,
    private logger: Logger
  ) {}

  async purchaseNumber(options: NumberPurchaseOptions): Promise<PurchasedNumberInfo> {
    try {
      this.logger.info('Purchasing number', { phoneNumber: options.phoneNumber });

      const purchaseOptions: any = {
        phoneNumber: options.phoneNumber,
        friendlyName: options.friendlyName,
        voiceUrl: options.voiceUrl,
        voiceMethod: options.voiceMethod || 'POST',
        voiceFallbackUrl: options.voiceFallbackUrl,
        voiceFallbackMethod: options.voiceFallbackMethod || 'POST',
        statusCallback: options.statusCallback,
        statusCallbackMethod: options.statusCallbackMethod || 'POST',
        voiceCallerIdLookup: options.voiceCallerIdLookup || false,
        smsUrl: options.smsUrl,
        smsMethod: options.smsMethod || 'POST',
        smsFallbackUrl: options.smsFallbackUrl,
        smsFallbackMethod: options.smsFallbackMethod || 'POST'
      };

      // Add optional parameters if provided
      if (options.addressSid) purchaseOptions.addressSid = options.addressSid;
      if (options.emergencyStatus) purchaseOptions.emergencyStatus = options.emergencyStatus;
      if (options.emergencyAddressSid) purchaseOptions.emergencyAddressSid = options.emergencyAddressSid;
      if (options.trunkSid) purchaseOptions.trunkSid = options.trunkSid;
      if (options.identitySid) purchaseOptions.identitySid = options.identitySid;
      if (options.bundleSid) purchaseOptions.bundleSid = options.bundleSid;

      const purchasedNumber = await this.twilioClient.incomingPhoneNumbers.create(purchaseOptions);

      this.logger.info('Number purchased successfully', {
        phoneNumber: options.phoneNumber,
        sid: purchasedNumber.sid
      });

      return this.mapPurchasedNumber(purchasedNumber);

    } catch (error) {
      this.logger.error('Number purchase failed', {
        phoneNumber: options.phoneNumber,
        error: error.message,
        code: error.code
      });

      throw this.handleTwilioError(error);
    }
  }

  async updateNumberConfiguration(
    numberSid: string,
    updates: Partial<NumberPurchaseOptions>
  ): Promise<PurchasedNumberInfo> {
    try {
      this.logger.info('Updating number configuration', { numberSid, updates });

      const updatedNumber = await this.twilioClient
        .incomingPhoneNumbers(numberSid)
        .update(updates);

      this.logger.info('Number configuration updated', { numberSid });

      return this.mapPurchasedNumber(updatedNumber);

    } catch (error) {
      this.logger.error('Number update failed', { numberSid, error });
      throw this.handleTwilioError(error);
    }
  }

  async releaseNumber(numberSid: string): Promise<void> {
    try {
      this.logger.info('Releasing number', { numberSid });

      await this.twilioClient.incomingPhoneNumbers(numberSid).remove();

      this.logger.info('Number released successfully', { numberSid });

    } catch (error) {
      this.logger.error('Number release failed', { numberSid, error });
      throw this.handleTwilioError(error);
    }
  }

  async getNumberInfo(numberSid: string): Promise<PurchasedNumberInfo> {
    try {
      const number = await this.twilioClient.incomingPhoneNumbers(numberSid).fetch();
      return this.mapPurchasedNumber(number);
    } catch (error) {
      this.logger.error('Get number info failed', { numberSid, error });
      throw this.handleTwilioError(error);
    }
  }

  async listAccountNumbers(): Promise<PurchasedNumberInfo[]> {
    try {
      const numbers = await this.twilioClient.incomingPhoneNumbers.list({ limit: 1000 });
      return numbers.map(this.mapPurchasedNumber);
    } catch (error) {
      this.logger.error('List numbers failed', error);
      throw this.handleTwilioError(error);
    }
  }

  private mapPurchasedNumber = (twilioNumber: any): PurchasedNumberInfo => {
    return {
      sid: twilioNumber.sid,
      phoneNumber: twilioNumber.phoneNumber,
      friendlyName: twilioNumber.friendlyName || '',
      accountSid: twilioNumber.accountSid,
      status: twilioNumber.status,
      capabilities: {
        voice: twilioNumber.capabilities?.voice || false,
        sms: twilioNumber.capabilities?.sms || false,
        mms: twilioNumber.capabilities?.mms || false,
        fax: twilioNumber.capabilities?.fax || false
      },
      voiceUrl: twilioNumber.voiceUrl,
      smsUrl: twilioNumber.smsUrl,
      statusCallback: twilioNumber.statusCallback,
      dateCreated: new Date(twilioNumber.dateCreated),
      dateUpdated: new Date(twilioNumber.dateUpdated),
      origin: twilioNumber.origin || ''
    };
  };

  private handleTwilioError(error: any): TwilioServiceError {
    const errorMap: Record<number, string> = {
      20404: 'Phone number not found',
      21422: 'Phone number is not available for purchase',
      21450: 'Insufficient account balance',
      21451: 'Invalid phone number format',
      21452: 'Phone number already owned by your account',
      21453: 'Phone number not supported in your region',
      21454: 'Phone number requires address verification'
    };

    const message = errorMap[error.code] || error.message || 'Unknown Twilio error';
    
    return new TwilioServiceError(message, error.code, error);
  }
}
```

## 4. Webhook Management

### 4.1 Webhook Handler Framework

```typescript
// src/services/twilio/webhook.service.ts
import { Request, Response } from 'express';
import { Twilio } from 'twilio';
import { Logger } from 'winston';
import { EventEmitter } from 'events';

export interface WebhookEvent {
  type: string;
  timestamp: Date;
  data: Record<string, any>;
  source: 'twilio';
  accountSid: string;
  signature: string;
  requestId: string;
}

export interface WebhookHandlerResult {
  success: boolean;
  response?: string;
  statusCode?: number;
  error?: string;
}

export abstract class BaseWebhookHandler {
  abstract handle(event: WebhookEvent): Promise<WebhookHandlerResult>;
  abstract canHandle(eventType: string): boolean;
}

export class TwilioWebhookService {
  private handlers: Map<string, BaseWebhookHandler> = new Map();

  constructor(
    private config: { authToken: string; webhookUrl: string },
    private eventEmitter: EventEmitter,
    private logger: Logger
  ) {
    this.registerDefaultHandlers();
  }

  registerHandler(eventType: string, handler: BaseWebhookHandler): void {
    this.handlers.set(eventType, handler);
    this.logger.info('Webhook handler registered', { eventType });
  }

  async processWebhook(req: Request, res: Response): Promise<void> {
    try {
      // Validate webhook signature
      if (!this.validateWebhookSignature(req)) {
        this.logger.warn('Invalid webhook signature', {
          url: req.url,
          headers: req.headers
        });
        res.status(403).send('Invalid signature');
        return;
      }

      // Parse webhook event
      const event = this.parseWebhookEvent(req);
      
      // Find appropriate handler
      const handler = this.findHandler(event.type);
      if (!handler) {
        this.logger.warn('No handler found for webhook event', { eventType: event.type });
        res.status(200).send('OK'); // Still return 200 to prevent retries
        return;
      }

      // Process event
      const result = await handler.handle(event);

      // Emit event for other systems
      this.eventEmitter.emit('webhook.processed', {
        event,
        result,
        processingTime: Date.now() - event.timestamp.getTime()
      });

      // Send response
      res.status(result.statusCode || 200);
      if (result.response) {
        res.type('text/xml').send(result.response);
      } else {
        res.send('OK');
      }

    } catch (error) {
      this.logger.error('Webhook processing failed', {
        error: error.message,
        stack: error.stack,
        body: req.body
      });

      res.status(500).send('Internal server error');
    }
  }

  private validateWebhookSignature(req: Request): boolean {
    try {
      const signature = req.headers['x-twilio-signature'] as string;
      if (!signature) return false;

      const url = `${this.config.webhookUrl}${req.url}`;
      const body = req.body;

      return Twilio.validateRequest(
        this.config.authToken,
        body,
        url,
        signature
      );
    } catch (error) {
      this.logger.error('Signature validation error', error);
      return false;
    }
  }

  private parseWebhookEvent(req: Request): WebhookEvent {
    const body = req.body;
    const eventType = this.determineEventType(req.url, body);

    return {
      type: eventType,
      timestamp: new Date(),
      data: body,
      source: 'twilio',
      accountSid: body.AccountSid || '',
      signature: req.headers['x-twilio-signature'] as string,
      requestId: req.headers['x-request-id'] as string || ''
    };
  }

  private determineEventType(url: string, body: any): string {
    if (url.includes('/voice/')) {
      if (body.CallStatus) {
        return `voice.${body.CallStatus.toLowerCase()}`;
      }
      return 'voice.unknown';
    }

    if (url.includes('/sms/')) {
      if (body.SmsStatus) {
        return `sms.${body.SmsStatus.toLowerCase()}`;
      }
      if (body.MessageStatus) {
        return `sms.${body.MessageStatus.toLowerCase()}`;
      }
      return 'sms.received';
    }

    if (url.includes('/status/')) {
      return 'status.update';
    }

    return 'unknown';
  }

  private findHandler(eventType: string): BaseWebhookHandler | undefined {
    // Try exact match first
    let handler = this.handlers.get(eventType);
    if (handler) return handler;

    // Try pattern matching
    for (const [pattern, handlerInstance] of this.handlers.entries()) {
      if (handlerInstance.canHandle(eventType)) {
        return handlerInstance;
      }
    }

    return undefined;
  }

  private registerDefaultHandlers(): void {
    this.registerHandler('voice.*', new VoiceWebhookHandler(this.logger));
    this.registerHandler('sms.*', new SmsWebhookHandler(this.logger));
    this.registerHandler('status.*', new StatusWebhookHandler(this.logger));
  }
}
```

### 4.2 Specific Webhook Handlers

```typescript
// src/services/twilio/handlers/voice-webhook.handler.ts
export class VoiceWebhookHandler extends BaseWebhookHandler {
  constructor(private logger: Logger) {
    super();
  }

  canHandle(eventType: string): boolean {
    return eventType.startsWith('voice.');
  }

  async handle(event: WebhookEvent): Promise<WebhookHandlerResult> {
    const { data } = event;
    
    try {
      switch (event.type) {
        case 'voice.ringing':
          return this.handleCallRinging(data);
        case 'voice.answered':
          return this.handleCallAnswered(data);
        case 'voice.completed':
          return this.handleCallCompleted(data);
        case 'voice.failed':
          return this.handleCallFailed(data);
        case 'voice.busy':
          return this.handleCallBusy(data);
        case 'voice.no-answer':
          return this.handleCallNoAnswer(data);
        default:
          return this.handleIncomingCall(data);
      }
    } catch (error) {
      this.logger.error('Voice webhook handling failed', { event, error });
      return { success: false, error: error.message };
    }
  }

  private async handleIncomingCall(data: any): Promise<WebhookHandlerResult> {
    this.logger.info('Incoming call received', {
      callSid: data.CallSid,
      from: data.From,
      to: data.To
    });

    // Generate TwiML response for call routing
    const twiml = this.generateCallRoutingTwiML(data);

    return {
      success: true,
      response: twiml,
      statusCode: 200
    };
  }

  private async handleCallCompleted(data: any): Promise<WebhookHandlerResult> {
    this.logger.info('Call completed', {
      callSid: data.CallSid,
      callDuration: data.CallDuration,
      callStatus: data.CallStatus
    });

    // Store call log in database
    await this.storeCallLog(data);

    return { success: true };
  }

  private generateCallRoutingTwiML(callData: any): string {
    // This would be configurable based on number settings
    const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="alice">Welcome to our service. Please hold while we connect you.</Say>
    <Dial timeout="30" record="record-from-answer">
        <Number>+1234567890</Number>
    </Dial>
    <Say voice="alice">Sorry, no one is available. Please leave a message after the beep.</Say>
    <Record maxLength="300" transcribe="true" />
</Response>`;

    return twiml;
  }

  private async storeCallLog(data: any): Promise<void> {
    // Implementation would store call data in database
    this.logger.debug('Storing call log', { callSid: data.CallSid });
  }

  // Other handler methods...
  private async handleCallRinging(data: any): Promise<WebhookHandlerResult> {
    return { success: true };
  }

  private async handleCallAnswered(data: any): Promise<WebhookHandlerResult> {
    return { success: true };
  }

  private async handleCallFailed(data: any): Promise<WebhookHandlerResult> {
    return { success: true };
  }

  private async handleCallBusy(data: any): Promise<WebhookHandlerResult> {
    return { success: true };
  }

  private async handleCallNoAnswer(data: any): Promise<WebhookHandlerResult> {
    return { success: true };
  }
}
```

## 5. Advanced Call Routing

### 5.1 Dynamic Call Routing Engine

```typescript
// src/services/twilio/routing/call-routing.service.ts
export interface RoutingRule {
  id: string;
  name: string;
  priority: number;
  conditions: RoutingCondition[];
  actions: RoutingAction[];
  enabled: boolean;
  schedule?: TimeSchedule;
}

export interface RoutingCondition {
  type: 'caller_id' | 'geographic' | 'time' | 'queue_size' | 'agent_availability';
  operator: 'equals' | 'contains' | 'starts_with' | 'in_list' | 'not_in_list' | 'greater_than' | 'less_than';
  value: any;
}

export interface RoutingAction {
  type: 'forward' | 'voicemail' | 'queue' | 'ivr' | 'conference' | 'reject' | 'say';
  parameters: Record<string, any>;
}

export interface TimeSchedule {
  timezone: string;
  businessHours: {
    dayOfWeek: number[];
    startTime: string;
    endTime: string;
  }[];
  holidays: string[];
}

export class CallRoutingService {
  constructor(
    private prisma: PrismaClient,
    private logger: Logger
  ) {}

  async routeCall(phoneNumber: string, callData: any): Promise<string> {
    try {
      // Get routing rules for the number
      const rules = await this.getRoutingRules(phoneNumber);
      
      // Evaluate rules in priority order
      const matchedRule = await this.evaluateRules(rules, callData);
      
      if (matchedRule) {
        this.logger.info('Call routing rule matched', {
          phoneNumber,
          ruleId: matchedRule.id,
          ruleName: matchedRule.name,
          callSid: callData.CallSid
        });

        return this.executeRoutingActions(matchedRule.actions, callData);
      }

      // Default routing if no rules match
      return this.getDefaultRouting(phoneNumber, callData);

    } catch (error) {
      this.logger.error('Call routing failed', { phoneNumber, callData, error });
      return this.getFailoverRouting(callData);
    }
  }

  private async getRoutingRules(phoneNumber: string): Promise<RoutingRule[]> {
    // Get from database based on phone number configuration
    const numberConfig = await this.prisma.number.findUnique({
      where: { phoneNumber },
      include: { configurations: true }
    });

    if (!numberConfig || !numberConfig.configurations.length) {
      return [];
    }

    // Convert database configuration to routing rules
    return numberConfig.configurations
      .filter(config => config.isActive)
      .map(config => this.parseRoutingRules(config.routingRules as any))
      .flat()
      .sort((a, b) => a.priority - b.priority);
  }

  private async evaluateRules(rules: RoutingRule[], callData: any): Promise<RoutingRule | null> {
    for (const rule of rules) {
      if (!rule.enabled) continue;

      // Check schedule if defined
      if (rule.schedule && !this.isWithinSchedule(rule.schedule)) {
        continue;
      }

      // Evaluate all conditions
      const allConditionsMet = await this.evaluateConditions(rule.conditions, callData);
      
      if (allConditionsMet) {
        return rule;
      }
    }

    return null;
  }

  private async evaluateConditions(conditions: RoutingCondition[], callData: any): Promise<boolean> {
    for (const condition of conditions) {
      const result = await this.evaluateCondition(condition, callData);
      if (!result) {
        return false;
      }
    }
    return true;
  }

  private async evaluateCondition(condition: RoutingCondition, callData: any): Promise<boolean> {
    const contextValue = this.getContextValue(condition.type, callData);
    
    switch (condition.operator) {
      case 'equals':
        return contextValue === condition.value;
      case 'contains':
        return String(contextValue).includes(String(condition.value));
      case 'starts_with':
        return String(contextValue).startsWith(String(condition.value));
      case 'in_list':
        return Array.isArray(condition.value) && condition.value.includes(contextValue);
      case 'not_in_list':
        return Array.isArray(condition.value) && !condition.value.includes(contextValue);
      case 'greater_than':
        return Number(contextValue) > Number(condition.value);
      case 'less_than':
        return Number(contextValue) < Number(condition.value);
      default:
        return false;
    }
  }

  private getContextValue(type: string, callData: any): any {
    switch (type) {
      case 'caller_id':
        return callData.From;
      case 'geographic':
        return callData.FromCity || callData.FromState || callData.FromCountry;
      case 'time':
        return new Date().getHours();
      case 'queue_size':
        // Would integrate with queue management system
        return 0;
      case 'agent_availability':
        // Would integrate with agent management system
        return true;
      default:
        return null;
    }
  }

  private isWithinSchedule(schedule: TimeSchedule): boolean {
    const now = new Date();
    const timezone = schedule.timezone || 'UTC';
    
    // Convert to specified timezone
    const localTime = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      hour: '2-digit',
      minute: '2-digit',
      weekday: 'numeric'
    }).formatToParts(now);

    const currentHour = parseInt(localTime.find(part => part.type === 'hour')?.value || '0');
    const currentMinute = parseInt(localTime.find(part => part.type === 'minute')?.value || '0');
    const currentDay = parseInt(localTime.find(part => part.type === 'weekday')?.value || '0');
    const currentTime = currentHour * 60 + currentMinute;

    // Check if current day/time is within business hours
    for (const businessHour of schedule.businessHours) {
      if (businessHour.dayOfWeek.includes(currentDay)) {
        const [startHour, startMinute] = businessHour.startTime.split(':').map(Number);
        const [endHour, endMinute] = businessHour.endTime.split(':').map(Number);
        const startTime = startHour * 60 + startMinute;
        const endTime = endHour * 60 + endMinute;

        if (currentTime >= startTime && currentTime <= endTime) {
          return true;
        }
      }
    }

    return false;
  }

  private executeRoutingActions(actions: RoutingAction[], callData: any): string {
    let twiml = '<?xml version="1.0" encoding="UTF-8"?>\n<Response>';

    for (const action of actions) {
      switch (action.type) {
        case 'say':
          twiml += `\n  <Say voice="${action.parameters.voice || 'alice'}">${action.parameters.message}</Say>`;
          break;
        case 'forward':
          twiml += this.generateForwardTwiML(action.parameters);
          break;
        case 'voicemail':
          twiml += this.generateVoicemailTwiML(action.parameters);
          break;
        case 'queue':
          twiml += this.generateQueueTwiML(action.parameters);
          break;
        case 'ivr':
          twiml += this.generateIVRTwiML(action.parameters);
          break;
        case 'conference':
          twiml += this.generateConferenceTwiML(action.parameters);
          break;
        case 'reject':
          twiml += '\n  <Reject />';
          break;
      }
    }

    twiml += '\n</Response>';
    return twiml;
  }

  private generateForwardTwiML(params: any): string {
    const timeout = params.timeout || 30;
    const record = params.record ? ' record="record-from-answer"' : '';
    
    let dialTwiML = `\n  <Dial timeout="${timeout}"${record}>`;
    
    if (params.numbers && Array.isArray(params.numbers)) {
      for (const number of params.numbers) {
        dialTwiML += `\n    <Number>${number}</Number>`;
      }
    } else if (params.sipUri) {
      dialTwiML += `\n    <Sip>${params.sipUri}</Sip>`;
    }
    
    dialTwiML += '\n  </Dial>';
    return dialTwiML;
  }

  private generateVoicemailTwiML(params: any): string {
    const maxLength = params.maxLength || 300;
    const transcribe = params.transcribe || false;
    
    return `\n  <Say voice="alice">${params.greeting || 'Please leave a message after the beep.'}</Say>
  <Record maxLength="${maxLength}" transcribe="${transcribe}" />`;
  }

  private generateQueueTwiML(params: any): string {
    const waitUrl = params.waitUrl || '';
    const maxWait = params.maxWait || 300;
    
    return `\n  <Enqueue waitUrl="${waitUrl}" maxWait="${maxWait}">${params.queueName || 'default'}</Enqueue>`;
  }

  private generateIVRTwiML(params: any): string {
    let ivrTwiML = `\n  <Gather input="dtmf" timeout="${params.timeout || 5}" numDigits="${params.numDigits || 1}" action="${params.action}">`;
    ivrTwiML += `\n    <Say voice="alice">${params.prompt}</Say>`;
    ivrTwiML += '\n  </Gather>';
    return ivrTwiML;
  }

  private generateConferenceTwiML(params: any): string {
    const attributes = [];
    if (params.muted) attributes.push('muted="true"');
    if (params.startConferenceOnEnter === false) attributes.push('startConferenceOnEnter="false"');
    if (params.endConferenceOnExit) attributes.push('endConferenceOnExit="true"');
    
    const attributeString = attributes.length > 0 ? ' ' + attributes.join(' ') : '';
    
    return `\n  <Dial>
    <Conference${attributeString}>${params.conferenceName}</Conference>
  </Dial>`;
  }

  private getDefaultRouting(phoneNumber: string, callData: any): string {
    return `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="alice">Thank you for calling. All our representatives are currently busy. Please leave a message and we'll get back to you shortly.</Say>
  <Record maxLength="300" transcribe="true" />
</Response>`;
  }

  private getFailoverRouting(callData: any): string {
    return `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="alice">We're sorry, but we're experiencing technical difficulties. Please try calling again later.</Say>
  <Hangup />
</Response>`;
  }

  private parseRoutingRules(routingRulesJson: any): RoutingRule[] {
    // Convert JSON configuration to RoutingRule objects
    try {
      return Array.isArray(routingRulesJson) ? routingRulesJson : [routingRulesJson];
    } catch (error) {
      this.logger.error('Failed to parse routing rules', { routingRulesJson, error });
      return [];
    }
  }
}
```

## 6. Error Handling and Monitoring

### 6.1 Twilio Error Handler

```typescript
// src/services/twilio/error-handler.service.ts
export class TwilioServiceError extends Error {
  constructor(
    message: string,
    public code?: number,
    public originalError?: any,
    public retryable: boolean = false
  ) {
    super(message);
    this.name = 'TwilioServiceError';
  }
}

export class TwilioErrorHandler {
  private static readonly RETRYABLE_ERRORS = [
    20003, // Internal Server Error
    20004, // Request Timeout
    20005, // Gateway Timeout
    20007, // Service Unavailable
    81003, // Max execution time exceeded
  ];

  private static readonly ERROR_CATEGORIES = {
    AUTHENTICATION: [20003, 20004],
    AUTHORIZATION: [20003, 20004],
    VALIDATION: [21201, 21202, 21210, 21211, 21212, 21213, 21214, 21215, 21216, 21217, 21219, 21220],
    RESOURCE_NOT_FOUND: [20404],
    RATE_LIMITING: [20429],
    INSUFFICIENT_FUNDS: [21450],
    NETWORK: [20005, 20007],
    SERVICE_UNAVAILABLE: [20007, 81003]
  };

  static handleError(error: any): TwilioServiceError {
    const code = error.code || error.status;
    const message = error.message || 'Unknown Twilio error';
    const retryable = this.isRetryableError(code);

    const category = this.categorizeError(code);
    const userFriendlyMessage = this.getUserFriendlyMessage(code, category);

    return new TwilioServiceError(
      userFriendlyMessage || message,
      code,
      error,
      retryable
    );
  }

  static isRetryableError(code: number): boolean {
    return this.RETRYABLE_ERRORS.includes(code);
  }

  static categorizeError(code: number): string {
    for (const [category, codes] of Object.entries(this.ERROR_CATEGORIES)) {
      if (codes.includes(code)) {
        return category;
      }
    }
    return 'UNKNOWN';
  }

  static getUserFriendlyMessage(code: number, category: string): string {
    const messages: Record<number, string> = {
      20404: 'The requested resource was not found',
      21422: 'This phone number is not available for purchase',
      21450: 'Insufficient account balance to complete this operation',
      21451: 'Invalid phone number format',
      21452: 'This phone number is already owned by your account',
      21453: 'Phone number not supported in your region',
      21454: 'Address verification required for this phone number',
      20429: 'Too many requests. Please try again later',
      20003: 'Authentication failed. Please check your credentials',
      20007: 'Service temporarily unavailable. Please try again later'
    };

    return messages[code] || `Service error (${category})`;
  }
}
```

### 6.2 Monitoring and Metrics

```typescript
// src/services/twilio/monitoring.service.ts
export interface TwilioMetrics {
  apiCalls: {
    total: number;
    successful: number;
    failed: number;
    averageResponseTime: number;
  };
  webhooks: {
    received: number;
    processed: number;
    failed: number;
    averageProcessingTime: number;
  };
  numbers: {
    purchased: number;
    released: number;
    active: number;
  };
  calls: {
    total: number;
    completed: number;
    failed: number;
    averageDuration: number;
  };
  costs: {
    totalSpent: number;
    currency: string;
    breakdown: {
      numbers: number;
      calls: number;
      sms: number;
      other: number;
    };
  };
}

export class TwilioMonitoringService {
  constructor(
    private redis: Redis,
    private logger: Logger
  ) {}

  async recordApiCall(
    method: string,
    endpoint: string,
    responseTime: number,
    success: boolean,
    errorCode?: number
  ): Promise<void> {
    const timestamp = new Date();
    const key = `twilio_metrics:api:${timestamp.toISOString().split('T')[0]}`;

    try {
      await this.redis.hincrby(key, 'total_calls', 1);
      await this.redis.hincrby(key, success ? 'successful_calls' : 'failed_calls', 1);
      await this.redis.hincrby(key, 'total_response_time', responseTime);
      
      if (errorCode) {
        await this.redis.hincrby(key, `error_${errorCode}`, 1);
      }

      // Set expiry for 30 days
      await this.redis.expire(key, 30 * 24 * 60 * 60);

    } catch (error) {
      this.logger.error('Failed to record API call metrics', error);
    }
  }

  async recordWebhookEvent(
    eventType: string,
    processingTime: number,
    success: boolean
  ): Promise<void> {
    const timestamp = new Date();
    const key = `twilio_metrics:webhooks:${timestamp.toISOString().split('T')[0]}`;

    try {
      await this.redis.hincrby(key, 'total_webhooks', 1);
      await this.redis.hincrby(key, success ? 'successful_webhooks' : 'failed_webhooks', 1);
      await this.redis.hincrby(key, 'total_processing_time', processingTime);
      await this.redis.hincrby(key, `event_${eventType}`, 1);

      await this.redis.expire(key, 30 * 24 * 60 * 60);

    } catch (error) {
      this.logger.error('Failed to record webhook metrics', error);
    }
  }

  async getMetrics(date?: string): Promise<TwilioMetrics> {
    const targetDate = date || new Date().toISOString().split('T')[0];
    
    try {
      const [apiMetrics, webhookMetrics] = await Promise.all([
        this.redis.hgetall(`twilio_metrics:api:${targetDate}`),
        this.redis.hgetall(`twilio_metrics:webhooks:${targetDate}`)
      ]);

      return this.buildMetricsResponse(apiMetrics, webhookMetrics);

    } catch (error) {
      this.logger.error('Failed to get metrics', error);
      return this.getEmptyMetrics();
    }
  }

  private buildMetricsResponse(
    apiMetrics: Record<string, string>,
    webhookMetrics: Record<string, string>
  ): TwilioMetrics {
    const totalApiCalls = parseInt(apiMetrics.total_calls || '0');
    const totalWebhooks = parseInt(webhookMetrics.total_webhooks || '0');

    return {
      apiCalls: {
        total: totalApiCalls,
        successful: parseInt(apiMetrics.successful_calls || '0'),
        failed: parseInt(apiMetrics.failed_calls || '0'),
        averageResponseTime: totalApiCalls > 0 
          ? parseInt(apiMetrics.total_response_time || '0') / totalApiCalls 
          : 0
      },
      webhooks: {
        received: totalWebhooks,
        processed: parseInt(webhookMetrics.successful_webhooks || '0'),
        failed: parseInt(webhookMetrics.failed_webhooks || '0'),
        averageProcessingTime: totalWebhooks > 0 
          ? parseInt(webhookMetrics.total_processing_time || '0') / totalWebhooks 
          : 0
      },
      numbers: {
        purchased: 0, // Would come from database
        released: 0,
        active: 0
      },
      calls: {
        total: 0, // Would come from call logs
        completed: 0,
        failed: 0,
        averageDuration: 0
      },
      costs: {
        totalSpent: 0, // Would come from billing data
        currency: 'USD',
        breakdown: {
          numbers: 0,
          calls: 0,
          sms: 0,
          other: 0
        }
      }
    };
  }

  private getEmptyMetrics(): TwilioMetrics {
    return {
      apiCalls: { total: 0, successful: 0, failed: 0, averageResponseTime: 0 },
      webhooks: { received: 0, processed: 0, failed: 0, averageProcessingTime: 0 },
      numbers: { purchased: 0, released: 0, active: 0 },
      calls: { total: 0, completed: 0, failed: 0, averageDuration: 0 },
      costs: { totalSpent: 0, currency: 'USD', breakdown: { numbers: 0, calls: 0, sms: 0, other: 0 } }
    };
  }
}
```

This comprehensive Twilio integration documentation provides complete TypeScript implementations for all aspects of telephony integration, from number management to advanced call routing and monitoring. The modular architecture ensures scalability and maintainability while providing enterprise-grade features.
