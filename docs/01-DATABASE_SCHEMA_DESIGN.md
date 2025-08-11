# Database Schema Design & TypeScript Types

## 1. Overview

This document provides comprehensive database schema design for the DID buy system using Prisma ORM with PostgreSQL, including all TypeScript types and interfaces.

## 2. Database Architecture

### 2.1 Technology Stack
- **Database**: PostgreSQL 15+
- **ORM**: Prisma 5.x
- **Type Generation**: Prisma Client TypeScript
- **Migrations**: Prisma Migrate
- **Connection Pooling**: PgBouncer (Production)

### 2.2 Schema Design Principles
- **Normalization**: 3NF compliance for data integrity
- **Indexing**: Strategic indexing for performance
- **Constraints**: Foreign keys and check constraints
- **Audit Trail**: CreatedAt/UpdatedAt timestamps
- **Soft Deletes**: Status-based deletion for critical data

## 3. Complete Prisma Schema

```prisma
// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

// ================================
// USER MANAGEMENT
// ================================

model User {
  id                        String    @id @default(cuid())
  email                     String    @unique
  password                  String
  firstName                 String
  lastName                  String
  company                   String?
  phone                     String?
  avatar                    String?
  timezone                  String    @default("UTC")
  language                  String    @default("en")
  
  // Email verification
  emailVerified             Boolean   @default(false)
  emailVerificationToken    String?   @unique
  emailVerificationExpires  DateTime?
  
  // Password reset
  passwordResetToken        String?   @unique
  passwordResetExpires      DateTime?
  
  // Account status
  isActive                  Boolean   @default(true)
  isSuspended               Boolean   @default(false)
  suspensionReason          String?
  lastLoginAt               DateTime?
  role                      UserRole  @default(USER)
  
  // Preferences
  preferences               Json      @default("{}")
  
  // Metadata
  createdAt                 DateTime  @default(now())
  updatedAt                 DateTime  @updatedAt

  // Relationships
  numbers                   Number[]
  orders                    Order[]
  billingAccount            BillingAccount?
  sessions                  Session[]
  apiKeys                   ApiKey[]
  webhookEndpoints          WebhookEndpoint[]
  callLogs                  CallLog[]
  notifications            Notification[]
  auditLogs                AuditLog[]

  @@map("users")
  @@index([email])
  @@index([isActive, isSuspended])
  @@index([createdAt])
}

model Session {
  id              String    @id @default(cuid())
  userId          String
  refreshToken    String    @unique
  accessToken     String?
  expiresAt       DateTime
  isRevoked       Boolean   @default(false)
  deviceInfo      Json?
  ipAddress       String?
  userAgent       String?
  createdAt       DateTime  @default(now())
  revokedAt       DateTime?

  // Relationships
  user            User      @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("sessions")
  @@index([userId])
  @@index([refreshToken])
  @@index([expiresAt])
}

model ApiKey {
  id              String      @id @default(cuid())
  userId          String
  name            String
  keyHash         String      @unique
  keyPrefix       String
  permissions     String[]    // ['read:numbers', 'write:numbers', etc.]
  isActive        Boolean     @default(true)
  expiresAt       DateTime?
  lastUsedAt      DateTime?
  usageCount      Int         @default(0)
  createdAt       DateTime    @default(now())
  updatedAt       DateTime    @updatedAt

  // Relationships
  user            User        @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("api_keys")
  @@index([userId])
  @@index([keyHash])
  @@index([isActive])
}

// ================================
// PHONE NUMBER MANAGEMENT
// ================================

model Number {
  id                String          @id @default(cuid())
  phoneNumber       String          @unique
  friendlyName      String?
  countryCode       String          // ISO country code (US, CA, GB, etc.)
  region            String?         // State/Province
  locality          String?         // City
  postalCode        String?         // ZIP/Postal code
  areaCode          String?         // Area code
  numberType        NumberType
  capabilities      NumberCapability[]
  
  // Twilio-specific data
  twilioSid         String          @unique
  twilioAccountSid  String
  
  // Pricing
  monthlyPrice      Decimal         @db.Money
  setupPrice        Decimal?        @db.Money
  currency          String          @default("USD")
  
  // Configuration
  voiceUrl          String?
  voiceMethod       HttpMethod?     @default(POST)
  voiceFallbackUrl  String?
  voiceFallbackMethod HttpMethod?   @default(POST)
  statusCallback    String?
  statusCallbackMethod HttpMethod?  @default(POST)
  voiceCallerIdLookup Boolean       @default(false)
  
  // SMS Configuration (if capable)
  smsUrl            String?
  smsMethod         HttpMethod?     @default(POST)
  smsFallbackUrl    String?
  smsFallbackMethod HttpMethod?     @default(POST)
  
  // Status and lifecycle
  status            NumberStatus    @default(ACTIVE)
  purchasedAt       DateTime        @default(now())
  releasedAt        DateTime?
  
  // Ownership
  userId            String
  orderId           String?
  
  // Usage tracking
  totalCalls        Int             @default(0)
  totalSms          Int             @default(0)
  lastUsedAt        DateTime?
  
  // Metadata
  tags              String[]        @default([])
  notes             String?
  createdAt         DateTime        @default(now())
  updatedAt         DateTime        @updatedAt

  // Relationships
  user              User            @relation(fields: [userId], references: [id])
  order             Order?          @relation(fields: [orderId], references: [id])
  callLogs          CallLog[]
  smsLogs           SmsLog[]
  configurations    NumberConfiguration[]

  @@map("numbers")
  @@index([userId])
  @@index([phoneNumber])
  @@index([countryCode, areaCode])
  @@index([status])
  @@index([numberType])
  @@index([twilioSid])
}

model NumberConfiguration {
  id              String      @id @default(cuid())
  numberId        String
  name            String      // Configuration name (e.g., "Business Hours", "After Hours")
  isActive        Boolean     @default(false)
  
  // Time-based routing
  scheduleEnabled Boolean     @default(false)
  schedule        Json?       // Cron-like schedule configuration
  timezone        String?
  
  // Routing rules
  routingRules    Json        // Complex routing logic
  fallbackRules   Json?       // Fallback routing
  
  // Call handling
  recordCalls     Boolean     @default(false)
  callScreening   Boolean     @default(false)
  callQueue       Boolean     @default(false)
  maxQueueSize    Int?
  queueMusic      String?     // URL to hold music
  
  // Advanced features
  conferenceEnabled Boolean   @default(false)
  voicemailEnabled Boolean    @default(true)
  callForwarding  Json?       // Forwarding rules
  
  createdAt       DateTime    @default(now())
  updatedAt       DateTime    @updatedAt

  // Relationships
  number          Number      @relation(fields: [numberId], references: [id], onDelete: Cascade)

  @@map("number_configurations")
  @@index([numberId])
  @@index([isActive])
}

// ================================
// ORDER MANAGEMENT
// ================================

model Order {
  id                String        @id @default(cuid())
  orderNumber       String        @unique
  userId            String
  status            OrderStatus   @default(PENDING)
  
  // Financial
  subtotalAmount    Decimal       @db.Money
  taxAmount         Decimal       @default(0) @db.Money
  discountAmount    Decimal       @default(0) @db.Money
  totalAmount       Decimal       @db.Money
  currency          String        @default("USD")
  
  // Payment
  paymentIntentId   String?       @unique
  paymentStatus     PaymentStatus @default(PENDING)
  paymentMethod     String?
  paymentProcessor  String?       // 'stripe', 'paypal', etc.
  
  // Order metadata
  orderSource       String?       // 'web', 'api', 'mobile'
  promotionCode     String?
  
  // Billing address
  billingAddress    Json?
  
  // Processing
  processedAt       DateTime?
  completedAt       DateTime?
  cancelledAt       DateTime?
  cancellationReason String?
  
  // Timestamps
  createdAt         DateTime      @default(now())
  updatedAt         DateTime      @updatedAt

  // Relationships
  user              User          @relation(fields: [userId], references: [id])
  numbers           Number[]
  orderItems        OrderItem[]
  payments          Payment[]

  @@map("orders")
  @@index([userId])
  @@index([orderNumber])
  @@index([status])
  @@index([createdAt])
}

model OrderItem {
  id              String      @id @default(cuid())
  orderId         String
  itemType        OrderItemType
  itemId          String?     // Reference to specific item (numberId, etc.)
  description     String
  quantity        Int         @default(1)
  unitPrice       Decimal     @db.Money
  totalPrice      Decimal     @db.Money
  metadata        Json?       // Additional item data
  
  createdAt       DateTime    @default(now())

  // Relationships
  order           Order       @relation(fields: [orderId], references: [id], onDelete: Cascade)

  @@map("order_items")
  @@index([orderId])
}

// ================================
// BILLING & PAYMENTS
// ================================

model BillingAccount {
  id                String      @id @default(cuid())
  userId            String      @unique
  
  // External payment processor IDs
  stripeCustomerId  String?     @unique
  paypalCustomerId  String?     @unique
  
  // Company information
  company           String?
  taxId             String?
  vatNumber         String?
  
  // Billing address
  billingAddress    Json
  
  // Account financials
  accountBalance    Decimal     @default(0) @db.Money
  creditLimit       Decimal?    @db.Money
  currency          String      @default("USD")
  
  // Payment settings
  autoPayEnabled    Boolean     @default(false)
  defaultPaymentMethod String?  // Payment method ID
  
  // Account status
  isActive          Boolean     @default(true)
  isSuspended       Boolean     @default(false)
  suspensionReason  String?
  
  // Billing cycle
  billingCycle      BillingCycle @default(MONTHLY)
  nextBillingDate   DateTime?
  
  createdAt         DateTime    @default(now())
  updatedAt         DateTime    @updatedAt

  // Relationships
  user              User        @relation(fields: [userId], references: [id], onDelete: Cascade)
  invoices          Invoice[]
  payments          Payment[]
  paymentMethods    PaymentMethod[]
  usageRecords      UsageRecord[]

  @@map("billing_accounts")
  @@index([userId])
  @@index([stripeCustomerId])
}

model PaymentMethod {
  id                String          @id @default(cuid())
  billingAccountId  String
  externalId        String          // Payment processor ID
  processor         PaymentProcessor
  type              PaymentMethodType
  
  // Card details (if applicable)
  last4             String?
  brand             String?         // visa, mastercard, etc.
  expiryMonth       Int?
  expiryYear        Int?
  
  // Bank details (if applicable)
  bankName          String?
  accountType       String?         // checking, savings
  
  // Status
  isDefault         Boolean         @default(false)
  isVerified        Boolean         @default(false)
  isActive          Boolean         @default(true)
  
  createdAt         DateTime        @default(now())
  updatedAt         DateTime        @updatedAt

  // Relationships
  billingAccount    BillingAccount  @relation(fields: [billingAccountId], references: [id], onDelete: Cascade)
  payments          Payment[]

  @@map("payment_methods")
  @@index([billingAccountId])
  @@index([externalId])
}

model Invoice {
  id                String        @id @default(cuid())
  invoiceNumber     String        @unique
  billingAccountId  String
  
  // Invoice details
  subtotalAmount    Decimal       @db.Money
  taxAmount         Decimal       @default(0) @db.Money
  discountAmount    Decimal       @default(0) @db.Money
  totalAmount       Decimal       @db.Money
  currency          String        @default("USD")
  
  // Dates
  issueDate         DateTime      @default(now())
  dueDate           DateTime
  paidDate          DateTime?
  
  // Status
  status            InvoiceStatus @default(DRAFT)
  
  // Billing period
  periodStart       DateTime
  periodEnd         DateTime
  
  // Line items (stored as JSON for flexibility)
  lineItems         Json
  
  // Payment tracking
  amountPaid        Decimal       @default(0) @db.Money
  amountDue         Decimal       @db.Money
  
  // Metadata
  notes             String?
  paymentTerms      String?       // Net 30, etc.
  
  createdAt         DateTime      @default(now())
  updatedAt         DateTime      @updatedAt

  // Relationships
  billingAccount    BillingAccount @relation(fields: [billingAccountId], references: [id])
  payments          Payment[]

  @@map("invoices")
  @@index([billingAccountId])
  @@index([invoiceNumber])
  @@index([status])
  @@index([dueDate])
}

model Payment {
  id                String          @id @default(cuid())
  billingAccountId  String
  orderId           String?
  invoiceId         String?
  paymentMethodId   String?
  
  // Payment details
  amount            Decimal         @db.Money
  currency          String          @default("USD")
  status            PaymentStatus
  processor         PaymentProcessor
  
  // External references
  externalId        String?         // Payment processor transaction ID
  externalStatus    String?         // Processor-specific status
  
  // Payment metadata
  description       String?
  failureReason     String?
  processorFee      Decimal?        @db.Money
  
  // Timestamps
  processedAt       DateTime?
  failedAt          DateTime?
  refundedAt        DateTime?
  createdAt         DateTime        @default(now())
  updatedAt         DateTime        @updatedAt

  // Relationships
  billingAccount    BillingAccount  @relation(fields: [billingAccountId], references: [id])
  order             Order?          @relation(fields: [orderId], references: [id])
  invoice           Invoice?        @relation(fields: [invoiceId], references: [id])
  paymentMethod     PaymentMethod?  @relation(fields: [paymentMethodId], references: [id])

  @@map("payments")
  @@index([billingAccountId])
  @@index([status])
  @@index([externalId])
}

// ================================
// USAGE TRACKING & ANALYTICS
// ================================

model CallLog {
  id                String        @id @default(cuid())
  userId            String
  numberId          String?
  
  // Twilio call data
  twilioCallSid     String        @unique
  twilioAccountSid  String
  
  // Call participants
  fromNumber        String
  toNumber          String
  direction         CallDirection
  
  // Call status and timing
  status            CallStatus
  answerTime        DateTime?
  endTime           DateTime?
  duration          Int?          // Duration in seconds
  billableDuration  Int?          // Billable duration in seconds
  
  // Call quality and features
  quality           CallQuality?
  recordingUrl      String?
  recordingSid      String?
  transcription     String?
  
  // Pricing
  price             Decimal?      @db.Money
  priceUnit         String?       // per minute, per call, etc.
  currency          String        @default("USD")
  
  // Geographic data
  fromCity          String?
  fromState         String?
  fromCountry       String?
  toCity            String?
  toState           String?
  toCountry         String?
  
  // Call metadata
  userAgent         String?
  callReason        String?       // business, support, sales, etc.
  tags              String[]      @default([])
  
  createdAt         DateTime      @default(now())

  // Relationships
  user              User          @relation(fields: [userId], references: [id])
  number            Number?       @relation(fields: [numberId], references: [id])

  @@map("call_logs")
  @@index([userId])
  @@index([numberId])
  @@index([twilioCallSid])
  @@index([direction])
  @@index([status])
  @@index([createdAt])
}

model SmsLog {
  id                String        @id @default(cuid())
  numberId          String
  
  // Twilio SMS data
  twilioMessageSid  String        @unique
  twilioAccountSid  String
  
  // Message participants
  fromNumber        String
  toNumber          String
  direction         SmsDirection
  
  // Message content
  body              String
  mediaUrls         String[]      @default([])
  
  // Status and timing
  status            SmsStatus
  sentAt            DateTime?
  deliveredAt       DateTime?
  
  // Pricing
  price             Decimal?      @db.Money
  currency          String        @default("USD")
  
  // Error handling
  errorCode         String?
  errorMessage      String?
  
  createdAt         DateTime      @default(now())

  // Relationships
  number            Number        @relation(fields: [numberId], references: [id])

  @@map("sms_logs")
  @@index([numberId])
  @@index([twilioMessageSid])
  @@index([direction])
  @@index([status])
  @@index([createdAt])
}

model UsageRecord {
  id                String        @id @default(cuid())
  billingAccountId  String
  recordType        UsageType
  resourceId        String?       // numberId, callSid, etc.
  
  // Usage details
  quantity          Decimal       @db.Decimal(10,4)
  unit              String        // minutes, messages, numbers
  unitPrice         Decimal       @db.Money
  totalCost         Decimal       @db.Money
  currency          String        @default("USD")
  
  // Time period
  usageDate         DateTime
  billingPeriod     String        // YYYY-MM format
  
  // Metadata
  description       String?
  metadata          Json?
  
  createdAt         DateTime      @default(now())

  // Relationships
  billingAccount    BillingAccount @relation(fields: [billingAccountId], references: [id])

  @@map("usage_records")
  @@index([billingAccountId])
  @@index([recordType])
  @@index([usageDate])
  @@index([billingPeriod])
}

// ================================
// SYSTEM & CONFIGURATION
// ================================

model WebhookEndpoint {
  id              String          @id @default(cuid())
  userId          String
  url             String
  events          WebhookEvent[]
  isActive        Boolean         @default(true)
  secret          String          // For webhook signature verification
  
  // Configuration
  retryPolicy     Json            // Retry configuration
  timeout         Int             @default(30) // Timeout in seconds
  
  // Status
  lastDeliveryAt  DateTime?
  lastStatus      String?
  deliveryCount   Int             @default(0)
  failureCount    Int             @default(0)
  
  createdAt       DateTime        @default(now())
  updatedAt       DateTime        @updatedAt

  // Relationships
  user            User            @relation(fields: [userId], references: [id], onDelete: Cascade)
  deliveries      WebhookDelivery[]

  @@map("webhook_endpoints")
  @@index([userId])
  @@index([isActive])
}

model WebhookDelivery {
  id                String          @id @default(cuid())
  webhookEndpointId String
  event             WebhookEvent
  payload           Json
  
  // Delivery details
  httpStatus        Int?
  responseBody      String?
  deliveredAt       DateTime?
  
  // Retry information
  attemptCount      Int             @default(0)
  nextRetryAt       DateTime?
  
  // Status
  status            DeliveryStatus  @default(PENDING)
  errorMessage      String?
  
  createdAt         DateTime        @default(now())
  updatedAt         DateTime        @updatedAt

  // Relationships
  webhookEndpoint   WebhookEndpoint @relation(fields: [webhookEndpointId], references: [id], onDelete: Cascade)

  @@map("webhook_deliveries")
  @@index([webhookEndpointId])
  @@index([status])
  @@index([nextRetryAt])
}

model Notification {
  id              String            @id @default(cuid())
  userId          String
  type            NotificationType
  title           String
  message         String
  
  // Delivery channels
  channels        NotificationChannel[]
  
  // Status
  isRead          Boolean           @default(false)
  readAt          DateTime?
  
  // Scheduling
  scheduledFor    DateTime?
  deliveredAt     DateTime?
  
  // Priority and categorization
  priority        NotificationPriority @default(MEDIUM)
  category        String?
  
  // Action links
  actionUrl       String?
  actionText      String?
  
  // Metadata
  metadata        Json?
  expiresAt       DateTime?
  
  createdAt       DateTime          @default(now())
  updatedAt       DateTime          @updatedAt

  // Relationships
  user            User              @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("notifications")
  @@index([userId])
  @@index([type])
  @@index([isRead])
  @@index([scheduledFor])
}

model AuditLog {
  id              String      @id @default(cuid())
  userId          String?
  action          String      // CREATE, UPDATE, DELETE, etc.
  resource        String      // table/model name
  resourceId      String?     // ID of the affected resource
  
  // Change tracking
  oldValues       Json?
  newValues       Json?
  
  // Request context
  ipAddress       String?
  userAgent       String?
  endpoint        String?     // API endpoint
  method          String?     // HTTP method
  
  // Status
  success         Boolean     @default(true)
  errorMessage    String?
  
  createdAt       DateTime    @default(now())

  // Relationships
  user            User?       @relation(fields: [userId], references: [id])

  @@map("audit_logs")
  @@index([userId])
  @@index([action])
  @@index([resource])
  @@index([createdAt])
}

// ================================
// ENUMS
// ================================

enum UserRole {
  USER
  ADMIN
  SUPER_ADMIN
  DEVELOPER
  SUPPORT
}

enum NumberType {
  LOCAL
  TOLL_FREE
  MOBILE
  INTERNATIONAL
  PREMIUM
  SHARED_COST
}

enum NumberCapability {
  VOICE
  SMS
  MMS
  FAX
}

enum NumberStatus {
  ACTIVE
  SUSPENDED
  RELEASED
  PENDING
  CONFIGURING
  ERROR
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
  PARTIAL
}

enum OrderItemType {
  PHONE_NUMBER
  MONTHLY_FEE
  SETUP_FEE
  USAGE_FEE
  DISCOUNT
  TAX
}

enum PaymentStatus {
  PENDING
  PROCESSING
  SUCCEEDED
  FAILED
  CANCELLED
  REFUNDED
  PARTIAL_REFUND
}

enum PaymentProcessor {
  STRIPE
  PAYPAL
  BANK_TRANSFER
  CREDIT
}

enum PaymentMethodType {
  CARD
  BANK_ACCOUNT
  DIGITAL_WALLET
}

enum BillingCycle {
  MONTHLY
  QUARTERLY
  ANNUALLY
}

enum InvoiceStatus {
  DRAFT
  SENT
  VIEWED
  PAID
  PARTIAL_PAYMENT
  OVERDUE
  CANCELLED
  REFUNDED
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

enum CallQuality {
  EXCELLENT
  GOOD
  FAIR
  POOR
  BAD
}

enum SmsDirection {
  INBOUND
  OUTBOUND
}

enum SmsStatus {
  QUEUED
  SENT
  DELIVERED
  FAILED
  UNDELIVERED
}

enum UsageType {
  VOICE_MINUTES
  SMS_MESSAGE
  MMS_MESSAGE
  PHONE_NUMBER
  RECORDING_STORAGE
  TRANSCRIPTION
}

enum WebhookEvent {
  CALL_STARTED
  CALL_ANSWERED
  CALL_COMPLETED
  CALL_FAILED
  SMS_RECEIVED
  SMS_SENT
  SMS_DELIVERED
  SMS_FAILED
  NUMBER_PURCHASED
  NUMBER_RELEASED
  PAYMENT_SUCCEEDED
  PAYMENT_FAILED
  INVOICE_CREATED
  INVOICE_PAID
}

enum DeliveryStatus {
  PENDING
  DELIVERED
  FAILED
  RETRYING
  ABANDONED
}

enum NotificationType {
  SYSTEM
  BILLING
  CALL
  SMS
  SECURITY
  MARKETING
  SUPPORT
}

enum NotificationChannel {
  EMAIL
  SMS
  PUSH
  IN_APP
  WEBHOOK
}

enum NotificationPriority {
  LOW
  MEDIUM
  HIGH
  URGENT
}
```

## 4. TypeScript Type Definitions

### 4.1 Generated Prisma Types

```typescript
// src/types/prisma.types.ts
// These are automatically generated by Prisma Client
export type {
  User,
  Session,
  ApiKey,
  Number,
  NumberConfiguration,
  Order,
  OrderItem,
  BillingAccount,
  PaymentMethod,
  Invoice,
  Payment,
  CallLog,
  SmsLog,
  UsageRecord,
  WebhookEndpoint,
  WebhookDelivery,
  Notification,
  AuditLog
} from '@prisma/client';

export type {
  UserRole,
  NumberType,
  NumberCapability,
  NumberStatus,
  HttpMethod,
  OrderStatus,
  OrderItemType,
  PaymentStatus,
  PaymentProcessor,
  PaymentMethodType,
  BillingCycle,
  InvoiceStatus,
  CallDirection,
  CallStatus,
  CallQuality,
  SmsDirection,
  SmsStatus,
  UsageType,
  WebhookEvent,
  DeliveryStatus,
  NotificationType,
  NotificationChannel,
  NotificationPriority
} from '@prisma/client';
```

### 4.2 Custom Type Definitions

```typescript
// src/types/database.types.ts
import { User, Number, Order, CallLog, BillingAccount } from '@prisma/client';

// Extended user type with relationships
export interface UserWithRelations extends User {
  numbers: Number[];
  orders: Order[];
  billingAccount: BillingAccount | null;
  _count: {
    numbers: number;
    orders: number;
    callLogs: number;
  };
}

// Number with full relationships
export interface NumberWithRelations extends Number {
  user: User;
  order: Order | null;
  callLogs: CallLog[];
  configurations: NumberConfiguration[];
  _count: {
    callLogs: number;
    smsLogs: number;
  };
}

// Order with items and payment info
export interface OrderWithDetails extends Order {
  user: User;
  numbers: Number[];
  orderItems: OrderItem[];
  payments: Payment[];
}

// Call log with geographic data
export interface CallLogWithDetails extends CallLog {
  user: User;
  number: Number | null;
  geographic: {
    fromLocation: string;
    toLocation: string;
  };
}

// Billing account with full financial data
export interface BillingAccountWithDetails extends BillingAccount {
  user: User;
  invoices: Invoice[];
  payments: Payment[];
  paymentMethods: PaymentMethod[];
  usageRecords: UsageRecord[];
  accountSummary: {
    totalSpent: number;
    currentBalance: number;
    pendingCharges: number;
  };
}

// Database connection configuration
export interface DatabaseConfig {
  url: string;
  maxConnections: number;
  connectionTimeout: number;
  queryTimeout: number;
  logQueries: boolean;
  enableLogging: boolean;
}

// Search and pagination types
export interface PaginationOptions {
  page: number;
  limit: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface SearchFilters {
  search?: string;
  status?: string[];
  type?: string[];
  dateFrom?: Date;
  dateTo?: Date;
  tags?: string[];
}

export interface PaginatedResult<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrevious: boolean;
  };
}
```

### 4.3 JSON Schema Types

```typescript
// src/types/json-schemas.types.ts

// User preferences JSON structure
export interface UserPreferences {
  theme: 'light' | 'dark' | 'auto';
  language: string;
  timezone: string;
  notifications: {
    email: boolean;
    sms: boolean;
    push: boolean;
    marketing: boolean;
  };
  dashboard: {
    defaultView: 'numbers' | 'analytics' | 'billing';
    chartsType: 'line' | 'bar' | 'pie';
  };
  calling: {
    recordByDefault: boolean;
    transcribeByDefault: boolean;
    blockAnonymous: boolean;
  };
}

// Billing address structure
export interface BillingAddress {
  firstName: string;
  lastName: string;
  company?: string;
  addressLine1: string;
  addressLine2?: string;
  city: string;
  state: string;
  postalCode: string;
  country: string;
}

// Device info for sessions
export interface DeviceInfo {
  platform: string;
  browser: string;
  version: string;
  mobile: boolean;
  os: string;
  screen: {
    width: number;
    height: number;
  };
}

// Number routing rules
export interface RoutingRules {
  defaultAction: 'forward' | 'voicemail' | 'reject' | 'conference';
  timeBasedRules: TimeBasedRule[];
  geographicRules: GeographicRule[];
  callerIdRules: CallerIdRule[];
  failoverRules: FailoverRule[];
}

export interface TimeBasedRule {
  id: string;
  name: string;
  schedule: {
    timezone: string;
    rules: {
      dayOfWeek: number[];
      timeFrom: string; // HH:mm format
      timeTo: string;   // HH:mm format
    }[];
  };
  action: RoutingAction;
  priority: number;
}

export interface GeographicRule {
  id: string;
  name: string;
  countries: string[];
  states?: string[];
  cities?: string[];
  action: RoutingAction;
  priority: number;
}

export interface CallerIdRule {
  id: string;
  name: string;
  patterns: string[]; // Phone number patterns
  action: RoutingAction;
  priority: number;
}

export interface FailoverRule {
  id: string;
  attempts: number;
  delay: number; // seconds
  destinations: string[];
}

export interface RoutingAction {
  type: 'forward' | 'voicemail' | 'reject' | 'conference' | 'ivr';
  destination?: string;
  options?: {
    timeout?: number;
    record?: boolean;
    transcribe?: boolean;
    music?: string;
  };
}

// Invoice line items
export interface InvoiceLineItem {
  id: string;
  description: string;
  quantity: number;
  unitPrice: number;
  totalPrice: number;
  type: 'usage' | 'subscription' | 'one_time' | 'tax' | 'discount';
  period?: {
    start: string;
    end: string;
  };
  details?: {
    resourceId?: string;
    resourceType?: string;
    usageDetails?: UsageDetails;
  };
}

export interface UsageDetails {
  unit: string;
  rate: number;
  quantity: number;
  breakdown: {
    date: string;
    quantity: number;
    cost: number;
  }[];
}

// Webhook retry policy
export interface WebhookRetryPolicy {
  maxAttempts: number;
  backoffStrategy: 'fixed' | 'exponential' | 'linear';
  initialDelay: number; // milliseconds
  maxDelay: number;     // milliseconds
  retryOn: number[];    // HTTP status codes to retry on
}

// Notification metadata
export interface NotificationMetadata {
  resourceId?: string;
  resourceType?: string;
  actionUrl?: string;
  actionText?: string;
  templateId?: string;
  variables?: Record<string, any>;
  tracking?: {
    campaignId?: string;
    source?: string;
    medium?: string;
  };
}
```

## 5. Database Indexes and Performance

### 5.1 Index Strategy

```sql
-- Critical performance indexes
CREATE INDEX CONCURRENTLY idx_users_email_active ON users(email) WHERE is_active = true;
CREATE INDEX CONCURRENTLY idx_numbers_user_status ON numbers(user_id, status);
CREATE INDEX CONCURRENTLY idx_call_logs_number_date ON call_logs(number_id, created_at DESC);
CREATE INDEX CONCURRENTLY idx_orders_user_date ON orders(user_id, created_at DESC);
CREATE INDEX CONCURRENTLY idx_payments_billing_status ON payments(billing_account_id, status);

-- Composite indexes for complex queries
CREATE INDEX CONCURRENTLY idx_numbers_search ON numbers(country_code, area_code, number_type, status);
CREATE INDEX CONCURRENTLY idx_call_logs_analytics ON call_logs(user_id, direction, status, created_at);
CREATE INDEX CONCURRENTLY idx_usage_records_billing ON usage_records(billing_account_id, usage_date, record_type);

-- Partial indexes for better performance
CREATE INDEX CONCURRENTLY idx_sessions_active ON sessions(user_id, expires_at) WHERE is_revoked = false;
CREATE INDEX CONCURRENTLY idx_webhooks_pending ON webhook_deliveries(webhook_endpoint_id, next_retry_at) WHERE status = 'PENDING';
```

### 5.2 Database Constraints

```sql
-- Check constraints for data integrity
ALTER TABLE numbers ADD CONSTRAINT chk_phone_number_format 
  CHECK (phone_number ~ '^\+[1-9]\d{1,14}$');

ALTER TABLE users ADD CONSTRAINT chk_email_format 
  CHECK (email ~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');

ALTER TABLE orders ADD CONSTRAINT chk_total_amount_positive 
  CHECK (total_amount >= 0);

ALTER TABLE call_logs ADD CONSTRAINT chk_duration_positive 
  CHECK (duration IS NULL OR duration >= 0);

-- Foreign key constraints with proper cascade behavior
ALTER TABLE numbers ADD CONSTRAINT fk_numbers_user 
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE sessions ADD CONSTRAINT fk_sessions_user 
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
```

## 6. Migration Strategy

### 6.1 Initial Migration

```sql
-- 001_initial_schema.sql
-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create custom types
CREATE TYPE user_role AS ENUM ('USER', 'ADMIN', 'SUPER_ADMIN', 'DEVELOPER', 'SUPPORT');
CREATE TYPE number_type AS ENUM ('LOCAL', 'TOLL_FREE', 'MOBILE', 'INTERNATIONAL', 'PREMIUM', 'SHARED_COST');
-- ... other enums

-- Create tables (generated by Prisma)
-- Users table with all necessary columns and constraints
-- ... rest of schema
```

### 6.2 Seed Data

```typescript
// prisma/seed.ts
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  // Create admin user
  const adminPassword = await bcrypt.hash('AdminPassword123!', 12);
  const adminUser = await prisma.user.create({
    data: {
      email: 'admin@didbuysystem.com',
      password: adminPassword,
      firstName: 'System',
      lastName: 'Administrator',
      role: 'SUPER_ADMIN',
      emailVerified: true,
      isActive: true,
    },
  });

  // Create billing account for admin
  await prisma.billingAccount.create({
    data: {
      userId: adminUser.id,
      billingAddress: {
        firstName: 'System',
        lastName: 'Administrator',
        addressLine1: '123 Admin St',
        city: 'Admin City',
        state: 'AC',
        postalCode: '12345',
        country: 'US',
      },
      currency: 'USD',
      isActive: true,
    },
  });

  // Create sample webhook endpoints
  await prisma.webhookEndpoint.create({
    data: {
      userId: adminUser.id,
      url: 'https://api.example.com/webhooks/did-buy',
      events: ['CALL_COMPLETED', 'SMS_RECEIVED', 'PAYMENT_SUCCEEDED'],
      secret: 'webhook_secret_key',
      retryPolicy: {
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelay: 1000,
        maxDelay: 30000,
        retryOn: [500, 502, 503, 504],
      },
    },
  });

  console.log('Seed data created successfully');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
```

## 7. Database Utilities

### 7.1 Connection Management

```typescript
// src/utils/database.ts
import { PrismaClient } from '@prisma/client';
import { logger } from './logger';

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

export const prisma = globalForPrisma.prisma ?? new PrismaClient({
  log: [
    { level: 'query', emit: 'event' },
    { level: 'error', emit: 'event' },
    { level: 'info', emit: 'event' },
    { level: 'warn', emit: 'event' },
  ],
  errorFormat: 'pretty',
});

// Log database queries in development
if (process.env.NODE_ENV === 'development') {
  prisma.$on('query', (e) => {
    logger.debug('Database Query', {
      query: e.query,
      params: e.params,
      duration: `${e.duration}ms`,
    });
  });
}

// Log database errors
prisma.$on('error', (e) => {
  logger.error('Database Error', e);
});

// Handle graceful shutdown
process.on('beforeExit', async () => {
  await prisma.$disconnect();
});

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

export default prisma;
```

### 7.2 Query Helpers

```typescript
// src/utils/query-helpers.ts
import { Prisma } from '@prisma/client';

export class QueryBuilder {
  static buildPaginationQuery(page: number, limit: number) {
    const skip = (page - 1) * limit;
    return { skip, take: limit };
  }

  static buildSearchQuery(search: string, fields: string[]) {
    if (!search) return {};
    
    return {
      OR: fields.map(field => ({
        [field]: {
          contains: search,
          mode: 'insensitive' as Prisma.QueryMode,
        },
      })),
    };
  }

  static buildDateRangeQuery(dateFrom?: Date, dateTo?: Date) {
    if (!dateFrom && !dateTo) return {};
    
    const dateFilter: any = {};
    if (dateFrom) dateFilter.gte = dateFrom;
    if (dateTo) dateFilter.lte = dateTo;
    
    return { createdAt: dateFilter };
  }

  static buildSortQuery(sortBy?: string, sortOrder?: 'asc' | 'desc') {
    if (!sortBy) return { createdAt: 'desc' };
    return { [sortBy]: sortOrder || 'asc' };
  }
}

export const getPaginationMetadata = (
  page: number,
  limit: number,
  total: number
) => {
  const totalPages = Math.ceil(total / limit);
  return {
    page,
    limit,
    total,
    totalPages,
    hasNext: page < totalPages,
    hasPrevious: page > 1,
  };
};
```

This comprehensive database schema provides a solid foundation for the DID buy system with proper TypeScript integration, performance optimization, and data integrity constraints.
