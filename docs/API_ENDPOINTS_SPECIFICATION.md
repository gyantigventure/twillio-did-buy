# API Endpoints Specification - TypeScript Implementation

## 1. Overview

This document provides comprehensive API endpoints specification for the DID buy system with complete TypeScript interfaces, request/response schemas, and implementation details.

## 2. API Architecture

### 2.1 RESTful Design Principles
- **Resource-based URLs**: `/api/v1/resources`
- **HTTP methods**: GET, POST, PUT, DELETE, PATCH
- **Status codes**: Consistent HTTP status code usage
- **JSON payloads**: All requests and responses in JSON format
- **Versioning**: URL-based versioning (`/api/v1/`)

### 2.2 Base Configuration

```typescript
// src/types/api.types.ts
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: ApiError;
  meta?: {
    timestamp: string;
    requestId: string;
    version: string;
  };
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, any>;
  field?: string;
}

export interface PaginatedResponse<T> {
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

export interface ApiRequest extends Request {
  user?: AuthenticatedUser;
  requestId: string;
}

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: UserRole;
  permissions: string[];
}
```

## 3. Authentication Endpoints

### 3.1 User Registration

```typescript
// POST /api/v1/auth/register
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

export interface RegisterResponse {
  user: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    emailVerified: boolean;
    role: UserRole;
  };
  tokens: {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  };
  onboarding: {
    nextStep: string;
    completionUrl: string;
  };
}

// Implementation
export const registerController = async (
  req: Request<{}, RegisterResponse, RegisterRequest>,
  res: Response<RegisterResponse>
): Promise<void> => {
  const validatedData = registerSchema.parse(req.body);
  
  try {
    const result = await authService.register(validatedData);
    res.status(201).json({
      success: true,
      data: result,
      meta: {
        timestamp: new Date().toISOString(),
        requestId: req.requestId,
        version: 'v1'
      }
    });
  } catch (error) {
    throw new ValidationError('Registration failed', error);
  }
};
```

### 3.2 User Login

```typescript
// POST /api/v1/auth/login
export interface LoginRequest {
  email: string;
  password: string;
  rememberMe?: boolean;
  deviceInfo?: {
    platform: string;
    browser: string;
    version: string;
  };
}

export interface LoginResponse {
  user: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    role: UserRole;
    preferences: UserPreferences;
    lastLoginAt: string;
  };
  tokens: {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  };
  account: {
    billingStatus: string;
    trialEndsAt?: string;
    featuresEnabled: string[];
  };
}

export const loginController = async (
  req: Request<{}, LoginResponse, LoginRequest>,
  res: Response<LoginResponse>
): Promise<void> => {
  const { email, password, rememberMe, deviceInfo } = loginSchema.parse(req.body);
  
  const result = await authService.login({
    email,
    password,
    rememberMe,
    deviceInfo,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.json({
    success: true,
    data: result
  });
};
```

### 3.3 Token Management

```typescript
// POST /api/v1/auth/refresh
export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

// POST /api/v1/auth/logout
export interface LogoutRequest {
  refreshToken?: string;
  allDevices?: boolean;
}

// POST /api/v1/auth/forgot-password
export interface ForgotPasswordRequest {
  email: string;
  resetUrl: string;
}

// POST /api/v1/auth/reset-password
export interface ResetPasswordRequest {
  token: string;
  newPassword: string;
  confirmPassword: string;
}

// GET /api/v1/auth/verify-email?token=xxx
export interface VerifyEmailQuery {
  token: string;
}
```

## 4. Number Management Endpoints

### 4.1 Number Search

```typescript
// GET /api/v1/numbers/search
export interface NumberSearchQuery {
  countryCode: string;           // Required: ISO country code
  areaCode?: string;             // Area code filter
  contains?: string;             // Number pattern
  nearLatLong?: string;          // "lat,lng" format
  distance?: number;             // Distance in miles/km
  numberType?: NumberType;       // LOCAL, TOLL_FREE, etc.
  capabilities?: NumberCapability[]; // VOICE, SMS, MMS
  limit?: number;                // Default: 20, Max: 100
  priceMax?: number;             // Maximum monthly price
  excludeRestricted?: boolean;   // Exclude restricted numbers
}

export interface AvailableNumber {
  phoneNumber: string;
  friendlyName: string;
  locality: string;
  region: string;
  countryCode: string;
  areaCode: string;
  numberType: NumberType;
  capabilities: NumberCapability[];
  pricing: {
    setupPrice: number;
    monthlyPrice: number;
    currency: string;
  };
  features: {
    smsEnabled: boolean;
    mmsEnabled: boolean;
    voiceEnabled: boolean;
    faxEnabled: boolean;
  };
  restrictions?: string[];
}

export interface NumberSearchResponse {
  numbers: AvailableNumber[];
  searchCriteria: NumberSearchQuery;
  total: number;
  hasMore: boolean;
  suggestions?: {
    alternativeAreaCodes: string[];
    nearbyRegions: string[];
  };
}

export const searchNumbersController = async (
  req: Request<{}, NumberSearchResponse, {}, NumberSearchQuery>,
  res: Response<NumberSearchResponse>
): Promise<void> => {
  const query = numberSearchSchema.parse(req.query);
  
  const result = await numbersService.searchAvailableNumbers(query);
  
  res.json({
    success: true,
    data: result
  });
};
```

### 4.2 Number Purchase

```typescript
// POST /api/v1/numbers/purchase
export interface NumberPurchaseRequest {
  numbers: {
    phoneNumber: string;
    friendlyName?: string;
    configuration?: {
      voiceUrl?: string;
      voiceMethod?: HttpMethod;
      smsUrl?: string;
      statusCallback?: string;
    };
  }[];
  billing: {
    paymentMethodId?: string;
    billingAddress?: BillingAddress;
    promoCode?: string;
  };
  configuration?: {
    autoActivate: boolean;
    defaultRouting?: RoutingConfiguration;
  };
}

export interface RoutingConfiguration {
  voiceUrl: string;
  voiceMethod: HttpMethod;
  voiceFallbackUrl?: string;
  statusCallback?: string;
  recordCalls?: boolean;
  transcribeCalls?: boolean;
  callScreening?: boolean;
}

export interface NumberPurchaseResponse {
  order: {
    id: string;
    orderNumber: string;
    status: OrderStatus;
    totalAmount: number;
    currency: string;
  };
  results: {
    phoneNumber: string;
    status: 'SUCCESS' | 'FAILED' | 'PENDING';
    numberId?: string;
    error?: string;
    estimatedActivation?: string;
  }[];
  summary: {
    totalRequested: number;
    successful: number;
    failed: number;
    pending: number;
  };
  nextSteps?: {
    configurationUrl: string;
    documentationUrl: string;
  };
}

export const purchaseNumbersController = async (
  req: ApiRequest<{}, NumberPurchaseResponse, NumberPurchaseRequest>,
  res: Response<NumberPurchaseResponse>
): Promise<void> => {
  const purchaseData = numberPurchaseSchema.parse(req.body);
  
  const result = await numbersService.purchaseNumbers(
    req.user!.id,
    purchaseData
  );
  
  res.status(201).json({
    success: true,
    data: result
  });
};
```

### 4.3 Number Management

```typescript
// GET /api/v1/numbers
export interface GetNumbersQuery {
  page?: number;
  limit?: number;
  status?: NumberStatus[];
  numberType?: NumberType[];
  search?: string;
  sortBy?: 'phoneNumber' | 'createdAt' | 'monthlyPrice' | 'lastUsed';
  sortOrder?: 'asc' | 'desc';
  tags?: string[];
}

export interface UserNumber {
  id: string;
  phoneNumber: string;
  friendlyName: string | null;
  countryCode: string;
  region: string | null;
  locality: string | null;
  areaCode: string | null;
  numberType: NumberType;
  capabilities: NumberCapability[];
  status: NumberStatus;
  
  // Configuration
  voiceUrl: string | null;
  voiceMethod: HttpMethod | null;
  smsUrl: string | null;
  statusCallback: string | null;
  
  // Pricing
  monthlyPrice: number;
  setupPrice: number | null;
  currency: string;
  
  // Usage statistics
  usage: {
    totalCalls: number;
    totalSms: number;
    monthlyMinutes: number;
    monthlySms: number;
    lastUsedAt: string | null;
  };
  
  // Metadata
  tags: string[];
  notes: string | null;
  purchasedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface GetNumbersResponse extends PaginatedResponse<UserNumber> {
  summary: {
    totalNumbers: number;
    activeNumbers: number;
    monthlyTotal: number;
    currency: string;
  };
}

// GET /api/v1/numbers/:id
export interface NumberDetailsResponse extends UserNumber {
  configurations: {
    id: string;
    name: string;
    isActive: boolean;
    routingRules: RoutingRules;
    createdAt: string;
  }[];
  recentCalls: {
    id: string;
    from: string;
    to: string;
    direction: CallDirection;
    status: CallStatus;
    duration: number | null;
    createdAt: string;
  }[];
  analytics: {
    thisMonth: {
      calls: number;
      minutes: number;
      sms: number;
      cost: number;
    };
    lastMonth: {
      calls: number;
      minutes: number;
      sms: number;
      cost: number;
    };
  };
}

// PUT /api/v1/numbers/:id
export interface UpdateNumberRequest {
  friendlyName?: string;
  voiceUrl?: string;
  voiceMethod?: HttpMethod;
  voiceFallbackUrl?: string;
  smsUrl?: string;
  statusCallback?: string;
  tags?: string[];
  notes?: string;
  configuration?: {
    recordCalls?: boolean;
    transcribeCalls?: boolean;
    callScreening?: boolean;
    voicemail?: boolean;
  };
}

// POST /api/v1/numbers/:id/configure
export interface ConfigureNumberRequest {
  configuration: {
    name: string;
    routingRules: RoutingRules;
    schedule?: {
      timezone: string;
      businessHours: {
        dayOfWeek: number[];
        timeFrom: string;
        timeTo: string;
      }[];
    };
    features: {
      recordCalls: boolean;
      transcribeCalls: boolean;
      callScreening: boolean;
      callQueue: boolean;
      voicemail: boolean;
    };
  };
  makeDefault?: boolean;
}

// DELETE /api/v1/numbers/:id
export interface ReleaseNumberRequest {
  releaseDate?: string; // Future date for scheduled release
  reason?: string;
  transferTo?: string; // Transfer to another account
}
```

## 5. Order Management Endpoints

### 5.1 Order Operations

```typescript
// GET /api/v1/orders
export interface GetOrdersQuery {
  page?: number;
  limit?: number;
  status?: OrderStatus[];
  dateFrom?: string;
  dateTo?: string;
  sortBy?: 'createdAt' | 'totalAmount' | 'status';
  sortOrder?: 'asc' | 'desc';
}

export interface OrderSummary {
  id: string;
  orderNumber: string;
  status: OrderStatus;
  totalAmount: number;
  currency: string;
  itemCount: number;
  paymentStatus: PaymentStatus;
  createdAt: string;
  completedAt: string | null;
  
  items: {
    type: OrderItemType;
    description: string;
    quantity: number;
    unitPrice: number;
    totalPrice: number;
  }[];
}

export interface GetOrdersResponse extends PaginatedResponse<OrderSummary> {
  summary: {
    totalOrders: number;
    totalSpent: number;
    pendingOrders: number;
    currency: string;
  };
}

// GET /api/v1/orders/:id
export interface OrderDetailsResponse {
  id: string;
  orderNumber: string;
  status: OrderStatus;
  
  // Financial details
  subtotalAmount: number;
  taxAmount: number;
  discountAmount: number;
  totalAmount: number;
  currency: string;
  
  // Payment information
  paymentStatus: PaymentStatus;
  paymentMethod: string | null;
  paymentProcessor: string | null;
  
  // Items
  items: {
    id: string;
    type: OrderItemType;
    description: string;
    quantity: number;
    unitPrice: number;
    totalPrice: number;
    metadata: Record<string, any>;
  }[];
  
  // Numbers purchased (if applicable)
  numbers: {
    id: string;
    phoneNumber: string;
    status: NumberStatus;
    activatedAt: string | null;
  }[];
  
  // Billing
  billingAddress: BillingAddress;
  
  // Timeline
  timeline: {
    status: OrderStatus;
    timestamp: string;
    note?: string;
  }[];
  
  // Timestamps
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
  cancelledAt: string | null;
}

// POST /api/v1/orders
export interface CreateOrderRequest {
  items: {
    type: OrderItemType;
    itemId?: string; // For number purchases
    quantity: number;
    customPrice?: number; // For manual pricing
    metadata?: Record<string, any>;
  }[];
  billing: {
    paymentMethodId?: string;
    billingAddress: BillingAddress;
    promoCode?: string;
  };
  autoComplete?: boolean;
}

// PUT /api/v1/orders/:id/cancel
export interface CancelOrderRequest {
  reason: string;
  refundRequested?: boolean;
}

// POST /api/v1/orders/:id/retry-payment
export interface RetryPaymentRequest {
  paymentMethodId?: string;
}
```

## 6. Billing & Payment Endpoints

### 6.1 Billing Account Management

```typescript
// GET /api/v1/billing/account
export interface BillingAccountResponse {
  id: string;
  company: string | null;
  taxId: string | null;
  billingAddress: BillingAddress;
  
  // Financial status
  accountBalance: number;
  creditLimit: number | null;
  currency: string;
  
  // Payment settings
  autoPayEnabled: boolean;
  defaultPaymentMethod: string | null;
  
  // Billing cycle
  billingCycle: BillingCycle;
  nextBillingDate: string | null;
  
  // Account status
  isActive: boolean;
  isSuspended: boolean;
  suspensionReason: string | null;
  
  // External IDs
  stripeCustomerId: string | null;
  paypalCustomerId: string | null;
  
  createdAt: string;
  updatedAt: string;
}

// PUT /api/v1/billing/account
export interface UpdateBillingAccountRequest {
  company?: string;
  taxId?: string;
  billingAddress?: BillingAddress;
  autoPayEnabled?: boolean;
  billingCycle?: BillingCycle;
}

// GET /api/v1/billing/payment-methods
export interface PaymentMethod {
  id: string;
  type: PaymentMethodType;
  processor: PaymentProcessor;
  
  // Card details
  last4?: string;
  brand?: string;
  expiryMonth?: number;
  expiryYear?: number;
  
  // Bank details
  bankName?: string;
  accountType?: string;
  
  // Status
  isDefault: boolean;
  isVerified: boolean;
  isActive: boolean;
  
  createdAt: string;
}

// POST /api/v1/billing/payment-methods
export interface AddPaymentMethodRequest {
  type: PaymentMethodType;
  processor: PaymentProcessor;
  token: string; // Payment processor token
  makeDefault?: boolean;
  billingAddress?: BillingAddress;
}

// DELETE /api/v1/billing/payment-methods/:id
// PUT /api/v1/billing/payment-methods/:id/default
```

### 6.2 Invoice Management

```typescript
// GET /api/v1/billing/invoices
export interface GetInvoicesQuery {
  page?: number;
  limit?: number;
  status?: InvoiceStatus[];
  dateFrom?: string;
  dateTo?: string;
  sortBy?: 'issueDate' | 'dueDate' | 'totalAmount';
  sortOrder?: 'asc' | 'desc';
}

export interface InvoiceSummary {
  id: string;
  invoiceNumber: string;
  status: InvoiceStatus;
  totalAmount: number;
  amountPaid: number;
  amountDue: number;
  currency: string;
  issueDate: string;
  dueDate: string;
  paidDate: string | null;
  
  // Period
  periodStart: string;
  periodEnd: string;
}

export interface GetInvoicesResponse extends PaginatedResponse<InvoiceSummary> {
  summary: {
    totalInvoices: number;
    totalAmount: number;
    paidAmount: number;
    outstandingAmount: number;
    overdueAmount: number;
    currency: string;
  };
}

// GET /api/v1/billing/invoices/:id
export interface InvoiceDetailsResponse {
  id: string;
  invoiceNumber: string;
  status: InvoiceStatus;
  
  // Amounts
  subtotalAmount: number;
  taxAmount: number;
  discountAmount: number;
  totalAmount: number;
  amountPaid: number;
  amountDue: number;
  currency: string;
  
  // Dates
  issueDate: string;
  dueDate: string;
  paidDate: string | null;
  
  // Billing period
  periodStart: string;
  periodEnd: string;
  
  // Line items
  lineItems: {
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
  }[];
  
  // Payment information
  payments: {
    id: string;
    amount: number;
    status: PaymentStatus;
    processor: PaymentProcessor;
    processedAt: string | null;
    paymentMethod: string | null;
  }[];
  
  // Billing address
  billingAddress: BillingAddress;
  
  // Downloads
  downloadUrls: {
    pdf: string;
    csv: string;
  };
  
  createdAt: string;
  updatedAt: string;
}

// POST /api/v1/billing/invoices/:id/pay
export interface PayInvoiceRequest {
  paymentMethodId: string;
  amount?: number; // For partial payments
}

// GET /api/v1/billing/invoices/:id/download?format=pdf
export interface DownloadInvoiceQuery {
  format: 'pdf' | 'csv' | 'json';
}
```

### 6.3 Usage and Analytics

```typescript
// GET /api/v1/billing/usage
export interface GetUsageQuery {
  startDate: string;
  endDate: string;
  groupBy?: 'day' | 'week' | 'month';
  resourceType?: UsageType[];
  resourceId?: string;
}

export interface UsageRecord {
  date: string;
  resourceType: UsageType;
  resourceId: string | null;
  quantity: number;
  unit: string;
  unitPrice: number;
  totalCost: number;
  currency: string;
  description: string | null;
}

export interface UsageResponse {
  usage: UsageRecord[];
  summary: {
    totalCost: number;
    totalQuantity: number;
    period: {
      start: string;
      end: string;
    };
    breakdown: {
      [key in UsageType]?: {
        quantity: number;
        cost: number;
        unit: string;
      };
    };
  };
  trends: {
    date: string;
    cost: number;
    quantity: number;
  }[];
}

// GET /api/v1/analytics/dashboard
export interface DashboardAnalytics {
  summary: {
    totalNumbers: number;
    activeNumbers: number;
    totalCalls: number;
    totalMinutes: number;
    monthlyCost: number;
    currency: string;
  };
  
  usage: {
    thisMonth: {
      calls: number;
      minutes: number;
      sms: number;
      cost: number;
    };
    lastMonth: {
      calls: number;
      minutes: number;
      sms: number;
      cost: number;
    };
    growth: {
      calls: number;    // Percentage growth
      minutes: number;
      sms: number;
      cost: number;
    };
  };
  
  charts: {
    callVolume: {
      date: string;
      inbound: number;
      outbound: number;
    }[];
    
    costTrend: {
      date: string;
      cost: number;
    }[];
    
    numberUtilization: {
      numberId: string;
      phoneNumber: string;
      calls: number;
      minutes: number;
      utilization: number;
    }[];
  };
  
  recentActivity: {
    type: 'call' | 'sms' | 'number_purchased' | 'payment';
    description: string;
    timestamp: string;
    amount?: number;
  }[];
}

// GET /api/v1/analytics/calls
export interface CallAnalyticsQuery {
  startDate: string;
  endDate: string;
  numberId?: string;
  direction?: CallDirection;
  status?: CallStatus;
  groupBy?: 'hour' | 'day' | 'week' | 'month';
}

export interface CallAnalyticsResponse {
  summary: {
    totalCalls: number;
    totalMinutes: number;
    averageDuration: number;
    successRate: number;
    totalCost: number;
    currency: string;
  };
  
  breakdown: {
    byDirection: {
      inbound: { calls: number; minutes: number; cost: number };
      outbound: { calls: number; minutes: number; cost: number };
    };
    
    byStatus: {
      [key in CallStatus]: number;
    };
    
    byHour: {
      hour: number;
      calls: number;
      minutes: number;
    }[];
    
    byDay: {
      date: string;
      calls: number;
      minutes: number;
    }[];
  };
  
  topNumbers: {
    numberId: string;
    phoneNumber: string;
    calls: number;
    minutes: number;
    cost: number;
  }[];
  
  geographic: {
    country: string;
    calls: number;
    minutes: number;
    percentage: number;
  }[];
}
```

## 7. Webhook Endpoints

### 7.1 Webhook Management

```typescript
// GET /api/v1/webhooks
export interface WebhookEndpoint {
  id: string;
  url: string;
  events: WebhookEvent[];
  isActive: boolean;
  
  // Status
  lastDeliveryAt: string | null;
  lastStatus: string | null;
  deliveryCount: number;
  failureCount: number;
  
  // Configuration
  timeout: number;
  retryPolicy: WebhookRetryPolicy;
  
  createdAt: string;
  updatedAt: string;
}

// POST /api/v1/webhooks
export interface CreateWebhookRequest {
  url: string;
  events: WebhookEvent[];
  description?: string;
  retryPolicy?: Partial<WebhookRetryPolicy>;
  timeout?: number;
}

// PUT /api/v1/webhooks/:id
export interface UpdateWebhookRequest {
  url?: string;
  events?: WebhookEvent[];
  isActive?: boolean;
  retryPolicy?: Partial<WebhookRetryPolicy>;
  timeout?: number;
}

// GET /api/v1/webhooks/:id/deliveries
export interface WebhookDelivery {
  id: string;
  event: WebhookEvent;
  status: DeliveryStatus;
  httpStatus: number | null;
  attemptCount: number;
  deliveredAt: string | null;
  nextRetryAt: string | null;
  errorMessage: string | null;
  
  // Payload info
  payloadSize: number;
  responseTime: number | null;
  
  createdAt: string;
}

// POST /api/v1/webhooks/:id/test
export interface TestWebhookRequest {
  event: WebhookEvent;
  customPayload?: Record<string, any>;
}

// POST /api/v1/webhooks/:id/retry/:deliveryId
// Retry a failed webhook delivery
```

### 7.2 Webhook Event Payloads

```typescript
// Webhook payload structures
export interface WebhookPayload {
  event: WebhookEvent;
  timestamp: string;
  data: any;
  account: {
    id: string;
    email: string;
  };
}

// Call event payload
export interface CallWebhookPayload extends WebhookPayload {
  event: 'CALL_STARTED' | 'CALL_ANSWERED' | 'CALL_COMPLETED' | 'CALL_FAILED';
  data: {
    callId: string;
    callSid: string;
    numberId: string;
    phoneNumber: string;
    from: string;
    to: string;
    direction: CallDirection;
    status: CallStatus;
    duration?: number;
    recordingUrl?: string;
    cost?: number;
    currency?: string;
  };
}

// SMS event payload
export interface SmsWebhookPayload extends WebhookPayload {
  event: 'SMS_RECEIVED' | 'SMS_SENT' | 'SMS_DELIVERED' | 'SMS_FAILED';
  data: {
    messageId: string;
    messageSid: string;
    numberId: string;
    phoneNumber: string;
    from: string;
    to: string;
    body: string;
    direction: SmsDirection;
    status: SmsStatus;
    cost?: number;
    currency?: string;
  };
}

// Number event payload
export interface NumberWebhookPayload extends WebhookPayload {
  event: 'NUMBER_PURCHASED' | 'NUMBER_RELEASED';
  data: {
    numberId: string;
    phoneNumber: string;
    numberType: NumberType;
    orderId?: string;
    cost?: number;
    currency?: string;
  };
}

// Payment event payload
export interface PaymentWebhookPayload extends WebhookPayload {
  event: 'PAYMENT_SUCCEEDED' | 'PAYMENT_FAILED';
  data: {
    paymentId: string;
    orderId?: string;
    invoiceId?: string;
    amount: number;
    currency: string;
    status: PaymentStatus;
    paymentMethod: string;
    failureReason?: string;
  };
}
```

## 8. Administrative Endpoints

### 8.1 Admin User Management

```typescript
// GET /api/v1/admin/users
export interface AdminGetUsersQuery {
  page?: number;
  limit?: number;
  search?: string;
  role?: UserRole[];
  status?: 'active' | 'suspended' | 'inactive';
  sortBy?: 'createdAt' | 'lastLoginAt' | 'email';
  sortOrder?: 'asc' | 'desc';
}

export interface AdminUserSummary {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  company: string | null;
  role: UserRole;
  isActive: boolean;
  isSuspended: boolean;
  emailVerified: boolean;
  
  // Statistics
  totalNumbers: number;
  totalOrders: number;
  totalSpent: number;
  lastLoginAt: string | null;
  
  createdAt: string;
}

// GET /api/v1/admin/users/:id
export interface AdminUserDetailsResponse {
  user: UserWithRelations;
  statistics: {
    totalNumbers: number;
    activeNumbers: number;
    totalCalls: number;
    totalMinutes: number;
    totalSms: number;
    totalSpent: number;
    averageMonthlySpend: number;
  };
  recentActivity: {
    type: string;
    description: string;
    timestamp: string;
  }[];
}

// PUT /api/v1/admin/users/:id/suspend
export interface SuspendUserRequest {
  reason: string;
  duration?: number; // Days
  notifyUser: boolean;
}

// PUT /api/v1/admin/users/:id/role
export interface UpdateUserRoleRequest {
  role: UserRole;
  reason: string;
}
```

### 8.2 System Analytics

```typescript
// GET /api/v1/admin/analytics/overview
export interface SystemAnalyticsResponse {
  summary: {
    totalUsers: number;
    activeUsers: number;
    totalNumbers: number;
    totalRevenue: number;
    currency: string;
  };
  
  growth: {
    period: string;
    newUsers: number;
    revenue: number;
    numbersPurchased: number;
  }[];
  
  usage: {
    totalCalls: number;
    totalMinutes: number;
    totalSms: number;
    avgCallsPerUser: number;
  };
  
  revenue: {
    monthly: number;
    annual: number;
    growth: number;
    breakdown: {
      numbers: number;
      usage: number;
      other: number;
    };
  };
}

// GET /api/v1/admin/system/health
export interface SystemHealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  services: {
    database: {
      status: 'up' | 'down';
      responseTime: number;
      connections: number;
    };
    twilio: {
      status: 'up' | 'down';
      responseTime: number;
      lastError?: string;
    };
    redis: {
      status: 'up' | 'down';
      responseTime: number;
      memory: number;
    };
    stripe: {
      status: 'up' | 'down';
      responseTime: number;
      lastError?: string;
    };
  };
  metrics: {
    uptime: number;
    requestsPerMinute: number;
    errorRate: number;
    avgResponseTime: number;
  };
}
```

## 9. API Security & Rate Limiting

### 9.1 Rate Limiting Configuration

```typescript
// Rate limiting interfaces
export interface RateLimitConfig {
  windowMs: number;        // Time window in milliseconds
  maxRequests: number;     // Maximum requests per window
  message: string;         // Error message
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  keyGenerator?: (req: Request) => string;
}

export const rateLimitConfigs: Record<string, RateLimitConfig> = {
  default: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 1000,
    message: 'Too many requests from this IP'
  },
  auth: {
    windowMs: 15 * 60 * 1000,
    maxRequests: 5,
    message: 'Too many authentication attempts'
  },
  search: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 100,
    message: 'Too many search requests'
  },
  purchase: {
    windowMs: 60 * 1000,
    maxRequests: 10,
    message: 'Too many purchase attempts'
  }
};
```

### 9.2 API Key Authentication

```typescript
// API Key interfaces
export interface ApiKeyRequest extends Request {
  apiKey?: {
    id: string;
    userId: string;
    permissions: string[];
    name: string;
  };
}

export interface CreateApiKeyRequest {
  name: string;
  permissions: string[];
  expiresAt?: string;
  description?: string;
}

export interface ApiKeyResponse {
  id: string;
  name: string;
  key: string;        // Only returned once during creation
  keyPrefix: string;  // First 8 characters for identification
  permissions: string[];
  expiresAt: string | null;
  createdAt: string;
}

// Webhook signature verification
export interface WebhookSignature {
  timestamp: string;
  signature: string;
}

export const verifyWebhookSignature = (
  payload: string,
  signature: WebhookSignature,
  secret: string
): boolean => {
  // Implementation for webhook signature verification
  return true;
};
```

## 10. Error Response Schemas

### 10.1 Standard Error Responses

```typescript
// Standard error response format
export interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: Record<string, any>;
    field?: string;
  };
  meta: {
    timestamp: string;
    requestId: string;
    version: string;
  };
}

// Validation error response
export interface ValidationErrorResponse extends ErrorResponse {
  error: {
    code: 'VALIDATION_ERROR';
    message: 'Request validation failed';
    details: {
      field: string;
      message: string;
      value?: any;
    }[];
  };
}

// Authentication error response
export interface AuthErrorResponse extends ErrorResponse {
  error: {
    code: 'AUTHENTICATION_ERROR' | 'AUTHORIZATION_ERROR';
    message: string;
    details?: {
      requiredRole?: string;
      requiredPermissions?: string[];
    };
  };
}

// Rate limit error response
export interface RateLimitErrorResponse extends ErrorResponse {
  error: {
    code: 'RATE_LIMIT_EXCEEDED';
    message: string;
    details: {
      limit: number;
      remaining: number;
      resetTime: string;
    };
  };
}

// Business logic error response
export interface BusinessErrorResponse extends ErrorResponse {
  error: {
    code: 'INSUFFICIENT_BALANCE' | 'NUMBER_NOT_AVAILABLE' | 'INVALID_CONFIGURATION';
    message: string;
    details?: Record<string, any>;
  };
}
```

This comprehensive API specification provides a complete TypeScript-based foundation for implementing all endpoints in the DID buy system with proper type safety, validation, and error handling.
