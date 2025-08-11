# Deployment Guide - Complete Production Setup

## 1. Overview

This document provides comprehensive deployment guidance for the DID buy system, including Docker containerization, CI/CD pipelines, cloud deployment strategies, monitoring, and production best practices.

## 2. Infrastructure Architecture

### 2.1 Production Architecture Overview

```typescript
// src/config/deployment.config.ts
export interface DeploymentConfig {
  environment: 'development' | 'staging' | 'production';
  application: {
    name: string;
    version: string;
    port: number;
    workers: number;
    cluster: boolean;
  };
  database: {
    url: string;
    poolSize: number;
    ssl: boolean;
    migrations: boolean;
  };
  redis: {
    url: string;
    cluster: boolean;
    retryAttempts: number;
  };
  monitoring: {
    enableMetrics: boolean;
    enableTracing: boolean;
    enableLogging: boolean;
    sentryDsn?: string;
    datadogApiKey?: string;
  };
  security: {
    enableHelmet: boolean;
    enableCors: boolean;
    enableRateLimit: boolean;
    trustProxy: boolean;
  };
  performance: {
    enableCompression: boolean;
    enableCaching: boolean;
    staticFilesCaching: boolean;
  };
}

export const deploymentConfigs: Record<string, DeploymentConfig> = {
  development: {
    environment: 'development',
    application: {
      name: 'did-buy-api-dev',
      version: process.env.APP_VERSION || '1.0.0',
      port: 3000,
      workers: 1,
      cluster: false,
    },
    database: {
      url: process.env.DATABASE_URL || 'postgresql://dev:dev@localhost:5432/did_buy_dev',
      poolSize: 10,
      ssl: false,
      migrations: true,
    },
    redis: {
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      cluster: false,
      retryAttempts: 3,
    },
    monitoring: {
      enableMetrics: false,
      enableTracing: false,
      enableLogging: true,
    },
    security: {
      enableHelmet: true,
      enableCors: true,
      enableRateLimit: false,
      trustProxy: false,
    },
    performance: {
      enableCompression: false,
      enableCaching: false,
      staticFilesCaching: false,
    },
  },
  
  production: {
    environment: 'production',
    application: {
      name: 'did-buy-api',
      version: process.env.APP_VERSION || '1.0.0',
      port: parseInt(process.env.PORT || '3000'),
      workers: parseInt(process.env.WEB_CONCURRENCY || '4'),
      cluster: true,
    },
    database: {
      url: process.env.DATABASE_URL!,
      poolSize: 20,
      ssl: true,
      migrations: false,
    },
    redis: {
      url: process.env.REDIS_URL!,
      cluster: true,
      retryAttempts: 5,
    },
    monitoring: {
      enableMetrics: true,
      enableTracing: true,
      enableLogging: true,
      sentryDsn: process.env.SENTRY_DSN,
      datadogApiKey: process.env.DATADOG_API_KEY,
    },
    security: {
      enableHelmet: true,
      enableCors: true,
      enableRateLimit: true,
      trustProxy: true,
    },
    performance: {
      enableCompression: true,
      enableCaching: true,
      staticFilesCaching: true,
    },
  },
};
```

### 2.2 Cloud Infrastructure Components

```yaml
# infrastructure/aws/architecture.yaml
# AWS Infrastructure as Code (CloudFormation/CDK)
Resources:
  # VPC and Networking
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsHostnames: true
      EnableDnsSupport: true
      
  PublicSubnet1:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.0.1.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      
  PublicSubnet2:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.0.2.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
      
  PrivateSubnet1:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.0.3.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      
  PrivateSubnet2:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.0.4.0/24
      AvailabilityZone: !Select [1, !GetAZs '']

  # Application Load Balancer
  ApplicationLoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Type: application
      Scheme: internet-facing
      Subnets:
        - !Ref PublicSubnet1
        - !Ref PublicSubnet2
      SecurityGroups:
        - !Ref ALBSecurityGroup

  # ECS Cluster
  ECSCluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: did-buy-cluster
      CapacityProviders:
        - FARGATE
        - FARGATE_SPOT

  # RDS Database
  DatabaseCluster:
    Type: AWS::RDS::DBCluster
    Properties:
      Engine: aurora-postgresql
      EngineVersion: '13.7'
      DatabaseName: did_buy_prod
      MasterUsername: postgres
      MasterUserPassword: !Ref DatabasePassword
      VpcSecurityGroupIds:
        - !Ref DatabaseSecurityGroup
      DBSubnetGroupName: !Ref DatabaseSubnetGroup
      BackupRetentionPeriod: 30
      DeletionProtection: true
      
  # ElastiCache Redis
  RedisCluster:
    Type: AWS::ElastiCache::ReplicationGroup
    Properties:
      ReplicationGroupDescription: DID Buy Redis Cluster
      NumCacheClusters: 2
      Engine: redis
      CacheNodeType: cache.r6g.large
      SecurityGroupIds:
        - !Ref RedisSecurityGroup
      SubnetGroupName: !Ref RedisSubnetGroup
```

## 3. Docker Configuration

### 3.1 Multi-stage Dockerfile

```dockerfile
# Dockerfile
# Build stage
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY prisma ./prisma/

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY . .

# Generate Prisma client
RUN npx prisma generate

# Build application
RUN npm run build

# Remove dev dependencies
RUN npm prune --production

# Production stage
FROM node:18-alpine AS production

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create app directory and user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

WORKDIR /app

# Copy built application
COPY --from=builder --chown=nextjs:nodejs /app/dist ./dist
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/prisma ./prisma
COPY --from=builder --chown=nextjs:nodejs /app/package*.json ./

# Create logs directory
RUN mkdir -p /app/logs && chown nextjs:nodejs /app/logs

USER nextjs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node dist/health-check.js

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start application
CMD ["node", "dist/server.js"]
```

### 3.2 Docker Compose for Development

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://postgres:password@db:5432/did_buy_dev
      - REDIS_URL=redis://redis:6379
      - TWILIO_ACCOUNT_SID=${TWILIO_ACCOUNT_SID}
      - TWILIO_AUTH_TOKEN=${TWILIO_AUTH_TOKEN}
      - JWT_SECRET=${JWT_SECRET}
    volumes:
      - ./src:/app/src
      - ./prisma:/app/prisma
      - /app/node_modules
    depends_on:
      - db
      - redis
    networks:
      - did-buy-network

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=did_buy_dev
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./database/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    networks:
      - did-buy-network

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    networks:
      - did-buy-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    depends_on:
      - app
    networks:
      - did-buy-network

volumes:
  postgres_data:
  redis_data:

networks:
  did-buy-network:
    driver: bridge
```

### 3.3 Production Docker Compose

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  app:
    image: did-buy-api:${VERSION:-latest}
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
        order: start-first
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
    environment:
      - NODE_ENV=production
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - TWILIO_ACCOUNT_SID=${TWILIO_ACCOUNT_SID}
      - TWILIO_AUTH_TOKEN=${TWILIO_AUTH_TOKEN}
      - JWT_SECRET=${JWT_SECRET}
      - SENTRY_DSN=${SENTRY_DSN}
    ports:
      - "3000"
    volumes:
      - app_logs:/app/logs
    networks:
      - did-buy-network
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.prod.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
      - nginx_logs:/var/log/nginx
    depends_on:
      - app
    networks:
      - did-buy-network

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    networks:
      - did-buy-network

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards
    networks:
      - did-buy-network

volumes:
  app_logs:
  nginx_logs:
  prometheus_data:
  grafana_data:

networks:
  did-buy-network:
    external: true
```

## 4. CI/CD Pipeline

### 4.1 GitHub Actions Workflow

```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

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
          
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'

    - name: Install dependencies
      run: npm ci

    - name: Generate Prisma client
      run: npx prisma generate

    - name: Run database migrations
      run: npx prisma migrate deploy
      env:
        DATABASE_URL: postgresql://postgres:password@localhost:5432/test_db

    - name: Run linting
      run: npm run lint

    - name: Run type checking
      run: npm run type-check

    - name: Run unit tests
      run: npm run test:unit
      env:
        DATABASE_URL: postgresql://postgres:password@localhost:5432/test_db
        REDIS_URL: redis://localhost:6379

    - name: Run integration tests
      run: npm run test:integration
      env:
        DATABASE_URL: postgresql://postgres:password@localhost:5432/test_db
        REDIS_URL: redis://localhost:6379
        JWT_SECRET: test-jwt-secret
        TWILIO_ACCOUNT_SID: test_account_sid
        TWILIO_AUTH_TOKEN: test_auth_token

    - name: Upload coverage reports
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/lcov.info
        flags: unittests
        name: codecov-umbrella

  security:
    runs-on: ubuntu-latest
    needs: test

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'

    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

    - name: Run npm audit
      run: npm audit --audit-level moderate

  build:
    runs-on: ubuntu-latest
    needs: [test, security]
    if: github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop'

    outputs:
      image-digest: ${{ steps.build.outputs.digest }}
      image-url: ${{ steps.build.outputs.image-url }}

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3

    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=sha,prefix={{branch}}-
          type=raw,value=latest,enable={{is_default_branch}}

    - name: Build and push Docker image
      id: build
      uses: docker/build-push-action@v5
      with:
        context: .
        platforms: linux/amd64,linux/arm64
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max

  deploy-staging:
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/develop'
    environment: staging

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: us-east-1

    - name: Deploy to ECS Staging
      run: |
        aws ecs update-service \
          --cluster did-buy-staging \
          --service did-buy-api-staging \
          --force-new-deployment

    - name: Wait for deployment
      run: |
        aws ecs wait services-stable \
          --cluster did-buy-staging \
          --services did-buy-api-staging

    - name: Run smoke tests
      run: |
        npm run test:smoke -- --baseUrl=https://api-staging.didbuy.com

  deploy-production:
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    environment: production

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: us-east-1

    - name: Deploy to ECS Production
      run: |
        aws ecs update-service \
          --cluster did-buy-production \
          --service did-buy-api-production \
          --force-new-deployment

    - name: Wait for deployment
      run: |
        aws ecs wait services-stable \
          --cluster did-buy-production \
          --services did-buy-api-production

    - name: Run production health checks
      run: |
        npm run test:health -- --baseUrl=https://api.didbuy.com

    - name: Notify deployment
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        channel: '#deployments'
        webhook_url: ${{ secrets.SLACK_WEBHOOK }}
      if: always()
```

### 4.2 Deployment Scripts

```bash
#!/bin/bash
# scripts/deploy.sh

set -e

ENVIRONMENT=${1:-staging}
VERSION=${2:-latest}

echo "Deploying to $ENVIRONMENT with version $VERSION"

# Load environment variables
if [ -f ".env.$ENVIRONMENT" ]; then
    export $(cat .env.$ENVIRONMENT | xargs)
fi

# Validate required environment variables
required_vars=(
    "DATABASE_URL"
    "REDIS_URL"
    "TWILIO_ACCOUNT_SID"
    "TWILIO_AUTH_TOKEN"
    "JWT_SECRET"
)

for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "Error: $var is not set"
        exit 1
    fi
done

# Build Docker image
echo "Building Docker image..."
docker build -t did-buy-api:$VERSION .

# Run database migrations
echo "Running database migrations..."
docker run --rm \
    -e DATABASE_URL="$DATABASE_URL" \
    did-buy-api:$VERSION \
    npx prisma migrate deploy

# Deploy based on environment
case $ENVIRONMENT in
    "staging")
        deploy_staging
        ;;
    "production")
        deploy_production
        ;;
    *)
        echo "Unknown environment: $ENVIRONMENT"
        exit 1
        ;;
esac

function deploy_staging() {
    echo "Deploying to staging..."
    
    # Update ECS service
    aws ecs update-service \
        --cluster did-buy-staging \
        --service did-buy-api-staging \
        --task-definition did-buy-api-staging:$VERSION \
        --force-new-deployment
    
    # Wait for deployment to complete
    aws ecs wait services-stable \
        --cluster did-buy-staging \
        --services did-buy-api-staging
    
    echo "Staging deployment completed"
}

function deploy_production() {
    echo "Deploying to production..."
    
    # Backup database before deployment
    echo "Creating database backup..."
    pg_dump $DATABASE_URL > "backup-$(date +%Y%m%d_%H%M%S).sql"
    
    # Blue-green deployment
    aws ecs update-service \
        --cluster did-buy-production \
        --service did-buy-api-production \
        --task-definition did-buy-api-production:$VERSION \
        --deployment-configuration "maximumPercent=200,minimumHealthyPercent=100"
    
    # Wait for deployment to complete
    aws ecs wait services-stable \
        --cluster did-buy-production \
        --services did-buy-api-production
    
    # Run health checks
    echo "Running post-deployment health checks..."
    ./scripts/health-check.sh https://api.didbuy.com
    
    echo "Production deployment completed"
}
```

### 4.3 Health Check Script

```bash
#!/bin/bash
# scripts/health-check.sh

BASE_URL=${1:-http://localhost:3000}
MAX_ATTEMPTS=30
ATTEMPT=1

echo "Running health checks against $BASE_URL"

# Function to check endpoint
check_endpoint() {
    local endpoint=$1
    local expected_status=${2:-200}
    
    echo "Checking $endpoint..."
    
    status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$endpoint")
    
    if [ "$status" -eq "$expected_status" ]; then
        echo "✓ $endpoint returned status $status"
        return 0
    else
        echo "✗ $endpoint returned status $status, expected $expected_status"
        return 1
    fi
}

# Wait for application to be ready
echo "Waiting for application to be ready..."
while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
    if check_endpoint "/health" 200; then
        echo "Application is ready after $ATTEMPT attempts"
        break
    fi
    
    if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
        echo "Application failed to become ready after $MAX_ATTEMPTS attempts"
        exit 1
    fi
    
    echo "Attempt $ATTEMPT/$MAX_ATTEMPTS failed, waiting 10 seconds..."
    sleep 10
    ATTEMPT=$((ATTEMPT + 1))
done

# Run comprehensive health checks
echo "Running comprehensive health checks..."

FAILED_CHECKS=0

# Check health endpoint
if ! check_endpoint "/health" 200; then
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# Check API version endpoint
if ! check_endpoint "/api/v1/health" 200; then
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# Check metrics endpoint (if enabled)
if ! check_endpoint "/metrics" 200; then
    echo "⚠ Metrics endpoint not available (might be disabled)"
fi

# Check that protected endpoints require authentication
if ! check_endpoint "/api/v1/numbers" 401; then
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# Summary
if [ $FAILED_CHECKS -eq 0 ]; then
    echo "✓ All health checks passed"
    exit 0
else
    echo "✗ $FAILED_CHECKS health checks failed"
    exit 1
fi
```

## 5. Environment Configuration

### 5.1 Environment Variables Management

```typescript
// src/config/environment.ts
import { z } from 'zod';

const environmentSchema = z.object({
  // Application
  NODE_ENV: z.enum(['development', 'staging', 'production']).default('development'),
  PORT: z.string().transform(Number).default('3000'),
  APP_VERSION: z.string().default('1.0.0'),
  APP_NAME: z.string().default('DID Buy API'),
  
  // Database
  DATABASE_URL: z.string().url(),
  DATABASE_POOL_SIZE: z.string().transform(Number).default('20'),
  DATABASE_SSL: z.string().transform(Boolean).default('true'),
  
  // Redis
  REDIS_URL: z.string().url(),
  REDIS_CLUSTER: z.string().transform(Boolean).default('false'),
  
  // JWT
  JWT_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  JWT_ACCESS_EXPIRY: z.string().default('15m'),
  JWT_REFRESH_EXPIRY: z.string().default('7d'),
  
  // Twilio
  TWILIO_ACCOUNT_SID: z.string().min(1),
  TWILIO_AUTH_TOKEN: z.string().min(1),
  TWILIO_WEBHOOK_SECRET: z.string().min(1),
  
  // External Services
  STRIPE_SECRET_KEY: z.string().optional(),
  STRIPE_WEBHOOK_SECRET: z.string().optional(),
  SENDGRID_API_KEY: z.string().optional(),
  
  // Monitoring
  SENTRY_DSN: z.string().url().optional(),
  DATADOG_API_KEY: z.string().optional(),
  NEW_RELIC_LICENSE_KEY: z.string().optional(),
  
  // Security
  CORS_ORIGIN: z.string().default('*'),
  RATE_LIMIT_WINDOW: z.string().transform(Number).default('900000'), // 15 minutes
  RATE_LIMIT_MAX: z.string().transform(Number).default('1000'),
  
  // Logging
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  LOG_FORMAT: z.enum(['json', 'combined', 'common']).default('json'),
  
  // Performance
  CLUSTER_WORKERS: z.string().transform(Number).optional(),
  ENABLE_COMPRESSION: z.string().transform(Boolean).default('true'),
  ENABLE_HELMET: z.string().transform(Boolean).default('true'),
});

export type Environment = z.infer<typeof environmentSchema>;

let env: Environment;

try {
  env = environmentSchema.parse(process.env);
} catch (error) {
  console.error('Environment validation failed:', error);
  process.exit(1);
}

export { env };

// Environment-specific configurations
export const isDevelopment = env.NODE_ENV === 'development';
export const isProduction = env.NODE_ENV === 'production';
export const isStaging = env.NODE_ENV === 'staging';

export const getConnectionString = (service: string): string => {
  switch (service) {
    case 'database':
      return env.DATABASE_URL;
    case 'redis':
      return env.REDIS_URL;
    default:
      throw new Error(`Unknown service: ${service}`);
  }
};
```

### 5.2 Configuration Management

```bash
# .env.example
# Application
NODE_ENV=development
PORT=3000
APP_VERSION=1.0.0
APP_NAME=DID Buy API

# Database
DATABASE_URL=postgresql://username:password@localhost:5432/did_buy
DATABASE_POOL_SIZE=20
DATABASE_SSL=false

# Redis
REDIS_URL=redis://localhost:6379
REDIS_CLUSTER=false

# JWT Secrets (generate with: openssl rand -base64 32)
JWT_SECRET=your-super-secret-jwt-key-here
JWT_REFRESH_SECRET=your-super-secret-refresh-key-here
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d

# Twilio Configuration
TWILIO_ACCOUNT_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
TWILIO_WEBHOOK_SECRET=your-webhook-secret

# Payment Processing
STRIPE_SECRET_KEY=sk_test_your-stripe-secret-key
STRIPE_WEBHOOK_SECRET=whsec_your-webhook-secret

# Email Service
SENDGRID_API_KEY=SG.your-sendgrid-api-key

# Monitoring and Observability
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project-id
DATADOG_API_KEY=your-datadog-api-key
NEW_RELIC_LICENSE_KEY=your-newrelic-license-key

# Security
CORS_ORIGIN=http://localhost:3001
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=1000

# Logging
LOG_LEVEL=debug
LOG_FORMAT=json

# Performance
CLUSTER_WORKERS=4
ENABLE_COMPRESSION=true
ENABLE_HELMET=true
```

## 6. Monitoring and Observability

### 6.1 Application Monitoring Setup

```typescript
// src/monitoring/monitoring.service.ts
import { Request, Response } from 'express';
import { Registry, Counter, Histogram, Gauge } from 'prom-client';
import { Logger } from 'winston';

export class MonitoringService {
  private registry: Registry;
  private httpRequestsTotal: Counter<string>;
  private httpRequestDuration: Histogram<string>;
  private activeConnections: Gauge<string>;
  private databaseConnections: Gauge<string>;
  private memoryUsage: Gauge<string>;

  constructor(private logger: Logger) {
    this.registry = new Registry();
    this.setupMetrics();
    this.collectDefaultMetrics();
  }

  private setupMetrics(): void {
    // HTTP request metrics
    this.httpRequestsTotal = new Counter({
      name: 'http_requests_total',
      help: 'Total number of HTTP requests',
      labelNames: ['method', 'route', 'status_code'],
      registers: [this.registry],
    });

    this.httpRequestDuration = new Histogram({
      name: 'http_request_duration_seconds',
      help: 'Duration of HTTP requests in seconds',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10],
      registers: [this.registry],
    });

    // Application metrics
    this.activeConnections = new Gauge({
      name: 'active_connections',
      help: 'Number of active connections',
      registers: [this.registry],
    });

    this.databaseConnections = new Gauge({
      name: 'database_connections',
      help: 'Number of active database connections',
      registers: [this.registry],
    });

    this.memoryUsage = new Gauge({
      name: 'memory_usage_bytes',
      help: 'Memory usage in bytes',
      labelNames: ['type'],
      registers: [this.registry],
    });
  }

  private collectDefaultMetrics(): void {
    // Collect default Node.js metrics
    require('prom-client').collectDefaultMetrics({
      register: this.registry,
      prefix: 'nodejs_',
    });

    // Custom memory metrics
    setInterval(() => {
      const memUsage = process.memoryUsage();
      this.memoryUsage.set({ type: 'rss' }, memUsage.rss);
      this.memoryUsage.set({ type: 'heapUsed' }, memUsage.heapUsed);
      this.memoryUsage.set({ type: 'heapTotal' }, memUsage.heapTotal);
      this.memoryUsage.set({ type: 'external' }, memUsage.external);
    }, 10000); // Every 10 seconds
  }

  recordHttpRequest(
    method: string,
    route: string,
    statusCode: number,
    duration: number
  ): void {
    const labels = {
      method,
      route,
      status_code: statusCode.toString(),
    };

    this.httpRequestsTotal.inc(labels);
    this.httpRequestDuration.observe(labels, duration / 1000); // Convert to seconds
  }

  incrementActiveConnections(): void {
    this.activeConnections.inc();
  }

  decrementActiveConnections(): void {
    this.activeConnections.dec();
  }

  setDatabaseConnections(count: number): void {
    this.databaseConnections.set(count);
  }

  getMetrics(): Promise<string> {
    return this.registry.metrics();
  }

  // Express middleware for automatic request tracking
  createMiddleware() {
    return (req: Request, res: Response, next: Function) => {
      const startTime = Date.now();

      // Track active connections
      this.incrementActiveConnections();

      res.on('finish', () => {
        const duration = Date.now() - startTime;
        const route = req.route?.path || req.path;

        this.recordHttpRequest(
          req.method,
          route,
          res.statusCode,
          duration
        );

        this.decrementActiveConnections();
      });

      next();
    };
  }
}
```

### 6.2 Health Check Implementation

```typescript
// src/health/health-check.service.ts
export interface HealthCheckResult {
  status: 'healthy' | 'unhealthy' | 'degraded';
  timestamp: string;
  uptime: number;
  version: string;
  checks: {
    [key: string]: {
      status: 'up' | 'down';
      responseTime: number;
      message?: string;
      details?: Record<string, any>;
    };
  };
}

export class HealthCheckService {
  constructor(
    private prisma: PrismaClient,
    private redis: Redis,
    private twilioService: TwilioService,
    private logger: Logger
  ) {}

  async checkHealth(): Promise<HealthCheckResult> {
    const startTime = Date.now();
    const checks: HealthCheckResult['checks'] = {};

    // Database health check
    checks.database = await this.checkDatabase();
    
    // Redis health check
    checks.redis = await this.checkRedis();
    
    // Twilio service health check
    checks.twilio = await this.checkTwilio();
    
    // Memory usage check
    checks.memory = this.checkMemory();
    
    // Disk space check
    checks.disk = await this.checkDiskSpace();

    // Determine overall status
    const allStatuses = Object.values(checks).map(check => check.status);
    const hasDown = allStatuses.includes('down');
    const hasDegraded = allStatuses.some(status => 
      checks[Object.keys(checks).find(key => checks[key].status === status)!].responseTime > 1000
    );

    let overallStatus: 'healthy' | 'unhealthy' | 'degraded';
    if (hasDown) {
      overallStatus = 'unhealthy';
    } else if (hasDegraded) {
      overallStatus = 'degraded';
    } else {
      overallStatus = 'healthy';
    }

    return {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.APP_VERSION || '1.0.0',
      checks,
    };
  }

  private async checkDatabase(): Promise<HealthCheckResult['checks'][string]> {
    const startTime = Date.now();
    
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      
      return {
        status: 'up',
        responseTime: Date.now() - startTime,
        message: 'Database connection successful',
      };
    } catch (error) {
      return {
        status: 'down',
        responseTime: Date.now() - startTime,
        message: 'Database connection failed',
        details: { error: error.message },
      };
    }
  }

  private async checkRedis(): Promise<HealthCheckResult['checks'][string]> {
    const startTime = Date.now();
    
    try {
      await this.redis.ping();
      
      return {
        status: 'up',
        responseTime: Date.now() - startTime,
        message: 'Redis connection successful',
      };
    } catch (error) {
      return {
        status: 'down',
        responseTime: Date.now() - startTime,
        message: 'Redis connection failed',
        details: { error: error.message },
      };
    }
  }

  private async checkTwilio(): Promise<HealthCheckResult['checks'][string]> {
    const startTime = Date.now();
    
    try {
      const isHealthy = await this.twilioService.checkHealth();
      
      return {
        status: isHealthy ? 'up' : 'down',
        responseTime: Date.now() - startTime,
        message: isHealthy ? 'Twilio service healthy' : 'Twilio service unhealthy',
      };
    } catch (error) {
      return {
        status: 'down',
        responseTime: Date.now() - startTime,
        message: 'Twilio health check failed',
        details: { error: error.message },
      };
    }
  }

  private checkMemory(): HealthCheckResult['checks'][string] {
    const memUsage = process.memoryUsage();
    const maxMemory = 1024 * 1024 * 1024; // 1GB
    const memoryUsagePercent = (memUsage.heapUsed / maxMemory) * 100;
    
    return {
      status: memoryUsagePercent > 90 ? 'down' : 'up',
      responseTime: 0,
      message: `Memory usage: ${memoryUsagePercent.toFixed(2)}%`,
      details: {
        heapUsed: memUsage.heapUsed,
        heapTotal: memUsage.heapTotal,
        rss: memUsage.rss,
        external: memUsage.external,
      },
    };
  }

  private async checkDiskSpace(): Promise<HealthCheckResult['checks'][string]> {
    try {
      const fs = require('fs').promises;
      const stats = await fs.statfs('./');
      
      const freeSpace = stats.bavail * stats.bsize;
      const totalSpace = stats.blocks * stats.bsize;
      const usagePercent = ((totalSpace - freeSpace) / totalSpace) * 100;
      
      return {
        status: usagePercent > 90 ? 'down' : 'up',
        responseTime: 0,
        message: `Disk usage: ${usagePercent.toFixed(2)}%`,
        details: {
          freeSpace,
          totalSpace,
          usagePercent,
        },
      };
    } catch (error) {
      return {
        status: 'down',
        responseTime: 0,
        message: 'Disk space check failed',
        details: { error: error.message },
      };
    }
  }
}
```

### 6.3 Logging Configuration

```typescript
// src/logging/logger.config.ts
import winston from 'winston';
import { env } from '../config/environment';

const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.metadata({
    fillExcept: ['message', 'level', 'timestamp', 'label']
  })
);

const consoleFormat = winston.format.combine(
  logFormat,
  winston.format.colorize(),
  winston.format.printf(({ timestamp, level, message, metadata }) => {
    let log = `${timestamp} [${level}] ${message}`;
    
    if (Object.keys(metadata).length > 0) {
      log += `\n${JSON.stringify(metadata, null, 2)}`;
    }
    
    return log;
  })
);

const jsonFormat = winston.format.combine(
  logFormat,
  winston.format.json()
);

const transports: winston.transport[] = [];

// Console transport for development
if (env.NODE_ENV === 'development') {
  transports.push(
    new winston.transports.Console({
      format: consoleFormat,
      level: env.LOG_LEVEL,
    })
  );
} else {
  // JSON format for production
  transports.push(
    new winston.transports.Console({
      format: jsonFormat,
      level: env.LOG_LEVEL,
    })
  );
}

// File transports for production
if (env.NODE_ENV === 'production') {
  transports.push(
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      format: jsonFormat,
      maxsize: 10485760, // 10MB
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: 'logs/combined.log',
      format: jsonFormat,
      maxsize: 10485760, // 10MB
      maxFiles: 5,
    })
  );
}

export const logger = winston.createLogger({
  level: env.LOG_LEVEL,
  format: logFormat,
  defaultMeta: {
    service: env.APP_NAME,
    version: env.APP_VERSION,
    environment: env.NODE_ENV,
  },
  transports,
  exceptionHandlers: [
    new winston.transports.File({
      filename: 'logs/exceptions.log',
      format: jsonFormat,
    }),
  ],
  rejectionHandlers: [
    new winston.transports.File({
      filename: 'logs/rejections.log',
      format: jsonFormat,
    }),
  ],
});

// Don't exit on handled exceptions in production
if (env.NODE_ENV === 'production') {
  logger.exitOnError = false;
}
```

This comprehensive deployment guide provides everything needed to deploy the DID buy system to production with proper containerization, CI/CD, monitoring, and operational practices.
