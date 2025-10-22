# Spring boot development role

**Created:** 10/22/2025 7:35:52  
**Updated:** 10/22/2025 9:05:01  
**Exported:** 10/22/2025 9:11:51  
**Link:** [https://claude.ai/chat/3fb336aa-3477-492c-b674-8f44318554dd](https://claude.ai/chat/3fb336aa-3477-492c-b674-8f44318554dd)  

## Response:
10/22/2025, 7:36:02 AM

# Spring Boot Developer Mode Activated 🍃

Hey! I'm ready to help you with Spring Boot development. I can assist with:

**Core Spring Boot**
- Application configuration and properties
- Dependency injection and IoC
- RESTful API development
- Spring Data JPA / Hibernate
- Spring Security (authentication/authorization)
- Exception handling and validation

**Database & Persistence**
- JPA/Hibernate entities and repositories
- Database migrations (Flyway/Liquibase)
- Transaction management
- Query optimization

**Microservices & Cloud**
- Spring Cloud components
- Service discovery (Eureka)
- API Gateway
- Config server
- Resilience patterns (Circuit Breaker, Retry)

**Testing & DevOps**
- Unit testing with JUnit/Mockito
- Integration testing
- Docker containerization
- CI/CD pipelines

**Best Practices**
- Clean architecture
- Design patterns
- Performance optimization
- Error handling strategies

What Spring Boot challenge can I help you tackle today? Feel free to share:
- Specific requirements or features you need
- Code issues or errors
- Architecture questions
- Performance optimization needs
- Or any other Spring Boot related topics!



## Response:
10/22/2025, 7:37:57 AM

# Integrating PayMongo GCash Payment in Spring Boot

I'll show you a complete implementation for integrating PayMongo's GCash payment in a Spring Boot application.

## 1. Add Dependencies

```xml
<!-- pom.xml -->
<dependencies>
    <!-- Spring Boot Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- Lombok (optional, for cleaner code) -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
    
    <!-- Spring Boot Starter Validation -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>
</dependencies>
```

## 2. Application Properties

```properties
# application.properties
paymongo.api.secret-key=${PAYMONGO_SECRET_KEY}
paymongo.api.public-key=${PAYMONGO_PUBLIC_KEY}
paymongo.api.base-url=https://api.paymongo.com/v1
```

## 3. Configuration Class

```java
@Configuration
@ConfigurationProperties(prefix = "paymongo.api")
@Data
public class PayMongoConfig {
    private String secretKey;
    private String publicKey;
    private String baseUrl;
    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
```

## 4. DTOs (Data Transfer Objects)

**PayMongo DTOs**

````java
// CreatePaymentRequest.java
package com.example.payment.dto;

import lombok.Data;
import java.math.BigDecimal;

@Data
public class CreatePaymentRequest {
    private BigDecimal amount;
    private String description;
    private String customerEmail;
    private String customerName;
    private String customerPhone;
}

// PaymentSourceRequest.java
package com.example.payment.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PaymentSourceRequest {
    @JsonProperty("data")
    private SourceData data;
    
    @Data
    @Builder
    public static class SourceData {
        private SourceAttributes attributes;
    }
    
    @Data
    @Builder
    public static class SourceAttributes {
        private Long amount;
        private String redirect;
        private String type;
        private BillingDetails billing;
        private String currency;
    }
    
    @Data
    @Builder
    public static class BillingDetails {
        private String name;
        private String email;
        private String phone;
    }
    
    @Data
    @Builder
    public static class RedirectUrls {
        private String success;
        private String failed;
    }
}

// PaymentSourceResponse.java
package com.example.payment.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class PaymentSourceResponse {
    @JsonProperty("data")
    private SourceData data;
    
    @Data
    public static class SourceData {
        private String id;
        private String type;
        private SourceAttributes attributes;
    }
    
    @Data
    public static class SourceAttributes {
        private Long amount;
        private String status;
        private String type;
        @JsonProperty("checkout_url")
        private String checkoutUrl;
        private String currency;
    }
}

// PaymentIntentRequest.java
package com.example.payment.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class PaymentIntentRequest {
    @JsonProperty("data")
    private IntentData data;
    
    @Data
    @Builder
    public static class IntentData {
        private IntentAttributes attributes;
    }
    
    @Data
    @Builder
    public static class IntentAttributes {
        private Long amount;
        @JsonProperty("payment_method_allowed")
        private List<String> paymentMethodAllowed;
        @JsonProperty("payment_method_options")
        private PaymentMethodOptions paymentMethodOptions;
        private String currency;
        private String description;
        @JsonProperty("statement_descriptor")
        private String statementDescriptor;
    }
    
    @Data
    @Builder
    public static class PaymentMethodOptions {
        private CardOptions card;
    }
    
    @Data
    @Builder
    public static class CardOptions {
        @JsonProperty("request_three_d_secure")
        private String requestThreeDSecure;
    }
}

// PaymentIntentResponse.java
package com.example.payment.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class PaymentIntentResponse {
    @JsonProperty("data")
    private IntentData data;
    
    @Data
    public static class IntentData {
        private String id;
        private String type;
        private IntentAttributes attributes;
    }
    
    @Data
    public static class IntentAttributes {
        private Long amount;
        private String currency;
        private String description;
        private String status;
        @JsonProperty("client_key")
        private String clientKey;
        @JsonProperty("payment_method_allowed")
        private String[] paymentMethodAllowed;
    }
}

// AttachPaymentRequest.java
package com.example.payment.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AttachPaymentRequest {
    @JsonProperty("data")
    private AttachData data;
    
    @Data
    @Builder
    public static class AttachData {
        private AttachAttributes attributes;
    }
    
    @Data
    @Builder
    public static class AttachAttributes {
        @JsonProperty("payment_method")
        private String paymentMethod;
        @JsonProperty("client_key")
        private String clientKey;
        @JsonProperty("return_url")
        private String returnUrl;
    }
}

// PaymentResponse.java
package com.example.payment.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PaymentResponse {
    private String paymentId;
    private String status;
    private String checkoutUrl;
    private String message;
    private Long amount;
}
````

## 5. PayMongo Service Implementation

**PayMongo Service**

````java
package com.example.payment.service;

import com.example.payment.config.PayMongoConfig;
import com.example.payment.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

@Service
@RequiredArgsConstructor
@Slf4j
public class PayMongoService {
    
    private final PayMongoConfig payMongoConfig;
    private final RestTemplate restTemplate;
    
    /**
     * Create GCash payment source
     * This is the main method for GCash payments
     */
    public PaymentResponse createGCashPayment(CreatePaymentRequest request) {
        try {
            // Convert amount to centavos (PayMongo uses smallest currency unit)
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            // Build the payment source request
            PaymentSourceRequest sourceRequest = PaymentSourceRequest.builder()
                .data(PaymentSourceRequest.SourceData.builder()
                    .attributes(PaymentSourceRequest.SourceAttributes.builder()
                        .amount(amountInCentavos)
                        .type("gcash")
                        .currency("PHP")
                        .redirect(PaymentSourceRequest.RedirectUrls.builder()
                            .success("https://your-website.com/payment/success")
                            .failed("https://your-website.com/payment/failed")
                            .build()
                            .toString())
                        .billing(PaymentSourceRequest.BillingDetails.builder()
                            .name(request.getCustomerName())
                            .email(request.getCustomerEmail())
                            .phone(request.getCustomerPhone())
                            .build())
                        .build())
                    .build())
                .build();
            
            // Create HTTP headers with Basic Auth
            HttpHeaders headers = createHeaders();
            HttpEntity<PaymentSourceRequest> entity = new HttpEntity<>(sourceRequest, headers);
            
            // Make API call to PayMongo
            String url = payMongoConfig.getBaseUrl() + "/sources";
            ResponseEntity<PaymentSourceResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                PaymentSourceResponse.class
            );
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                PaymentSourceResponse.SourceData data = response.getBody().getData();
                
                log.info("GCash payment source created: {}", data.getId());
                
                return PaymentResponse.builder()
                    .paymentId(data.getId())
                    .status(data.getAttributes().getStatus())
                    .checkoutUrl(data.getAttributes().getCheckoutUrl())
                    .amount(data.getAttributes().getAmount())
                    .message("Payment source created successfully. Redirect user to checkout URL.")
                    .build();
            }
            
            throw new RuntimeException("Failed to create payment source");
            
        } catch (Exception e) {
            log.error("Error creating GCash payment: {}", e.getMessage(), e);
            throw new RuntimeException("Payment creation failed: " + e.getMessage());
        }
    }
    
    /**
     * Retrieve payment source status
     */
    public PaymentSourceResponse getPaymentSource(String sourceId) {
        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<?> entity = new HttpEntity<>(headers);
            
            String url = payMongoConfig.getBaseUrl() + "/sources/" + sourceId;
            ResponseEntity<PaymentSourceResponse> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                entity,
                PaymentSourceResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            log.error("Error retrieving payment source: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to retrieve payment source: " + e.getMessage());
        }
    }
    
    /**
     * Create payment intent (alternative method)
     */
    public PaymentIntentResponse createPaymentIntent(CreatePaymentRequest request) {
        try {
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            PaymentIntentRequest intentRequest = PaymentIntentRequest.builder()
                .data(PaymentIntentRequest.IntentData.builder()
                    .attributes(PaymentIntentRequest.IntentAttributes.builder()
                        .amount(amountInCentavos)
                        .paymentMethodAllowed(Collections.singletonList("gcash"))
                        .currency("PHP")
                        .description(request.getDescription())
                        .build())
                    .build())
                .build();
            
            HttpHeaders headers = createHeaders();
            HttpEntity<PaymentIntentRequest> entity = new HttpEntity<>(intentRequest, headers);
            
            String url = payMongoConfig.getBaseUrl() + "/payment_intents";
            ResponseEntity<PaymentIntentResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                PaymentIntentResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            log.error("Error creating payment intent: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create payment intent: " + e.getMessage());
        }
    }
    
    /**
     * Create HTTP headers with Basic Authentication
     */
    private HttpHeaders createHeaders() {
        String auth = payMongoConfig.getSecretKey() + ":";
        byte[] encodedAuth = Base64.getEncoder().encode(auth.getBytes(StandardCharsets.UTF_8));
        String authHeader = "Basic " + new String(encodedAuth);
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", authHeader);
        
        return headers;
    }
    
    /**
     * Verify webhook signature (for production use)
     */
    public boolean verifyWebhookSignature(String payload, String signature) {
        // Implement webhook signature verification
        // This is important for production to ensure webhooks are from PayMongo
        return true; // Placeholder
    }
}
````

## 6. REST Controller

**Payment Controller**

````java
package com.example.payment.controller;

import com.example.payment.dto.CreatePaymentRequest;
import com.example.payment.dto.PaymentResponse;
import com.example.payment.dto.PaymentSourceResponse;
import com.example.payment.service.PayMongoService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.validation.Valid;

@RestController
@RequestMapping("/api/payments")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "*") // Configure properly for production
public class PaymentController {
    
    private final PayMongoService payMongoService;
    
    /**
     * Create GCash payment
     * POST /api/payments/gcash
     */
    @PostMapping("/gcash")
    public ResponseEntity<PaymentResponse> createGCashPayment(
            @Valid @RequestBody CreatePaymentRequest request) {
        try {
            log.info("Creating GCash payment for amount: {}", request.getAmount());
            PaymentResponse response = payMongoService.createGCashPayment(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error creating payment: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(PaymentResponse.builder()
                    .status("failed")
                    .message("Payment creation failed: " + e.getMessage())
                    .build());
        }
    }
    
    /**
     * Check payment status
     * GET /api/payments/status/{sourceId}
     */
    @GetMapping("/status/{sourceId}")
    public ResponseEntity<PaymentSourceResponse> getPaymentStatus(
            @PathVariable String sourceId) {
        try {
            log.info("Checking payment status for source: {}", sourceId);
            PaymentSourceResponse response = payMongoService.getPaymentSource(sourceId);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error retrieving payment status: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * Webhook endpoint for PayMongo events
     * POST /api/payments/webhook
     */
    @PostMapping("/webhook")
    public ResponseEntity<String> handleWebhook(
            @RequestBody String payload,
            @RequestHeader("PayMongo-Signature") String signature) {
        try {
            log.info("Received webhook event");
            
            // Verify webhook signature
            if (!payMongoService.verifyWebhookSignature(payload, signature)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid signature");
            }
            
            // Parse and process the webhook event
            // Update your database based on payment status
            log.info("Webhook payload: {}", payload);
            
            // Common events:
            // - source.chargeable: Payment source is ready to be charged
            // - payment.paid: Payment was successful
            // - payment.failed: Payment failed
            
            return ResponseEntity.ok("Webhook processed");
        } catch (Exception e) {
            log.error("Error processing webhook: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error processing webhook");
        }
    }
    
    /**
     * Success callback endpoint
     * GET /api/payments/success
     */
    @GetMapping("/success")
    public ResponseEntity<String> paymentSuccess(@RequestParam(required = false) String sourceId) {
        log.info("Payment successful for source: {}", sourceId);
        // Redirect to success page or return success response
        return ResponseEntity.ok("Payment successful!");
    }
    
    /**
     * Failed callback endpoint
     * GET /api/payments/failed
     */
    @GetMapping("/failed")
    public ResponseEntity<String> paymentFailed(@RequestParam(required = false) String sourceId) {
        log.info("Payment failed for source: {}", sourceId);
        // Redirect to failed page or return error response
        return ResponseEntity.status(HttpStatus.PAYMENT_REQUIRED).body("Payment failed!");
    }
}
````

## 7. Exception Handler (Optional but Recommended)

**Payment Exception Handler**

````java
package com.example.payment.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class PaymentExceptionHandler {
    
    @ExceptionHandler(HttpClientErrorException.class)
    public ResponseEntity<Map<String, Object>> handleClientError(HttpClientErrorException ex) {
        log.error("PayMongo client error: {}", ex.getMessage());
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", ex.getStatusCode().value());
        errorResponse.put("error", "Payment API Error");
        errorResponse.put("message", "Invalid payment request. Please check your input.");
        errorResponse.put("details", ex.getResponseBodyAsString());
        
        return ResponseEntity.status(ex.getStatusCode()).body(errorResponse);
    }
    
    @ExceptionHandler(HttpServerErrorException.class)
    public ResponseEntity<Map<String, Object>> handleServerError(HttpServerErrorException ex) {
        log.error("PayMongo server error: {}", ex.getMessage());
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", HttpStatus.SERVICE_UNAVAILABLE.value());
        errorResponse.put("error", "Payment Service Unavailable");
        errorResponse.put("message", "Payment service is temporarily unavailable. Please try again later.");
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
    }
    
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(RuntimeException ex) {
        log.error("Runtime error: {}", ex.getMessage(), ex);
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        errorResponse.put("error", "Internal Server Error");
        errorResponse.put("message", ex.getMessage());
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) {
        log.error("Unexpected error: {}", ex.getMessage(), ex);
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        errorResponse.put("error", "Internal Server Error");
        errorResponse.put("message", "An unexpected error occurred");
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }
}
````

## 8. Testing with Postman or cURL

```bash
# Create GCash Payment
curl -X POST http://localhost:8080/api/payments/gcash \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 100.00,
    "description": "Test Payment",
    "customerEmail": "juan@example.com",
    "customerName": "Juan Dela Cruz",
    "customerPhone": "+639171234567"
  }'

# Check Payment Status
curl -X GET http://localhost:8080/api/payments/status/src_xxxxxxxxxxxxx
```

## 9. Environment Variables Setup

Create `.env` file or set environment variables:

```bash
PAYMONGO_SECRET_KEY=sk_test_your_secret_key_here
PAYMONGO_PUBLIC_KEY=pk_test_your_public_key_here
```

## 10. Payment Flow

1. **User initiates payment** → Your frontend calls `/api/payments/gcash`
2. **Backend creates payment source** → Returns `checkoutUrl`
3. **Redirect user to checkoutUrl** → User completes payment on PayMongo/GCash
4. **User redirected back** → To your success/failed URLs
5. **Webhook notification** → PayMongo sends payment status to `/api/payments/webhook`
6. **Update order status** → Based on webhook data

## Important Notes:

- **Test Mode**: Use `sk_test_` keys for development
- **Production**: Use `sk_live_` keys and configure proper webhook URLs
- **Webhooks**: Set up webhook URL in PayMongo dashboard: `https://yourdomain.com/api/payments/webhook`
- **Amount**: Always in centavos (100 = ₱1.00)
- **Currency**: Only PHP supported
- **Phone Format**: Must include country code (+63)

## Next Steps:

1. Get your API keys from [PayMongo Dashboard](https://dashboard.paymongo.com)
2. Set up webhooks in PayMongo dashboard
3. Test with test credentials first
4. Implement proper database persistence
5. Add transaction logging
6. Implement idempotency for duplicate requests

Would you like me to add database integration, webhook signature verification, or any specific feature?



## Response:
10/22/2025, 7:42:24 AM

# Where to Save .env File in Spring Boot

## 1. **Root Directory of Your Project** (Recommended)

The `.env` file should be placed at the **root of your Spring Boot project**, at the same level as your `pom.xml` or `build.gradle`:

```
my-spring-boot-app/
├── .env                    ← HERE (same level as pom.xml)
├── .gitignore
├── pom.xml
├── src/
│   ├── main/
│   │   ├── java/
│   │   └── resources/
│   │       └── application.properties
│   └── test/
└── target/
```

## 2. **Add .env to .gitignore**

**IMPORTANT**: Never commit your `.env` file to Git!

```gitignore
# .gitignore
.env
*.env
.env.local
.env.*.local
```

## 3. **Methods to Load .env in Spring Boot**

### **Option A: Using spring-dotenv (Easiest)**

Add dependency:
```xml
<!-- pom.xml -->
<dependency>
    <groupId>me.paulschwarz</groupId>
    <artifactId>spring-dotenv</artifactId>
    <version>4.0.0</version>
</dependency>
```

Create `.env` file:
```properties
# .env
PAYMONGO_SECRET_KEY=sk_test_xxxxxxxxxxxxxxxxxxxxxx
PAYMONGO_PUBLIC_KEY=pk_test_xxxxxxxxxxxxxxxxxxxxxx
```

Use in `application.properties`:
```properties
# application.properties
paymongo.api.secret-key=${PAYMONGO_SECRET_KEY}
paymongo.api.public-key=${PAYMONGO_PUBLIC_KEY}
paymongo.api.base-url=https://api.paymongo.com/v1
```

---

### **Option B: Using dotenv-java Library**

Add dependency:
```xml
<dependency>
    <groupId>io.github.cdimascio</groupId>
    <artifactId>dotenv-java</artifactId>
    <version>3.0.0</version>
</dependency>
```

Load in your main application class:
```java
@SpringBootApplication
public class PaymentApplication {
    
    public static void main(String[] args) {
        // Load .env file
        Dotenv dotenv = Dotenv.configure()
            .directory("./")  // Look in root directory
            .ignoreIfMissing()
            .load();
        
        // Set as system properties
        dotenv.entries().forEach(entry -> 
            System.setProperty(entry.getKey(), entry.getValue())
        );
        
        SpringApplication.run(PaymentApplication.class, args);
    }
}
```

---

### **Option C: Using System Environment Variables (Production)**

For production, don't use `.env` files. Instead, set environment variables:

**Linux/Mac:**
```bash
export PAYMONGO_SECRET_KEY=sk_live_xxxxx
export PAYMONGO_PUBLIC_KEY=pk_live_xxxxx
```

**Windows (Command Prompt):**
```cmd
set PAYMONGO_SECRET_KEY=sk_live_xxxxx
set PAYMONGO_PUBLIC_KEY=pk_live_xxxxx
```

**Windows (PowerShell):**
```powershell
$env:PAYMONGO_SECRET_KEY="sk_live_xxxxx"
$env:PAYMONGO_PUBLIC_KEY="pk_live_xxxxx"
```

---

### **Option D: Using application-{profile}.properties**

Create separate property files for different environments:

```
src/main/resources/
├── application.properties           # Common config
├── application-dev.properties       # Development
├── application-prod.properties      # Production
└── application-test.properties      # Testing
```

**application-dev.properties:**
```properties
paymongo.api.secret-key=sk_test_xxxxxx
paymongo.api.public-key=pk_test_xxxxxx
```

**application-prod.properties:**
```properties
paymongo.api.secret-key=${PAYMONGO_SECRET_KEY}
paymongo.api.public-key=${PAYMONGO_PUBLIC_KEY}
```

Run with profile:
```bash
# Development
java -jar -Dspring.profiles.active=dev myapp.jar

# Production
java -jar -Dspring.profiles.active=prod myapp.jar
```

---

## 4. **Example .env File Structure**

Create your `.env` file in project root:

```properties
# .env - PayMongo Configuration

# API Keys (Get from https://dashboard.paymongo.com)
PAYMONGO_SECRET_KEY=sk_test_xxxxxxxxxxxxxxxxxxxxxx
PAYMONGO_PUBLIC_KEY=pk_test_xxxxxxxxxxxxxxxxxxxxxx

# Database Configuration (if needed)
DB_URL=jdbc:postgresql://localhost:5432/payment_db
DB_USERNAME=postgres
DB_PASSWORD=yourpassword

# Server Configuration
SERVER_PORT=8080
SERVER_URL=http://localhost:8080

# Success/Failure URLs
PAYMENT_SUCCESS_URL=http://localhost:3000/payment/success
PAYMENT_FAILED_URL=http://localhost:3000/payment/failed
```

---

## 5. **IntelliJ IDEA Configuration**

If using IntelliJ IDEA, you can also set environment variables in Run Configuration:

1. **Run → Edit Configurations**
2. Select your Spring Boot application
3. **Environment Variables** → Click folder icon
4. Add your variables:
   ```
   PAYMONGO_SECRET_KEY=sk_test_xxxxx
   PAYMONGO_PUBLIC_KEY=pk_test_xxxxx
   ```

---

## 6. **Docker Configuration**

If deploying with Docker, use `.env` with docker-compose:

**docker-compose.yml:**
```yaml
version: '3.8'
services:
  app:
    build: .
    env_file:
      - .env
    ports:
      - "8080:8080"
```

Or pass environment variables directly:
```yaml
version: '3.8'
services:
  app:
    build: .
    environment:
      - PAYMONGO_SECRET_KEY=${PAYMONGO_SECRET_KEY}
      - PAYMONGO_PUBLIC_KEY=${PAYMONGO_PUBLIC_KEY}
    ports:
      - "8080:8080"
```

---

## 7. **Best Practices**

✅ **DO:**
- Keep `.env` in project root
- Add `.env` to `.gitignore`
- Use different keys for dev/test/prod
- Use environment variables in production
- Document required variables in `README.md`

❌ **DON'T:**
- Commit `.env` to version control
- Share API keys in public repositories
- Hardcode sensitive values in code
- Use production keys in development

---

## 8. **Create .env.example Template**

Create a `.env.example` file (safe to commit) to document required variables:

```properties
# .env.example - Copy this to .env and fill in your values

PAYMONGO_SECRET_KEY=sk_test_your_key_here
PAYMONGO_PUBLIC_KEY=pk_test_your_key_here
```

Add to your `README.md`:
```markdown
## Setup

1. Copy `.env.example` to `.env`
2. Fill in your PayMongo API keys
3. Run the application
```

---

## Quick Setup Command:

```bash
# Create .env file in project root
cd /path/to/your/spring-boot-project
touch .env
echo "PAYMONGO_SECRET_KEY=sk_test_xxxxx" >> .env
echo "PAYMONGO_PUBLIC_KEY=pk_test_xxxxx" >> .env

# Add to .gitignore
echo ".env" >> .gitignore
```

**My recommendation**: Use **Option A (spring-dotenv)** for development - it's the simplest and most Spring Boot-friendly approach! For production, use actual environment variables.



## Response:
10/22/2025, 8:35:30 AM

# Fixing PayMongo Authentication Error

The error means your API key authentication isn't working properly. Let's fix it!

## Common Issues & Solutions:

### **Issue 1: Incorrect Base64 Encoding**

The PayMongo API requires **Basic Authentication** where you encode `secret_key:` (note the colon at the end with nothing after it).

**Fix the `createHeaders()` method in PayMongoService:**

**PayMongo Service** ∙ Version 2

````java
package com.example.payment.service;

import com.example.payment.config.PayMongoConfig;
import com.example.payment.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

@Service
@RequiredArgsConstructor
@Slf4j
public class PayMongoService {
    
    private final PayMongoConfig payMongoConfig;
    private final RestTemplate restTemplate;
    
    /**
     * Create GCash payment source
     * This is the main method for GCash payments
     */
    public PaymentResponse createGCashPayment(CreatePaymentRequest request) {
        try {
            // Convert amount to centavos (PayMongo uses smallest currency unit)
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            // Build the payment source request
            PaymentSourceRequest sourceRequest = PaymentSourceRequest.builder()
                .data(PaymentSourceRequest.SourceData.builder()
                    .attributes(PaymentSourceRequest.SourceAttributes.builder()
                        .amount(amountInCentavos)
                        .type("gcash")
                        .currency("PHP")
                        .redirect(PaymentSourceRequest.RedirectUrls.builder()
                            .success("https://your-website.com/payment/success")
                            .failed("https://your-website.com/payment/failed")
                            .build()
                            .toString())
                        .billing(PaymentSourceRequest.BillingDetails.builder()
                            .name(request.getCustomerName())
                            .email(request.getCustomerEmail())
                            .phone(request.getCustomerPhone())
                            .build())
                        .build())
                    .build())
                .build();
            
            // Create HTTP headers with Basic Auth
            HttpHeaders headers = createHeaders();
            HttpEntity<PaymentSourceRequest> entity = new HttpEntity<>(sourceRequest, headers);
            
            // Make API call to PayMongo
            String url = payMongoConfig.getBaseUrl() + "/sources";
            ResponseEntity<PaymentSourceResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                PaymentSourceResponse.class
            );
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                PaymentSourceResponse.SourceData data = response.getBody().getData();
                
                log.info("GCash payment source created: {}", data.getId());
                
                return PaymentResponse.builder()
                    .paymentId(data.getId())
                    .status(data.getAttributes().getStatus())
                    .checkoutUrl(data.getAttributes().getCheckoutUrl())
                    .amount(data.getAttributes().getAmount())
                    .message("Payment source created successfully. Redirect user to checkout URL.")
                    .build();
            }
            
            throw new RuntimeException("Failed to create payment source");
            
        } catch (Exception e) {
            log.error("Error creating GCash payment: {}", e.getMessage(), e);
            throw new RuntimeException("Payment creation failed: " + e.getMessage());
        }
    }
    
    /**
     * Retrieve payment source status
     */
    public PaymentSourceResponse getPaymentSource(String sourceId) {
        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<?> entity = new HttpEntity<>(headers);
            
            String url = payMongoConfig.getBaseUrl() + "/sources/" + sourceId;
            ResponseEntity<PaymentSourceResponse> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                entity,
                PaymentSourceResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            log.error("Error retrieving payment source: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to retrieve payment source: " + e.getMessage());
        }
    }
    
    /**
     * Create payment intent (alternative method)
     */
    public PaymentIntentResponse createPaymentIntent(CreatePaymentRequest request) {
        try {
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            PaymentIntentRequest intentRequest = PaymentIntentRequest.builder()
                .data(PaymentIntentRequest.IntentData.builder()
                    .attributes(PaymentIntentRequest.IntentAttributes.builder()
                        .amount(amountInCentavos)
                        .paymentMethodAllowed(Collections.singletonList("gcash"))
                        .currency("PHP")
                        .description(request.getDescription())
                        .build())
                    .build())
                .build();
            
            HttpHeaders headers = createHeaders();
            HttpEntity<PaymentIntentRequest> entity = new HttpEntity<>(intentRequest, headers);
            
            String url = payMongoConfig.getBaseUrl() + "/payment_intents";
            ResponseEntity<PaymentIntentResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                PaymentIntentResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            log.error("Error creating payment intent: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create payment intent: " + e.getMessage());
        }
    }
    
    /**
     * Create HTTP headers with Basic Authentication
     */
    private HttpHeaders createHeaders() {
        // PayMongo requires: Base64(secret_key:) - note the colon at the end
        String auth = payMongoConfig.getSecretKey() + ":";
        String encodedAuth = Base64.getEncoder()
            .encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        String authHeader = "Basic " + encodedAuth;
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", authHeader);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        
        // Log for debugging (remove in production)
        log.debug("Auth header created for key: {}...", 
            payMongoConfig.getSecretKey().substring(0, 10));
        
        return headers;
    }
    
    /**
     * Verify webhook signature (for production use)
     */
    public boolean verifyWebhookSignature(String payload, String signature) {
        // Implement webhook signature verification
        // This is important for production to ensure webhooks are from PayMongo
        return true; // Placeholder
    }
}
````

### **Issue 2: Missing or Incorrect API Key**

**Check your `.env` file:**

```properties
# .env
# Make sure there are NO spaces around the = sign
# Use your ACTUAL keys from PayMongo dashboard
PAYMONGO_SECRET_KEY=sk_test_xxxxxxxxxxxxxxxxxxxxxx
PAYMONGO_PUBLIC_KEY=pk_test_xxxxxxxxxxxxxxxxxxxxxx
```

**Verify keys are loaded:**

Add this test endpoint to verify your configuration:

```java
@RestController
@RequestMapping("/api/test")
@RequiredArgsConstructor
public class TestController {
    
    private final PayMongoConfig payMongoConfig;
    
    @GetMapping("/config")
    public ResponseEntity<Map<String, String>> testConfig() {
        Map<String, String> config = new HashMap<>();
        
        String secretKey = payMongoConfig.getSecretKey();
        if (secretKey != null && !secretKey.isEmpty()) {
            // Only show first 10 characters for security
            config.put("secretKey", secretKey.substring(0, 10) + "...");
            config.put("secretKeyLength", String.valueOf(secretKey.length()));
            config.put("startsWithSk", String.valueOf(secretKey.startsWith("sk_")));
        } else {
            config.put("secretKey", "NOT LOADED!");
        }
        
        config.put("baseUrl", payMongoConfig.getBaseUrl());
        
        return ResponseEntity.ok(config);
    }
}
```

Visit: `http://localhost:8080/api/test/config` to verify keys are loaded.

---

### **Issue 3: Verify Your API Keys**

1. Go to [PayMongo Dashboard](https://dashboard.paymongo.com/)
2. Navigate to **Developers** → **API Keys**
3. Copy the **Secret Key** (starts with `sk_test_` for test mode)
4. Make sure you're using the **Secret Key**, NOT the Public Key for API calls

Your secret key should look like:
```
sk_test_ABC123XYZ789abc123xyz789ABC123XYZ789
```

---

### **Issue 4: Test with cURL First**

Before testing your Spring Boot app, verify your API key works with cURL:

```bash
# Replace with your actual secret key
curl https://api.paymongo.com/v1/sources \
  -u sk_test_YOUR_SECRET_KEY_HERE: \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "attributes": {
        "amount": 10000,
        "redirect": {
          "success": "http://localhost:8080/success",
          "failed": "http://localhost:8080/failed"
        },
        "type": "gcash",
        "currency": "PHP"
      }
    }
  }'
```

**Note:** The `-u sk_test_XXX:` (with colon at the end) is how you do basic auth with cURL.

---

### **Issue 5: Updated PayMongoService with Better Error Handling**

**PayMongo Service** ∙ Version 3

````java
package com.example.payment.service;

import com.example.payment.config.PayMongoConfig;
import com.example.payment.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

@Service
@RequiredArgsConstructor
@Slf4j
public class PayMongoService {
    
    private final PayMongoConfig payMongoConfig;
    private final RestTemplate restTemplate;
    
    /**
     * Create GCash payment source
     * This is the main method for GCash payments
     */
    public PaymentResponse createGCashPayment(CreatePaymentRequest request) {
        try {
            // Validate secret key is loaded
            if (payMongoConfig.getSecretKey() == null || payMongoConfig.getSecretKey().isEmpty()) {
                throw new RuntimeException("PayMongo secret key is not configured");
            }
            
            // Convert amount to centavos (PayMongo uses smallest currency unit)
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            // Build redirect object properly
            Map<String, String> redirectUrls = new HashMap<>();
            redirectUrls.put("success", "http://localhost:8080/api/payments/success");
            redirectUrls.put("failed", "http://localhost:8080/api/payments/failed");
            
            // Build the request manually to ensure proper structure
            Map<String, Object> requestBody = new HashMap<>();
            Map<String, Object> data = new HashMap<>();
            Map<String, Object> attributes = new HashMap<>();
            
            attributes.put("amount", amountInCentavos);
            attributes.put("type", "gcash");
            attributes.put("currency", "PHP");
            attributes.put("redirect", redirectUrls);
            
            // Add billing details
            Map<String, String> billing = new HashMap<>();
            billing.put("name", request.getCustomerName());
            billing.put("email", request.getCustomerEmail());
            billing.put("phone", request.getCustomerPhone());
            attributes.put("billing", billing);
            
            data.put("attributes", attributes);
            requestBody.put("data", data);
            
            // Create HTTP headers with Basic Auth
            HttpHeaders headers = createHeaders();
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
            
            // Make API call to PayMongo
            String url = payMongoConfig.getBaseUrl() + "/sources";
            
            log.info("Calling PayMongo API: {}", url);
            log.debug("Request body: {}", requestBody);
            
            ResponseEntity<PaymentSourceResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                PaymentSourceResponse.class
            );
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                PaymentSourceResponse.SourceData responseData = response.getBody().getData();
                
                log.info("GCash payment source created: {}", responseData.getId());
                
                return PaymentResponse.builder()
                    .paymentId(responseData.getId())
                    .status(responseData.getAttributes().getStatus())
                    .checkoutUrl(responseData.getAttributes().getCheckoutUrl())
                    .amount(responseData.getAttributes().getAmount())
                    .message("Payment source created successfully. Redirect user to checkout URL.")
                    .build();
            }
            
            throw new RuntimeException("Failed to create payment source");
            
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            log.error("PayMongo API error: Status={}, Response={}", 
                e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Payment creation failed: " + e.getResponseBodyAsString());
        } catch (Exception e) {
            log.error("Error creating GCash payment: {}", e.getMessage(), e);
            throw new RuntimeException("Payment creation failed: " + e.getMessage());
        }
    }
    
    /**
     * Retrieve payment source status
     */
    public PaymentSourceResponse getPaymentSource(String sourceId) {
        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<?> entity = new HttpEntity<>(headers);
            
            String url = payMongoConfig.getBaseUrl() + "/sources/" + sourceId;
            ResponseEntity<PaymentSourceResponse> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                entity,
                PaymentSourceResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            log.error("Error retrieving payment source: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to retrieve payment source: " + e.getMessage());
        }
    }
    
    /**
     * Create payment intent (alternative method)
     */
    public PaymentIntentResponse createPaymentIntent(CreatePaymentRequest request) {
        try {
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            PaymentIntentRequest intentRequest = PaymentIntentRequest.builder()
                .data(PaymentIntentRequest.IntentData.builder()
                    .attributes(PaymentIntentRequest.IntentAttributes.builder()
                        .amount(amountInCentavos)
                        .paymentMethodAllowed(Collections.singletonList("gcash"))
                        .currency("PHP")
                        .description(request.getDescription())
                        .build())
                    .build())
                .build();
            
            HttpHeaders headers = createHeaders();
            HttpEntity<PaymentIntentRequest> entity = new HttpEntity<>(intentRequest, headers);
            
            String url = payMongoConfig.getBaseUrl() + "/payment_intents";
            ResponseEntity<PaymentIntentResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                PaymentIntentResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            log.error("Error creating payment intent: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create payment intent: " + e.getMessage());
        }
    }
    
    /**
     * Create HTTP headers with Basic Authentication
     */
    private HttpHeaders createHeaders() {
        // PayMongo requires: Base64(secret_key:) - note the colon at the end
        String auth = payMongoConfig.getSecretKey() + ":";
        String encodedAuth = Base64.getEncoder()
            .encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        String authHeader = "Basic " + encodedAuth;
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", authHeader);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        
        // Log for debugging (remove in production)
        log.debug("Auth header created for key: {}...", 
            payMongoConfig.getSecretKey().substring(0, 10));
        
        return headers;
    }
    
    /**
     * Verify webhook signature (for production use)
     */
    public boolean verifyWebhookSignature(String payload, String signature) {
        // Implement webhook signature verification
        // This is important for production to ensure webhooks are from PayMongo
        return true; // Placeholder
    }
}
````

---

### **Issue 6: Add Missing Import**

**PayMongo Service** ∙ Version 4

````java
package com.example.payment.service;

import com.example.payment.config.PayMongoConfig;
import com.example.payment.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class PayMongoService {
    
    private final PayMongoConfig payMongoConfig;
    private final RestTemplate restTemplate;
    
    /**
     * Create GCash payment source
     * This is the main method for GCash payments
     */
    public PaymentResponse createGCashPayment(CreatePaymentRequest request) {
        try {
            // Validate secret key is loaded
            if (payMongoConfig.getSecretKey() == null || payMongoConfig.getSecretKey().isEmpty()) {
                throw new RuntimeException("PayMongo secret key is not configured");
            }
            
            // Convert amount to centavos (PayMongo uses smallest currency unit)
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            // Build redirect object properly
            Map<String, String> redirectUrls = new HashMap<>();
            redirectUrls.put("success", "http://localhost:8080/api/payments/success");
            redirectUrls.put("failed", "http://localhost:8080/api/payments/failed");
            
            // Build the request manually to ensure proper structure
            Map<String, Object> requestBody = new HashMap<>();
            Map<String, Object> data = new HashMap<>();
            Map<String, Object> attributes = new HashMap<>();
            
            attributes.put("amount", amountInCentavos);
            attributes.put("type", "gcash");
            attributes.put("currency", "PHP");
            attributes.put("redirect", redirectUrls);
            
            // Add billing details
            Map<String, String> billing = new HashMap<>();
            billing.put("name", request.getCustomerName());
            billing.put("email", request.getCustomerEmail());
            billing.put("phone", request.getCustomerPhone());
            attributes.put("billing", billing);
            
            data.put("attributes", attributes);
            requestBody.put("data", data);
            
            // Create HTTP headers with Basic Auth
            HttpHeaders headers = createHeaders();
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
            
            // Make API call to PayMongo
            String url = payMongoConfig.getBaseUrl() + "/sources";
            
            log.info("Calling PayMongo API: {}", url);
            log.debug("Request body: {}", requestBody);
            
            ResponseEntity<PaymentSourceResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                PaymentSourceResponse.class
            );
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                PaymentSourceResponse.SourceData responseData = response.getBody().getData();
                
                log.info("GCash payment source created: {}", responseData.getId());
                
                return PaymentResponse.builder()
                    .paymentId(responseData.getId())
                    .status(responseData.getAttributes().getStatus())
                    .checkoutUrl(responseData.getAttributes().getCheckoutUrl())
                    .amount(responseData.getAttributes().getAmount())
                    .message("Payment source created successfully. Redirect user to checkout URL.")
                    .build();
            }
            
            throw new RuntimeException("Failed to create payment source");
            
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            log.error("PayMongo API error: Status={}, Response={}", 
                e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Payment creation failed: " + e.getResponseBodyAsString());
        } catch (Exception e) {
            log.error("Error creating GCash payment: {}", e.getMessage(), e);
            throw new RuntimeException("Payment creation failed: " + e.getMessage());
        }
    }
    
    /**
     * Retrieve payment source status
     */
    public PaymentSourceResponse getPaymentSource(String sourceId) {
        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<?> entity = new HttpEntity<>(headers);
            
            String url = payMongoConfig.getBaseUrl() + "/sources/" + sourceId;
            ResponseEntity<PaymentSourceResponse> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                entity,
                PaymentSourceResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            log.error("Error retrieving payment source: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to retrieve payment source: " + e.getMessage());
        }
    }
    
    /**
     * Create payment intent (alternative method)
     */
    public PaymentIntentResponse createPaymentIntent(CreatePaymentRequest request) {
        try {
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            PaymentIntentRequest intentRequest = PaymentIntentRequest.builder()
                .data(PaymentIntentRequest.IntentData.builder()
                    .attributes(PaymentIntentRequest.IntentAttributes.builder()
                        .amount(amountInCentavos)
                        .paymentMethodAllowed(Collections.singletonList("gcash"))
                        .currency("PHP")
                        .description(request.getDescription())
                        .build())
                    .build())
                .build();
            
            HttpHeaders headers = createHeaders();
            HttpEntity<PaymentIntentRequest> entity = new HttpEntity<>(intentRequest, headers);
            
            String url = payMongoConfig.getBaseUrl() + "/payment_intents";
            ResponseEntity<PaymentIntentResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                PaymentIntentResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            log.error("Error creating payment intent: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create payment intent: " + e.getMessage());
        }
    }
    
    /**
     * Create HTTP headers with Basic Authentication
     */
    private HttpHeaders createHeaders() {
        // PayMongo requires: Base64(secret_key:) - note the colon at the end
        String auth = payMongoConfig.getSecretKey() + ":";
        String encodedAuth = Base64.getEncoder()
            .encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        String authHeader = "Basic " + encodedAuth;
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", authHeader);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        
        // Log for debugging (remove in production)
        log.debug("Auth header created for key: {}...", 
            payMongoConfig.getSecretKey().substring(0, 10));
        
        return headers;
    }
    
    /**
     * Verify webhook signature (for production use)
     */
    public boolean verifyWebhookSignature(String payload, String signature) {
        // Implement webhook signature verification
        // This is important for production to ensure webhooks are from PayMongo
        return true; // Placeholder
    }
}
````

---

## **Debugging Checklist:**

1. ✅ **Verify .env file location** - Must be in project root
2. ✅ **Check API key format** - Should start with `sk_test_`
3. ✅ **No extra spaces** - In .env file around `=`
4. ✅ **Test with /api/test/config** - Verify keys are loaded
5. ✅ **Test with cURL** - Verify your key works outside Spring Boot
6. ✅ **Check logs** - Look for the debug log showing key prefix
7. ✅ **Restart application** - After changing .env

---

## **Quick Test:**

```bash
# 1. Verify your .env file
cat .env

# 2. Test configuration endpoint
curl http://localhost:8080/api/test/config

# 3. Try creating a payment
curl -X POST http://localhost:8080/api/payments/gcash \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 100.00,
    "description": "Test Payment",
    "customerEmail": "test@example.com",
    "customerName": "Juan Dela Cruz",
    "customerPhone": "+639171234567"
  }'
```

---

## **If Still Not Working:**

Enable debug logging in `application.properties`:

```properties
logging.level.com.example.payment=DEBUG
logging.level.org.springframework.web.client=DEBUG
```

This will show you the exact HTTP request being sent to PayMongo, including headers.

Let me know what you see when you test with the `/api/test/config` endpoint!



## Response:
10/22/2025, 9:05:01 AM

# 🎉 Great! Payment Source Created Successfully!

However, I notice the **`checkoutUrl` is null**. This is a common issue with PayMongo's GCash integration. Let me help you fix it!

## Issue: Missing Checkout URL

The `checkoutUrl` should contain the URL where users complete their GCash payment. When it's null, it usually means the response structure is different than expected.

## Solution: Update the Response Handling

**PayMongo DTOs** ∙ Version 2

````java
// CreatePaymentRequest.java
package com.example.payment.dto;

import lombok.Data;
import java.math.BigDecimal;

@Data
public class CreatePaymentRequest {
    private BigDecimal amount;
    private String description;
    private String customerEmail;
    private String customerName;
    private String customerPhone;
}

// PaymentSourceRequest.java
package com.example.payment.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PaymentSourceRequest {
    @JsonProperty("data")
    private SourceData data;
    
    @Data
    @Builder
    public static class SourceData {
        private SourceAttributes attributes;
    }
    
    @Data
    @Builder
    public static class SourceAttributes {
        private Long amount;
        private String redirect;
        private String type;
        private BillingDetails billing;
        private String currency;
    }
    
    @Data
    @Builder
    public static class BillingDetails {
        private String name;
        private String email;
        private String phone;
    }
    
    @Data
    @Builder
    public static class RedirectUrls {
        private String success;
        private String failed;
    }
}

// PaymentSourceResponse.java
package com.example.payment.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class PaymentSourceResponse {
    @JsonProperty("data")
    private SourceData data;
    
    @Data
    public static class SourceData {
        private String id;
        private String type;
        private SourceAttributes attributes;
    }
    
    @Data
    public static class SourceAttributes {
        private Long amount;
        private String status;
        private String type;
        @JsonProperty("checkout_url")
        private String checkoutUrl;
        private String currency;
        private Object redirect;  // Can contain success/failed URLs
        private Billing billing;
        
        // GCash specific fields
        @JsonProperty("livemode")
        private Boolean livemode;
        @JsonProperty("created_at")
        private Long createdAt;
        @JsonProperty("updated_at")
        private Long updatedAt;
    }
    
    @Data
    public static class Billing {
        private String name;
        private String email;
        private String phone;
        private Address address;
    }
    
    @Data
    public static class Address {
        private String line1;
        private String line2;
        private String city;
        private String state;
        @JsonProperty("postal_code")
        private String postalCode;
        private String country;
    }
}

// PaymentIntentRequest.java
package com.example.payment.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class PaymentIntentRequest {
    @JsonProperty("data")
    private IntentData data;
    
    @Data
    @Builder
    public static class IntentData {
        private IntentAttributes attributes;
    }
    
    @Data
    @Builder
    public static class IntentAttributes {
        private Long amount;
        @JsonProperty("payment_method_allowed")
        private List<String> paymentMethodAllowed;
        @JsonProperty("payment_method_options")
        private PaymentMethodOptions paymentMethodOptions;
        private String currency;
        private String description;
        @JsonProperty("statement_descriptor")
        private String statementDescriptor;
    }
    
    @Data
    @Builder
    public static class PaymentMethodOptions {
        private CardOptions card;
    }
    
    @Data
    @Builder
    public static class CardOptions {
        @JsonProperty("request_three_d_secure")
        private String requestThreeDSecure;
    }
}

// PaymentIntentResponse.java
package com.example.payment.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class PaymentIntentResponse {
    @JsonProperty("data")
    private IntentData data;
    
    @Data
    public static class IntentData {
        private String id;
        private String type;
        private IntentAttributes attributes;
    }
    
    @Data
    public static class IntentAttributes {
        private Long amount;
        private String currency;
        private String description;
        private String status;
        @JsonProperty("client_key")
        private String clientKey;
        @JsonProperty("payment_method_allowed")
        private String[] paymentMethodAllowed;
    }
}

// AttachPaymentRequest.java
package com.example.payment.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AttachPaymentRequest {
    @JsonProperty("data")
    private AttachData data;
    
    @Data
    @Builder
    public static class AttachData {
        private AttachAttributes attributes;
    }
    
    @Data
    @Builder
    public static class AttachAttributes {
        @JsonProperty("payment_method")
        private String paymentMethod;
        @JsonProperty("client_key")
        private String clientKey;
        @JsonProperty("return_url")
        private String returnUrl;
    }
}

// PaymentResponse.java
package com.example.payment.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PaymentResponse {
    private String paymentId;
    private String status;
    private String checkoutUrl;
    private String message;
    private Long amount;
}
````

Now let's add better logging to see the full response:

**PayMongo Service** ∙ Version 5

````java
package com.example.payment.service;

import com.example.payment.config.PayMongoConfig;
import com.example.payment.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class PayMongoService {
    
    private final PayMongoConfig payMongoConfig;
    private final RestTemplate restTemplate;
    
    /**
     * Create GCash payment source
     * This is the main method for GCash payments
     */
    public PaymentResponse createGCashPayment(CreatePaymentRequest request) {
        try {
            // Validate secret key is loaded
            if (payMongoConfig.getSecretKey() == null || payMongoConfig.getSecretKey().isEmpty()) {
                throw new RuntimeException("PayMongo secret key is not configured");
            }
            
            // Convert amount to centavos (PayMongo uses smallest currency unit)
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            // Build redirect object properly
            Map<String, String> redirectUrls = new HashMap<>();
            redirectUrls.put("success", "http://localhost:8080/api/payments/success");
            redirectUrls.put("failed", "http://localhost:8080/api/payments/failed");
            
            // Build the request manually to ensure proper structure
            Map<String, Object> requestBody = new HashMap<>();
            Map<String, Object> data = new HashMap<>();
            Map<String, Object> attributes = new HashMap<>();
            
            attributes.put("amount", amountInCentavos);
            attributes.put("type", "gcash");
            attributes.put("currency", "PHP");
            attributes.put("redirect", redirectUrls);
            
            // Add billing details
            Map<String, String> billing = new HashMap<>();
            billing.put("name", request.getCustomerName());
            billing.put("email", request.getCustomerEmail());
            billing.put("phone", request.getCustomerPhone());
            attributes.put("billing", billing);
            
            data.put("attributes", attributes);
            requestBody.put("data", data);
            
            // Create HTTP headers with Basic Auth
            HttpHeaders headers = createHeaders();
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
            
            // Make API call to PayMongo
            String url = payMongoConfig.getBaseUrl() + "/sources";
            
            log.info("Calling PayMongo API: {}", url);
            log.debug("Request body: {}", requestBody);
            
            ResponseEntity<PaymentSourceResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                PaymentSourceResponse.class
            );
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                PaymentSourceResponse.SourceData responseData = response.getBody().getData();
                
                log.info("GCash payment source created: {}", responseData.getId());
                log.info("Full response: {}", response.getBody());
                log.info("Checkout URL: {}", responseData.getAttributes().getCheckoutUrl());
                log.info("Status: {}", responseData.getAttributes().getStatus());
                
                // The checkout URL might be in the redirect object for GCash
                String checkoutUrl = responseData.getAttributes().getCheckoutUrl();
                
                // If checkout_url is null, try to extract from redirect
                if (checkoutUrl == null && responseData.getAttributes().getRedirect() != null) {
                    log.info("Checkout URL is null, checking redirect object: {}", 
                        responseData.getAttributes().getRedirect());
                }
                
                return PaymentResponse.builder()
                    .paymentId(responseData.getId())
                    .status(responseData.getAttributes().getStatus())
                    .checkoutUrl(checkoutUrl)
                    .amount(responseData.getAttributes().getAmount())
                    .message("Payment source created successfully. Redirect user to checkout URL.")
                    .build();
            }
            
            throw new RuntimeException("Failed to create payment source");
            
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            log.error("PayMongo API error: Status={}, Response={}", 
                e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Payment creation failed: " + e.getResponseBodyAsString());
        } catch (Exception e) {
            log.error("Error creating GCash payment: {}", e.getMessage(), e);
            throw new RuntimeException("Payment creation failed: " + e.getMessage());
        }
    }
    
    /**
     * Retrieve payment source status
     */
    public PaymentSourceResponse getPaymentSource(String sourceId) {
        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<?> entity = new HttpEntity<>(headers);
            
            String url = payMongoConfig.getBaseUrl() + "/sources/" + sourceId;
            ResponseEntity<PaymentSourceResponse> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                entity,
                PaymentSourceResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            log.error("Error retrieving payment source: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to retrieve payment source: " + e.getMessage());
        }
    }
    
    /**
     * Create payment intent (alternative method)
     */
    public PaymentIntentResponse createPaymentIntent(CreatePaymentRequest request) {
        try {
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            PaymentIntentRequest intentRequest = PaymentIntentRequest.builder()
                .data(PaymentIntentRequest.IntentData.builder()
                    .attributes(PaymentIntentRequest.IntentAttributes.builder()
                        .amount(amountInCentavos)
                        .paymentMethodAllowed(Collections.singletonList("gcash"))
                        .currency("PHP")
                        .description(request.getDescription())
                        .build())
                    .build())
                .build();
            
            HttpHeaders headers = createHeaders();
            HttpEntity<PaymentIntentRequest> entity = new HttpEntity<>(intentRequest, headers);
            
            String url = payMongoConfig.getBaseUrl() + "/payment_intents";
            ResponseEntity<PaymentIntentResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                PaymentIntentResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            log.error("Error creating payment intent: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create payment intent: " + e.getMessage());
        }
    }
    
    /**
     * Create HTTP headers with Basic Authentication
     */
    private HttpHeaders createHeaders() {
        // PayMongo requires: Base64(secret_key:) - note the colon at the end
        String auth = payMongoConfig.getSecretKey() + ":";
        String encodedAuth = Base64.getEncoder()
            .encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        String authHeader = "Basic " + encodedAuth;
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", authHeader);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        
        // Log for debugging (remove in production)
        log.debug("Auth header created for key: {}...", 
            payMongoConfig.getSecretKey().substring(0, 10));
        
        return headers;
    }
    
    /**
     * Verify webhook signature (for production use)
     */
    public boolean verifyWebhookSignature(String payload, String signature) {
        // Implement webhook signature verification
        // This is important for production to ensure webhooks are from PayMongo
        return true; // Placeholder
    }
}
````

## Alternative: Using Payment Method Instead of Source

PayMongo has updated their API. For GCash, you might need to use **Payment Method** instead of **Payment Source**. Let me add this method:

**PayMongo Service** ∙ Version 6

````java
package com.example.payment.service;

import com.example.payment.config.PayMongoConfig;
import com.example.payment.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class PayMongoService {
    
    private final PayMongoConfig payMongoConfig;
    private final RestTemplate restTemplate;
    
    /**
     * Create GCash payment source
     * This is the main method for GCash payments
     */
    public PaymentResponse createGCashPayment(CreatePaymentRequest request) {
        try {
            // Validate secret key is loaded
            if (payMongoConfig.getSecretKey() == null || payMongoConfig.getSecretKey().isEmpty()) {
                throw new RuntimeException("PayMongo secret key is not configured");
            }
            
            // Convert amount to centavos (PayMongo uses smallest currency unit)
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            // Build redirect object properly
            Map<String, String> redirectUrls = new HashMap<>();
            redirectUrls.put("success", "http://localhost:8080/api/payments/success");
            redirectUrls.put("failed", "http://localhost:8080/api/payments/failed");
            
            // Build the request manually to ensure proper structure
            Map<String, Object> requestBody = new HashMap<>();
            Map<String, Object> data = new HashMap<>();
            Map<String, Object> attributes = new HashMap<>();
            
            attributes.put("amount", amountInCentavos);
            attributes.put("type", "gcash");
            attributes.put("currency", "PHP");
            attributes.put("redirect", redirectUrls);
            
            // Add billing details
            Map<String, String> billing = new HashMap<>();
            billing.put("name", request.getCustomerName());
            billing.put("email", request.getCustomerEmail());
            billing.put("phone", request.getCustomerPhone());
            attributes.put("billing", billing);
            
            data.put("attributes", attributes);
            requestBody.put("data", data);
            
            // Create HTTP headers with Basic Auth
            HttpHeaders headers = createHeaders();
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
            
            // Make API call to PayMongo
            String url = payMongoConfig.getBaseUrl() + "/sources";
            
            log.info("Calling PayMongo API: {}", url);
            log.debug("Request body: {}", requestBody);
            
            ResponseEntity<PaymentSourceResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                PaymentSourceResponse.class
            );
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                PaymentSourceResponse.SourceData responseData = response.getBody().getData();
                
                log.info("GCash payment source created: {}", responseData.getId());
                log.info("Full response: {}", response.getBody());
                log.info("Checkout URL: {}", responseData.getAttributes().getCheckoutUrl());
                log.info("Status: {}", responseData.getAttributes().getStatus());
                
                // The checkout URL might be in the redirect object for GCash
                String checkoutUrl = responseData.getAttributes().getCheckoutUrl();
                
                // If checkout_url is null, try to extract from redirect
                if (checkoutUrl == null && responseData.getAttributes().getRedirect() != null) {
                    log.info("Checkout URL is null, checking redirect object: {}", 
                        responseData.getAttributes().getRedirect());
                }
                
                return PaymentResponse.builder()
                    .paymentId(responseData.getId())
                    .status(responseData.getAttributes().getStatus())
                    .checkoutUrl(checkoutUrl)
                    .amount(responseData.getAttributes().getAmount())
                    .message("Payment source created successfully. Redirect user to checkout URL.")
                    .build();
            }
            
            throw new RuntimeException("Failed to create payment source");
            
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            log.error("PayMongo API error: Status={}, Response={}", 
                e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Payment creation failed: " + e.getResponseBodyAsString());
        } catch (Exception e) {
            log.error("Error creating GCash payment: {}", e.getMessage(), e);
            throw new RuntimeException("Payment creation failed: " + e.getMessage());
        }
    }
    
    /**
     * Retrieve payment source status
     */
    public PaymentSourceResponse getPaymentSource(String sourceId) {
        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<?> entity = new HttpEntity<>(headers);
            
            String url = payMongoConfig.getBaseUrl() + "/sources/" + sourceId;
            ResponseEntity<PaymentSourceResponse> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                entity,
                PaymentSourceResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            log.error("Error retrieving payment source: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to retrieve payment source: " + e.getMessage());
        }
    }
    
    /**
     * Create payment intent (alternative method)
     */
    public PaymentIntentResponse createPaymentIntent(CreatePaymentRequest request) {
        try {
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            PaymentIntentRequest intentRequest = PaymentIntentRequest.builder()
                .data(PaymentIntentRequest.IntentData.builder()
                    .attributes(PaymentIntentRequest.IntentAttributes.builder()
                        .amount(amountInCentavos)
                        .paymentMethodAllowed(Collections.singletonList("gcash"))
                        .currency("PHP")
                        .description(request.getDescription())
                        .build())
                    .build())
                .build();
            
            HttpHeaders headers = createHeaders();
            HttpEntity<PaymentIntentRequest> entity = new HttpEntity<>(intentRequest, headers);
            
            String url = payMongoConfig.getBaseUrl() + "/payment_intents";
            ResponseEntity<PaymentIntentResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                entity,
                PaymentIntentResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            log.error("Error creating payment intent: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create payment intent: " + e.getMessage());
        }
    }
    
    /**
     * Create HTTP headers with Basic Authentication
     */
    private HttpHeaders createHeaders() {
        // PayMongo requires: Base64(secret_key:) - note the colon at the end
        String auth = payMongoConfig.getSecretKey() + ":";
        String encodedAuth = Base64.getEncoder()
            .encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        String authHeader = "Basic " + encodedAuth;
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", authHeader);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        
        // Log for debugging (remove in production)
        log.debug("Auth header created for key: {}...", 
            payMongoConfig.getSecretKey().substring(0, 10));
        
        return headers;
    }
    
    /**
     * Create GCash payment using Payment Method (Recommended approach)
     */
    public PaymentResponse createGCashPaymentV2(CreatePaymentRequest request) {
        try {
            // Validate secret key
            if (payMongoConfig.getSecretKey() == null || payMongoConfig.getSecretKey().isEmpty()) {
                throw new RuntimeException("PayMongo secret key is not configured");
            }
            
            Long amountInCentavos = request.getAmount()
                .multiply(new java.math.BigDecimal("100"))
                .longValue();
            
            // Step 1: Create Payment Intent
            Map<String, Object> intentRequest = new HashMap<>();
            Map<String, Object> intentData = new HashMap<>();
            Map<String, Object> intentAttributes = new HashMap<>();
            
            intentAttributes.put("amount", amountInCentavos);
            intentAttributes.put("payment_method_allowed", Collections.singletonList("gcash"));
            intentAttributes.put("currency", "PHP");
            intentAttributes.put("description", request.getDescription());
            
            intentData.put("attributes", intentAttributes);
            intentRequest.put("data", intentData);
            
            HttpHeaders headers = createHeaders();
            HttpEntity<Map<String, Object>> intentEntity = new HttpEntity<>(intentRequest, headers);
            
            String intentUrl = payMongoConfig.getBaseUrl() + "/payment_intents";
            log.info("Creating payment intent: {}", intentUrl);
            
            ResponseEntity<Map> intentResponse = restTemplate.exchange(
                intentUrl,
                HttpMethod.POST,
                intentEntity,
                Map.class
            );
            
            if (intentResponse.getStatusCode() != HttpStatus.OK) {
                throw new RuntimeException("Failed to create payment intent");
            }
            
            Map<String, Object> intentData2 = (Map<String, Object>) intentResponse.getBody().get("data");
            String paymentIntentId = (String) intentData2.get("id");
            Map<String, Object> intentAttrs = (Map<String, Object>) intentData2.get("attributes");
            String clientKey = (String) intentAttrs.get("client_key");
            
            log.info("Payment intent created: {}", paymentIntentId);
            
            // Step 2: Create Payment Method for GCash
            Map<String, Object> methodRequest = new HashMap<>();
            Map<String, Object> methodData = new HashMap<>();
            Map<String, Object> methodAttributes = new HashMap<>();
            Map<String, Object> billingDetails = new HashMap<>();
            
            billingDetails.put("name", request.getCustomerName());
            billingDetails.put("email", request.getCustomerEmail());
            billingDetails.put("phone", request.getCustomerPhone());
            
            methodAttributes.put("type", "gcash");
            methodAttributes.put("billing", billingDetails);
            
            methodData.put("attributes", methodAttributes);
            methodRequest.put("data", methodData);
            
            HttpEntity<Map<String, Object>> methodEntity = new HttpEntity<>(methodRequest, headers);
            
            String methodUrl = payMongoConfig.getBaseUrl() + "/payment_methods";
            log.info("Creating payment method: {}", methodUrl);
            
            ResponseEntity<Map> methodResponse = restTemplate.exchange(
                methodUrl,
                HttpMethod.POST,
                methodEntity,
                Map.class
            );
            
            Map<String, Object> methodData2 = (Map<String, Object>) methodResponse.getBody().get("data");
            String paymentMethodId = (String) methodData2.get("id");
            
            log.info("Payment method created: {}", paymentMethodId);
            
            // Step 3: Attach Payment Method to Payment Intent
            Map<String, Object> attachRequest = new HashMap<>();
            Map<String, Object> attachData = new HashMap<>();
            Map<String, Object> attachAttributes = new HashMap<>();
            
            attachAttributes.put("payment_method", paymentMethodId);
            attachAttributes.put("client_key", clientKey);
            attachAttributes.put("return_url", "http://localhost:8080/api/payments/success");
            
            attachData.put("attributes", attachAttributes);
            attachRequest.put("data", attachData);
            
            HttpEntity<Map<String, Object>> attachEntity = new HttpEntity<>(attachRequest, headers);
            
            String attachUrl = payMongoConfig.getBaseUrl() + "/payment_intents/" + paymentIntentId + "/attach";
            log.info("Attaching payment method: {}", attachUrl);
            
            ResponseEntity<Map> attachResponse = restTemplate.exchange(
                attachUrl,
                HttpMethod.POST,
                attachEntity,
                Map.class
            );
            
            Map<String, Object> attachData2 = (Map<String, Object>) attachResponse.getBody().get("data");
            Map<String, Object> attachAttrs = (Map<String, Object>) attachData2.get("attributes");
            String status = (String) attachAttrs.get("status");
            
            // Get the next action URL (checkout URL for GCash)
            Map<String, Object> nextAction = (Map<String, Object>) attachAttrs.get("next_action");
            String checkoutUrl = null;
            
            if (nextAction != null) {
                Map<String, Object> redirect = (Map<String, Object>) nextAction.get("redirect");
                if (redirect != null) {
                    checkoutUrl = (String) redirect.get("url");
                }
            }
            
            log.info("Payment attached. Status: {}, Checkout URL: {}", status, checkoutUrl);
            
            return PaymentResponse.builder()
                .paymentId(paymentIntentId)
                .status(status)
                .checkoutUrl(checkoutUrl)
                .amount(amountInCentavos)
                .message("Payment created successfully. Redirect user to checkout URL.")
                .build();
            
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            log.error("PayMongo API error: Status={}, Response={}", 
                e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Payment creation failed: " + e.getResponseBodyAsString());
        } catch (Exception e) {
            log.error("Error creating GCash payment: {}", e.getMessage(), e);
            throw new RuntimeException("Payment creation failed: " + e.getMessage());
        }
    }
    
    /**
     * Verify webhook signature (for production use)
     */
    public boolean verifyWebhookSignature(String payload, String signature) {
        // Implement webhook signature verification
        // This is important for production to ensure webhooks are from PayMongo
        return true; // Placeholder
    }
}
````

Now add a new endpoint to test the V2 method:

**Payment Controller** ∙ Version 2

````java
package com.example.payment.controller;

import com.example.payment.dto.CreatePaymentRequest;
import com.example.payment.dto.PaymentResponse;
import com.example.payment.dto.PaymentSourceResponse;
import com.example.payment.service.PayMongoService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.validation.Valid;

@RestController
@RequestMapping("/api/payments")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "*") // Configure properly for production
public class PaymentController {
    
    private final PayMongoService payMongoService;
    
    /**
     * Create GCash payment
     * POST /api/payments/gcash
     */
    @PostMapping("/gcash")
    public ResponseEntity<PaymentResponse> createGCashPayment(
            @Valid @RequestBody CreatePaymentRequest request) {
        try {
            log.info("Creating GCash payment for amount: {}", request.getAmount());
            PaymentResponse response = payMongoService.createGCashPayment(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error creating payment: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(PaymentResponse.builder()
                    .status("failed")
                    .message("Payment creation failed: " + e.getMessage())
                    .build());
        }
    }
    
    /**
     * Create GCash payment using Payment Method API (V2 - Recommended)
     * POST /api/payments/gcash/v2
     */
    @PostMapping("/gcash/v2")
    public ResponseEntity<PaymentResponse> createGCashPaymentV2(
            @Valid @RequestBody CreatePaymentRequest request) {
        try {
            log.info("Creating GCash payment V2 for amount: {}", request.getAmount());
            PaymentResponse response = payMongoService.createGCashPaymentV2(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error creating payment V2: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(PaymentResponse.builder()
                    .status("failed")
                    .message("Payment creation failed: " + e.getMessage())
                    .build());
        }
    }
    
    /**
     * Check payment status
     * GET /api/payments/status/{sourceId}
     */
    @GetMapping("/status/{sourceId}")
    public ResponseEntity<PaymentSourceResponse> getPaymentStatus(
            @PathVariable String sourceId) {
        try {
            log.info("Checking payment status for source: {}", sourceId);
            PaymentSourceResponse response = payMongoService.getPaymentSource(sourceId);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error retrieving payment status: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * Webhook endpoint for PayMongo events
     * POST /api/payments/webhook
     */
    @PostMapping("/webhook")
    public ResponseEntity<String> handleWebhook(
            @RequestBody String payload,
            @RequestHeader("PayMongo-Signature") String signature) {
        try {
            log.info("Received webhook event");
            
            // Verify webhook signature
            if (!payMongoService.verifyWebhookSignature(payload, signature)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid signature");
            }
            
            // Parse and process the webhook event
            // Update your database based on payment status
            log.info("Webhook payload: {}", payload);
            
            // Common events:
            // - source.chargeable: Payment source is ready to be charged
            // - payment.paid: Payment was successful
            // - payment.failed: Payment failed
            
            return ResponseEntity.ok("Webhook processed");
        } catch (Exception e) {
            log.error("Error processing webhook: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error processing webhook");
        }
    }
    
    /**
     * Success callback endpoint
     * GET /api/payments/success
     */
    @GetMapping("/success")
    public ResponseEntity<String> paymentSuccess(@RequestParam(required = false) String sourceId) {
        log.info("Payment successful for source: {}", sourceId);
        // Redirect to success page or return success response
        return ResponseEntity.ok("Payment successful!");
    }
    
    /**
     * Failed callback endpoint
     * GET /api/payments/failed
     */
    @GetMapping("/failed")
    public ResponseEntity<String> paymentFailed(@RequestParam(required = false) String sourceId) {
        log.info("Payment failed for source: {}", sourceId);
        // Redirect to failed page or return error response
        return ResponseEntity.status(HttpStatus.PAYMENT_REQUIRED).body("Payment failed!");
    }
}
````

## Now Test Both Methods:

### **Method 1: Original Source API**
```bash
curl -X POST http://localhost:8080/api/payments/gcash \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 100.00,
    "description": "Test Payment",
    "customerEmail": "juan@example.com",
    "customerName": "Juan Dela Cruz",
    "customerPhone": "+639171234567"
  }'
```

### **Method 2: New Payment Method API (Recommended)**
```bash
curl -X POST http://localhost:8080/api/payments/gcash/v2 \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 100.00,
    "description": "Test GCash Payment",
    "customerEmail": "juan@example.com",
    "customerName": "Juan Dela Cruz",
    "customerPhone": "+639171234567"
  }'
```

## Why checkout_url might be null:

1. **Source is pending** - GCash sources need to be "chargeable" before getting a checkout URL
2. **API version difference** - Older sources API vs newer payment methods API
3. **Test mode behavior** - Test mode might not generate checkout URLs immediately

## Next Steps:

1. **Try the V2 endpoint** (`/api/payments/gcash/v2`) - This uses the newer Payment Method flow
2. **Check your logs** - Look for the full response to see what fields are available
3. **Poll for status** - The checkout URL might appear when status changes to "chargeable"

Let me know which method works better for you! The V2 method should give you a proper `checkoutUrl` in the `next_action.redirect.url` field. 🚀





---
Powered by [Claude Exporter](https://www.claudexporter.com)