# TypoSentinel Enterprise Features

This directory contains examples and documentation for TypoSentinel's enterprise security features, including Role-Based Access Control (RBAC), policy management, and advanced security enforcement.

## Features Overview

### 1. Role-Based Access Control (RBAC)
- **Granular Permissions**: Fine-grained permission system for different operations
- **Role Inheritance**: Roles can inherit permissions from other roles
- **Dynamic Policy Evaluation**: Real-time permission checking with context-aware policies
- **User Management**: Comprehensive user and role management APIs

### 2. Policy Management
- **Security Policies**: Define and enforce custom security policies
- **Policy Templates**: Pre-built templates for common enterprise scenarios
- **Policy Evaluation**: Real-time policy evaluation with detailed results
- **Conditional Logic**: Support for complex conditions and rules

### 3. Policy Enforcement
- **Automated Enforcement**: Automatic policy enforcement with configurable actions
- **Approval Workflows**: Multi-stage approval processes for policy violations
- **Notification System**: Configurable notifications for policy events
- **Audit Logging**: Comprehensive audit trails for compliance

### 4. Enterprise Integration
- **API-First Design**: RESTful APIs for all enterprise features
- **Middleware Integration**: Easy integration with existing authentication systems
- **Scalable Architecture**: Designed for enterprise-scale deployments

## Quick Start

### Running the Enterprise Example

```bash
cd /opt/Typosentinel/examples/enterprise
go run main.go
```

This will start a TypoSentinel server with enterprise features enabled on `http://localhost:8080`.

### Available API Endpoints

Once the server is running, you can access the following enterprise endpoints:

#### Policy Management
- `GET /api/v1/enterprise/policies` - List all policies
- `POST /api/v1/enterprise/policies` - Create a new policy
- `GET /api/v1/enterprise/policies/{id}` - Get specific policy
- `PUT /api/v1/enterprise/policies/{id}` - Update policy
- `DELETE /api/v1/enterprise/policies/{id}` - Delete policy
- `POST /api/v1/enterprise/policies/{id}/evaluate` - Evaluate policy

#### Policy Templates
- `GET /api/v1/enterprise/policy-templates` - List policy templates
- `GET /api/v1/enterprise/policy-templates/{id}` - Get specific template
- `POST /api/v1/enterprise/policy-templates/{id}/create-policy` - Create policy from template

#### RBAC Management
- `GET /api/v1/enterprise/rbac/roles` - List all roles
- `POST /api/v1/enterprise/rbac/roles` - Create new role
- `GET /api/v1/enterprise/rbac/roles/{id}` - Get specific role
- `PUT /api/v1/enterprise/rbac/roles/{id}` - Update role
- `DELETE /api/v1/enterprise/rbac/roles/{id}` - Delete role
- `GET /api/v1/enterprise/rbac/users/{userId}/permissions` - Get user permissions
- `POST /api/v1/enterprise/rbac/users/{userId}/check-permission` - Check user permission

#### Policy Enforcement
- `GET /api/v1/enterprise/enforcement/settings` - Get enforcement settings
- `PUT /api/v1/enterprise/enforcement/settings` - Update enforcement settings
- `POST /api/v1/enterprise/enforcement/evaluate` - Evaluate and enforce policies

#### Approval Workflows
- `GET /api/v1/enterprise/approvals/violations` - List policy violations
- `GET /api/v1/enterprise/approvals/violations/{id}` - Get specific violation
- `POST /api/v1/enterprise/approvals/violations/{id}/approve` - Approve violation
- `POST /api/v1/enterprise/approvals/violations/{id}/reject` - Reject violation

## Example Usage

### Creating a Security Policy

```bash
curl -X POST http://localhost:8080/api/v1/enterprise/policies \
  -H "Content-Type: application/json" \
  -d '{
    "id": "high-risk-package-policy",
    "name": "High Risk Package Policy",
    "description": "Blocks packages with high security risk",
    "enabled": true,
    "conditions": [
      {
        "field": "risk_score",
        "operator": "gt",
        "value": "0.8"
      }
    ],
    "actions": [
      {
        "type": "block",
        "message": "Package blocked due to high security risk"
      }
    ]
  }'
```

### Creating a Role

```bash
curl -X POST http://localhost:8080/api/v1/enterprise/rbac/roles \
  -H "Content-Type: application/json" \
  -d '{
    "name": "security_manager",
    "description": "Security manager with policy management access",
    "permissions": [
      "policies:read",
      "policies:create",
      "policies:update",
      "enforcement:read",
      "enforcement:update"
    ]
  }'
```

### Evaluating Policies

```bash
curl -X POST http://localhost:8080/api/v1/enterprise/enforcement/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "scan_result": {
      "packages": [
        {
          "name": "suspicious-package",
          "version": "1.0.0",
          "threats": [
            {
              "type": "typosquatting",
              "severity": "high",
              "confidence": 0.95
            }
          ]
        }
      ]
    },
    "user": {
      "id": "user123",
      "roles": ["developer"]
    },
    "context": {
      "environment": "production",
      "project": "critical-app"
    }
  }'
```

## Default Roles and Permissions

The example includes two default roles:

### Administrator (`admin`)
- Full access to all enterprise features
- Can manage policies, roles, enforcement settings, and approvals

### Security Analyst (`security_analyst`)
- Read-only access to policies, roles, enforcement settings, and approvals
- Cannot modify configurations but can view all security information

## Permissions Reference

### Policy Permissions
- `policies:read` - View policies and templates
- `policies:create` - Create new policies
- `policies:update` - Modify existing policies
- `policies:delete` - Delete policies
- `policies:evaluate` - Evaluate policies

### RBAC Permissions
- `rbac:read` - View roles and user permissions
- `rbac:create` - Create new roles
- `rbac:update` - Modify existing roles
- `rbac:delete` - Delete roles

### Enforcement Permissions
- `enforcement:read` - View enforcement settings
- `enforcement:update` - Modify enforcement settings
- `enforcement:evaluate` - Trigger policy evaluation

### Approval Permissions
- `approvals:read` - View policy violations and approvals
- `approvals:approve` - Approve or reject policy violations

## Integration with Existing Systems

The enterprise features are designed to integrate seamlessly with existing authentication and authorization systems:

1. **Authentication**: The RBAC system can work with any authentication provider
2. **Authorization**: Fine-grained permissions can be mapped to existing role systems
3. **Audit**: All actions are logged for compliance and security monitoring
4. **APIs**: RESTful APIs allow integration with existing enterprise tools

## Production Deployment

For production deployments, consider:

1. **Database Backend**: Configure persistent storage for policies and roles
2. **Authentication Integration**: Connect with your existing identity provider
3. **Monitoring**: Set up monitoring for policy violations and system health
4. **Backup**: Regular backups of policy and role configurations
5. **High Availability**: Deploy in a clustered configuration for reliability

## Support

For questions about enterprise features, please refer to the main TypoSentinel documentation or contact the development team.