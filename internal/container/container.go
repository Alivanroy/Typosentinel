// Package container provides dependency injection for Typosentinel
// This package implements a service container for managing dependencies and their lifecycle
package container

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/errors"
	"github.com/Alivanroy/Typosentinel/internal/interfaces"
)

// ServiceLifecycle represents the lifecycle of a service
type ServiceLifecycle string

const (
	// Singleton services are created once and reused
	LifecycleSingleton ServiceLifecycle = "singleton"
	// Transient services are created on each request
	LifecycleTransient ServiceLifecycle = "transient"
	// Scoped services are created once per scope (e.g., per request)
	LifecycleScoped ServiceLifecycle = "scoped"
)

// ServiceDefinition defines how a service should be created
type ServiceDefinition struct {
	Name         string
	Type         reflect.Type
	Factory      interface{}
	Lifecycle    ServiceLifecycle
	Dependencies []string
	Tags         []string
	Initializer  func(interface{}) error
	Finalizer    func(interface{}) error
}

// Container manages service dependencies and their lifecycle
type Container struct {
	mu           sync.RWMutex
	services     map[string]*ServiceDefinition
	singletons   map[string]interface{}
	scoped       map[string]map[string]interface{} // scope -> service -> instance
	logger       interfaces.Logger
	metrics      interfaces.Metrics
	initialized  bool
	shutdownCh   chan struct{}
	shutdownOnce sync.Once
}

// NewContainer creates a new dependency injection container
func NewContainer() *Container {
	return &Container{
		services:   make(map[string]*ServiceDefinition),
		singletons: make(map[string]interface{}),
		scoped:     make(map[string]map[string]interface{}),
		shutdownCh: make(chan struct{}),
	}
}

// SetLogger sets the logger for the container
func (c *Container) SetLogger(logger interfaces.Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logger = logger
}

// SetMetrics sets the metrics collector for the container
func (c *Container) SetMetrics(metrics interfaces.Metrics) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics = metrics
}

// Register registers a service with the container
func (c *Container) Register(name string, factory interface{}, lifecycle ServiceLifecycle) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.initialized {
		return errors.NewInternalError("cannot register services after container initialization")
	}

	// Validate factory function
	factoryType := reflect.TypeOf(factory)
	if factoryType.Kind() != reflect.Func {
		return errors.NewValidationError("factory must be a function")
	}

	if factoryType.NumOut() == 0 {
		return errors.NewValidationError("factory function must return at least one value")
	}

	// Get the return type (service type)
	serviceType := factoryType.Out(0)

	// Extract dependencies from factory parameters
	dependencies := make([]string, 0, factoryType.NumIn())
	for i := 0; i < factoryType.NumIn(); i++ {
		paramType := factoryType.In(i)
		// For interface types, use the interface name as dependency
		if paramType.Kind() == reflect.Interface {
			dependencies = append(dependencies, paramType.String())
		} else {
			// For concrete types, use the type name
			dependencies = append(dependencies, paramType.String())
		}
	}

	c.services[name] = &ServiceDefinition{
		Name:         name,
		Type:         serviceType,
		Factory:      factory,
		Lifecycle:    lifecycle,
		Dependencies: dependencies,
	}

	if c.logger != nil {
		c.logger.Info("Service registered",
			interfaces.String("service", name),
			interfaces.String("type", serviceType.String()),
			interfaces.String("lifecycle", string(lifecycle)),
			interfaces.Int("dependencies", len(dependencies)),
		)
	}

	return nil
}

// RegisterSingleton registers a singleton service
func (c *Container) RegisterSingleton(name string, factory interface{}) error {
	return c.Register(name, factory, LifecycleSingleton)
}

// RegisterTransient registers a transient service
func (c *Container) RegisterTransient(name string, factory interface{}) error {
	return c.Register(name, factory, LifecycleTransient)
}

// RegisterScoped registers a scoped service
func (c *Container) RegisterScoped(name string, factory interface{}) error {
	return c.Register(name, factory, LifecycleScoped)
}

// RegisterInstance registers a pre-created instance as a singleton
func (c *Container) RegisterInstance(name string, instance interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.initialized {
		return errors.NewInternalError("cannot register services after container initialization")
	}

	instanceType := reflect.TypeOf(instance)
	c.services[name] = &ServiceDefinition{
		Name:      name,
		Type:      instanceType,
		Lifecycle: LifecycleSingleton,
	}
	c.singletons[name] = instance

	if c.logger != nil {
		c.logger.Info("Instance registered",
			interfaces.String("service", name),
			interfaces.String("type", instanceType.String()),
		)
	}

	return nil
}

// AddInitializer adds an initializer function for a service
func (c *Container) AddInitializer(name string, initializer func(interface{}) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	service, exists := c.services[name]
	if !exists {
		return errors.NewNotFoundError("service", name)
	}

	service.Initializer = initializer
	return nil
}

// AddFinalizer adds a finalizer function for a service
func (c *Container) AddFinalizer(name string, finalizer func(interface{}) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	service, exists := c.services[name]
	if !exists {
		return errors.NewNotFoundError("service", name)
	}

	service.Finalizer = finalizer
	return nil
}

// AddTag adds a tag to a service
func (c *Container) AddTag(name string, tag string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	service, exists := c.services[name]
	if !exists {
		return errors.NewNotFoundError("service", name)
	}

	service.Tags = append(service.Tags, tag)
	return nil
}

// Initialize initializes the container and validates dependencies
func (c *Container) Initialize(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.initialized {
		return errors.NewInternalError("container already initialized")
	}

	// Validate dependency graph
	if err := c.validateDependencies(); err != nil {
		return errors.Wrap(err, errors.ErrCodeValidation, "dependency validation failed")
	}

	// Initialize singleton services
	for name, service := range c.services {
		if service.Lifecycle == LifecycleSingleton && c.singletons[name] == nil {
			instance, err := c.createInstance(ctx, name, "")
			if err != nil {
				return errors.Wrapf(err, errors.ErrCodeInternal, "failed to initialize singleton service '%s'", name)
			}
			c.singletons[name] = instance
		}
	}

	c.initialized = true

	if c.logger != nil {
		c.logger.Info("Container initialized",
			interfaces.Int("services", len(c.services)),
			interfaces.Int("singletons", len(c.singletons)),
		)
	}

	return nil
}

// Get retrieves a service instance
func (c *Container) Get(name string) (interface{}, error) {
	return c.GetScoped(name, "")
}

// GetScoped retrieves a service instance within a specific scope
func (c *Container) GetScoped(name string, scope string) (interface{}, error) {
	c.mu.RLock()
	service, exists := c.services[name]
	c.mu.RUnlock()

	if !exists {
		return nil, errors.NewNotFoundError("service", name)
	}

	start := time.Now()
	defer func() {
		if c.metrics != nil {
			c.metrics.RecordDuration("container.service_resolution", time.Since(start), interfaces.MetricTags{
				"service": name,
				"lifecycle": string(service.Lifecycle),
			})
		}
	}()

	switch service.Lifecycle {
	case LifecycleSingleton:
		c.mu.RLock()
		instance := c.singletons[name]
		c.mu.RUnlock()
		return instance, nil

	case LifecycleScoped:
		c.mu.Lock()
		if c.scoped[scope] == nil {
			c.scoped[scope] = make(map[string]interface{})
		}
		instance := c.scoped[scope][name]
		c.mu.Unlock()

		if instance == nil {
			var err error
			instance, err = c.createInstance(context.Background(), name, scope)
			if err != nil {
				return nil, err
			}
			c.mu.Lock()
			c.scoped[scope][name] = instance
			c.mu.Unlock()
		}
		return instance, nil

	case LifecycleTransient:
		return c.createInstance(context.Background(), name, scope)

	default:
		return nil, errors.NewInternalError(fmt.Sprintf("unknown lifecycle: %s", service.Lifecycle))
	}
}

// GetByType retrieves a service instance by its type
func (c *Container) GetByType(serviceType reflect.Type) (interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for name, service := range c.services {
		if service.Type == serviceType {
			c.mu.RUnlock()
			instance, err := c.Get(name)
			c.mu.RLock()
			return instance, err
		}
	}

	return nil, errors.NewNotFoundError("service type", serviceType.String())
}

// GetByTag retrieves all service instances with a specific tag
func (c *Container) GetByTag(tag string) ([]interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var instances []interface{}
	for name, service := range c.services {
		for _, serviceTag := range service.Tags {
			if serviceTag == tag {
				c.mu.RUnlock()
				instance, err := c.Get(name)
				c.mu.RLock()
				if err != nil {
					return nil, err
				}
				instances = append(instances, instance)
				break
			}
		}
	}

	return instances, nil
}

// ClearScope clears all scoped instances for a specific scope
func (c *Container) ClearScope(scope string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	scopedInstances := c.scoped[scope]
	if scopedInstances == nil {
		return nil
	}

	// Call finalizers for scoped instances
	for name, instance := range scopedInstances {
		if service := c.services[name]; service != nil && service.Finalizer != nil {
			if err := service.Finalizer(instance); err != nil && c.logger != nil {
				c.logger.Error("Failed to finalize scoped service", 
					interfaces.Error(err),
					interfaces.String("service", name),
					interfaces.String("scope", scope),
				)
			}
		}
	}

	delete(c.scoped, scope)

	if c.logger != nil {
		c.logger.Debug("Scope cleared", 
			interfaces.String("scope", scope),
			interfaces.Int("services", len(scopedInstances)),
		)
	}

	return nil
}

// Shutdown gracefully shuts down the container
func (c *Container) Shutdown(ctx context.Context) error {
	var shutdownErr error
	c.shutdownOnce.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		close(c.shutdownCh)

		// Finalize all singleton services
		for name, instance := range c.singletons {
			if service := c.services[name]; service != nil && service.Finalizer != nil {
				if err := service.Finalizer(instance); err != nil {
					if c.logger != nil {
					c.logger.Error("Failed to finalize singleton service", 
						interfaces.Error(err),
						interfaces.String("service", name),
					)
					}
					if shutdownErr == nil {
						shutdownErr = err
					}
				}
			}
		}

		// Clear all scoped instances
		for scope := range c.scoped {
			c.ClearScope(scope)
		}

		if c.logger != nil {
			c.logger.Info("Container shutdown completed")
		}
	})

	return shutdownErr
}

// IsShutdown returns true if the container has been shut down
func (c *Container) IsShutdown() bool {
	select {
	case <-c.shutdownCh:
		return true
	default:
		return false
	}
}

// ListServices returns a list of all registered services
func (c *Container) ListServices() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	services := make([]string, 0, len(c.services))
	for name := range c.services {
		services = append(services, name)
	}
	return services
}

// GetServiceInfo returns information about a service
func (c *Container) GetServiceInfo(name string) (*ServiceDefinition, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	service, exists := c.services[name]
	if !exists {
		return nil, errors.NewNotFoundError("service", name)
	}

	// Return a copy to prevent external modification
	return &ServiceDefinition{
		Name:         service.Name,
		Type:         service.Type,
		Lifecycle:    service.Lifecycle,
		Dependencies: append([]string(nil), service.Dependencies...),
		Tags:         append([]string(nil), service.Tags...),
	}, nil
}

// createInstance creates a new instance of a service
func (c *Container) createInstance(ctx context.Context, name string, scope string) (interface{}, error) {
	service := c.services[name]
	if service == nil {
		return nil, errors.NewNotFoundError("service", name)
	}

	// Resolve dependencies
	factoryValue := reflect.ValueOf(service.Factory)
	factoryType := factoryValue.Type()
	args := make([]reflect.Value, factoryType.NumIn())

	for i := 0; i < factoryType.NumIn(); i++ {
		paramType := factoryType.In(i)
		
		// Try to resolve dependency by type
		dep, err := c.resolveDependency(paramType, scope)
		if err != nil {
			return nil, errors.Wrapf(err, errors.ErrCodeInternal, "failed to resolve dependency %d for service '%s'", i, name)
		}
		args[i] = reflect.ValueOf(dep)
	}

	// Call factory function
	results := factoryValue.Call(args)
	if len(results) == 0 {
		return nil, errors.NewInternalError("factory function returned no values")
	}

	instance := results[0].Interface()

	// Check for error return
	if len(results) > 1 && !results[1].IsNil() {
		if err, ok := results[1].Interface().(error); ok {
			return nil, errors.Wrap(err, errors.ErrCodeInternal, "factory function returned error")
		}
	}

	// Call initializer if present
	if service.Initializer != nil {
		if err := service.Initializer(instance); err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeInternal, "service initialization failed")
		}
	}

	if c.metrics != nil {
		c.metrics.IncrementCounter("container.service_created", interfaces.MetricTags{
			"service": name,
			"lifecycle": string(service.Lifecycle),
		})
	}

	return instance, nil
}

// resolveDependency resolves a dependency by type
func (c *Container) resolveDependency(paramType reflect.Type, scope string) (interface{}, error) {
	// First try to find by exact type match
	for name, service := range c.services {
		if service.Type == paramType {
			return c.GetScoped(name, scope)
		}
	}

	// Then try to find by interface implementation
	if paramType.Kind() == reflect.Interface {
		for name, service := range c.services {
			if service.Type.Implements(paramType) {
				return c.GetScoped(name, scope)
			}
		}
	}

	return nil, errors.NewNotFoundError("dependency", paramType.String())
}

// validateDependencies validates the dependency graph for circular dependencies
func (c *Container) validateDependencies() error {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	for name := range c.services {
		if !visited[name] {
			if c.hasCyclicDependency(name, visited, recStack) {
				return errors.NewValidationError(fmt.Sprintf("circular dependency detected involving service '%s'", name))
			}
		}
	}

	return nil
}

// hasCyclicDependency checks for circular dependencies using DFS
func (c *Container) hasCyclicDependency(serviceName string, visited, recStack map[string]bool) bool {
	visited[serviceName] = true
	recStack[serviceName] = true

	service := c.services[serviceName]
	if service != nil {
		for _, dep := range service.Dependencies {
			// Find service by dependency name (simplified)
			for name := range c.services {
				if name == dep || c.services[name].Type.String() == dep {
					if !visited[name] {
						if c.hasCyclicDependency(name, visited, recStack) {
							return true
						}
					} else if recStack[name] {
						return true
					}
				}
			}
		}
	}

	recStack[serviceName] = false
	return false
}