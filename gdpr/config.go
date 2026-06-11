package gdpr

import (
	"time"

	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration is the go-gdpr-audit library configuration, bound as a
// sub-configuration of a consuming service. The Endpoint/Audience/Scope/Timeout
// describe the access-audit target the service's Poster talks to; the
// Outbox*/MaxRetries/RetryBackoff knobs tune the local resilience buffer the
// client owns.
type Configuration struct {
	// Endpoint is the access-audit service base URL (env ACCESS_AUDIT_URL).
	Endpoint string `mapstructure:"endpoint" validate:"required,url"`
	// Audience is the access-audit service `aud` for the outbound service token
	// (env ACCESS_AUDIT_AUDIENCE), e.g. "svc:access-audit".
	Audience string `mapstructure:"audience" validate:"required"`
	// Scope is the OAuth scope requested for the write call (env
	// ACCESS_AUDIT_SCOPE), e.g. "access-audit:write".
	Scope string `mapstructure:"scope"`
	// Timeout bounds a single synchronous post (env ACCESS_AUDIT_TIMEOUT).
	Timeout time.Duration `mapstructure:"timeout" validate:"required,gt=0"`

	// OutboxCapacity is the maximum number of records the local fallback buffer
	// holds (env ACCESS_AUDIT_OUTBOX_CAPACITY).
	OutboxCapacity int `mapstructure:"outbox_capacity" validate:"required,gt=0"`
	// MaxRetries bounds the background drainer's per-record retry attempts before
	// it gives up on a buffered record (env ACCESS_AUDIT_MAX_RETRIES).
	MaxRetries int `mapstructure:"max_retries" validate:"gte=0"`
	// RetryBackoff is the initial backoff between drain retries; it doubles up to
	// an internal cap, with jitter (env ACCESS_AUDIT_RETRY_BACKOFF).
	RetryBackoff time.Duration `mapstructure:"retry_backoff" validate:"required,gt=0"`

	// BreakerThreshold is the number of consecutive synchronous post failures
	// after which the client trips a circuit breaker: routine records then skip
	// the synchronous attempt and buffer immediately, protecting interactive
	// latency against a slow-but-up access-audit. 0 disables the breaker.
	// Viper-bound services default to DefaultBreakerThreshold; a Client
	// constructed programmatically must opt in explicitly
	// (env ACCESS_AUDIT_BREAKER_THRESHOLD).
	BreakerThreshold int `mapstructure:"breaker_threshold" validate:"gte=0"`
	// BreakerCooldown is how long the breaker stays open before the next call
	// probes the sink again (half-open) (env ACCESS_AUDIT_BREAKER_COOLDOWN).
	BreakerCooldown time.Duration `mapstructure:"breaker_cooldown" validate:"gte=0"`
}

// Default configuration values.
const (
	DefaultTimeout          = 5 * time.Second
	DefaultOutboxCapacity   = 1024
	DefaultMaxRetries       = 5
	DefaultRetryBackoff     = 500 * time.Millisecond
	DefaultBreakerThreshold = 3
	DefaultBreakerCooldown  = 10 * time.Second
)

// Bind registers defaults and environment-variable bindings under prefix.
func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	v.SetDefault(prefix+".timeout", DefaultTimeout)
	v.SetDefault(prefix+".outbox_capacity", DefaultOutboxCapacity)
	v.SetDefault(prefix+".max_retries", DefaultMaxRetries)
	v.SetDefault(prefix+".retry_backoff", DefaultRetryBackoff)
	v.SetDefault(prefix+".breaker_threshold", DefaultBreakerThreshold)
	v.SetDefault(prefix+".breaker_cooldown", DefaultBreakerCooldown)

	_ = v.BindEnv(prefix+".endpoint", "ACCESS_AUDIT_URL")
	_ = v.BindEnv(prefix+".audience", "ACCESS_AUDIT_AUDIENCE")
	_ = v.BindEnv(prefix+".scope", "ACCESS_AUDIT_SCOPE")
	_ = v.BindEnv(prefix+".timeout", "ACCESS_AUDIT_TIMEOUT")
	_ = v.BindEnv(prefix+".outbox_capacity", "ACCESS_AUDIT_OUTBOX_CAPACITY")
	_ = v.BindEnv(prefix+".max_retries", "ACCESS_AUDIT_MAX_RETRIES")
	_ = v.BindEnv(prefix+".retry_backoff", "ACCESS_AUDIT_RETRY_BACKOFF")
	_ = v.BindEnv(prefix+".breaker_threshold", "ACCESS_AUDIT_BREAKER_THRESHOLD")
	_ = v.BindEnv(prefix+".breaker_cooldown", "ACCESS_AUDIT_BREAKER_COOLDOWN")
}

// Validate validates the configuration.
func (c *Configuration) Validate(valid *validation.Validate) error {
	return valid.Struct(c)
}

// setDefaults fills zero-valued resilience knobs so a Client constructed
// programmatically (without viper) still behaves sanely.
func (c *Configuration) setDefaults() {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}

	if c.OutboxCapacity <= 0 {
		c.OutboxCapacity = DefaultOutboxCapacity
	}

	if c.RetryBackoff <= 0 {
		c.RetryBackoff = DefaultRetryBackoff
	}

	// BreakerThreshold is deliberately NOT defaulted here: 0 disables the
	// breaker for programmatic construction; viper-bound services get
	// DefaultBreakerThreshold via Bind.
	if c.BreakerThreshold > 0 && c.BreakerCooldown <= 0 {
		c.BreakerCooldown = DefaultBreakerCooldown
	}
}
