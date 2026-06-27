package breakglass

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto"
)

var (
	ErrAdminDisabled           = errors.New("breakglass admin: disabled")
	ErrAdminInvalidCredentials = errors.New("breakglass admin: invalid credentials")
	ErrAdminLocked             = errors.New("breakglass admin: locked")
)

type AdminConfig struct {
	Enabled     bool
	TenantID    string
	Sessions    *auth.SessionIssuer
	Params      crypto.Argon2idParams
	MaxFailures int
	Lockout     time.Duration
	Now         func() time.Time
	Audit       auditsink.Auditor
}

type AdminService struct {
	cfg   AdminConfig
	mu    sync.Mutex
	creds map[string]adminCredential
}

type adminCredential struct {
	actorID     string
	hash        []byte
	failures    int
	lockedUntil time.Time
}

func NewAdminService(cfg AdminConfig) *AdminService {
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = 5
	}
	if cfg.Lockout <= 0 {
		cfg.Lockout = 15 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &AdminService{cfg: cfg, creds: map[string]adminCredential{}}
}

func (s *AdminService) Enabled() bool { return s != nil && s.cfg.Enabled }

func (s *AdminService) SessionIssuer() *auth.SessionIssuer {
	if s == nil {
		return nil
	}
	return s.cfg.Sessions
}

func (s *AdminService) SetPassword(actorID string, password []byte) error {
	if !s.Enabled() {
		return ErrAdminDisabled
	}
	hash, err := crypto.HashArgon2id(password, s.cfg.Params)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[actorID] = adminCredential{actorID: actorID, hash: hash}
	return nil
}

func (s *AdminService) Authenticate(ctx context.Context, actorID string, password []byte, _, _ string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !s.Enabled() {
		if err := s.audit(ctx, s.tenantID(), actorID, "disabled"); err != nil {
			return "", err
		}
		return "", ErrAdminDisabled
	}
	now := s.cfg.Now()
	tenantID := s.tenantID()
	s.mu.Lock()
	cred, ok := s.creds[actorID]
	s.mu.Unlock()
	if !ok {
		if err := s.audit(ctx, tenantID, actorID, "invalid_credentials"); err != nil {
			return "", err
		}
		return "", ErrAdminInvalidCredentials
	}
	if !cred.lockedUntil.IsZero() && cred.lockedUntil.After(now) {
		if err := s.audit(ctx, tenantID, actorID, "locked"); err != nil {
			return "", err
		}
		return "", ErrAdminLocked
	}
	ok, err := crypto.VerifyArgon2id(cred.hash, password)
	if err != nil || !ok {
		s.mu.Lock()
		cred = s.creds[actorID]
		cred.failures++
		ret := ErrAdminInvalidCredentials
		if cred.failures >= s.cfg.MaxFailures {
			cred.lockedUntil = now.Add(s.cfg.Lockout)
			ret = ErrAdminLocked
		}
		s.creds[actorID] = cred
		s.mu.Unlock()
		outcome := "invalid_credentials"
		if errors.Is(ret, ErrAdminLocked) {
			outcome = "locked"
		}
		if err := s.audit(ctx, tenantID, actorID, outcome); err != nil {
			return "", err
		}
		return "", ret
	}
	s.mu.Lock()
	cred = s.creds[actorID]
	cred.failures = 0
	cred.lockedUntil = time.Time{}
	s.creds[actorID] = cred
	s.mu.Unlock()
	if s.cfg.Sessions == nil {
		return "", errors.New("breakglass admin: session issuer is required")
	}
	if err := s.audit(ctx, tenantID, actorID, "success"); err != nil {
		return "", err
	}
	return s.cfg.Sessions.Issue(actorID, tenantID, "", []string{"admin"})
}

func (s *AdminService) tenantID() string {
	if s == nil || s.cfg.TenantID == "" {
		return "default"
	}
	return s.cfg.TenantID
}

func (s *AdminService) audit(ctx context.Context, tenantID, actorID, outcome string) error {
	if s == nil || s.cfg.Audit == nil {
		return nil
	}
	data, err := json.Marshal(struct {
		ActorID string `json:"actor_id"`
		Outcome string `json:"outcome"`
	}{ActorID: actorID, Outcome: outcome})
	if err != nil {
		return err
	}
	return s.cfg.Audit.Audit(ctx, "breakglass.admin_login", tenantID, data)
}
