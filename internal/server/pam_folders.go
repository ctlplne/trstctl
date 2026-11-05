// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func folderView(f store.PAMFolder, targets int) api.PAMFolder {
	return api.PAMFolder{Name: f.Name, TemplateID: f.TemplateID, Description: f.Description, Revision: f.Revision,
		SavedBy: f.SavedBy, SavedAt: f.SavedAt.UTC(), Targets: targets}
}

func (s *pamService) SavePAMFolder(ctx context.Context, tenantID, actor string, f api.PAMFolder) (api.PAMFolder, error) {
	f.Name, f.Description = strings.TrimSpace(f.Name), strings.TrimSpace(f.Description)
	if actor == "" || !pamTemplateName.MatchString(f.Name) || utf8.RuneCountInString(f.Description) > 500 {
		return api.PAMFolder{}, fmt.Errorf("%w: an author, a 1-64 character lowercase folder name and a description up to 500 characters are required", api.ErrPAMInvalid)
	}
	if f.TemplateID == "" {
		return api.PAMFolder{}, fmt.Errorf("%w: an access template is required for a folder", api.ErrPAMInvalid)
	}
	if f.TemplateID != "" {
		if !validUUID(f.TemplateID) {
			return api.PAMFolder{}, fmt.Errorf("%w: template_id must be a UUID", api.ErrPAMInvalid)
		}
		if _, err := s.store.GetPAMTemplate(ctx, tenantID, f.TemplateID); err != nil {
			return api.PAMFolder{}, err
		}
	}
	err := s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		revision := int64(1)
		old, err := s.store.GetPAMFolderAnyState(ctx, tenantID, f.Name)
		if err == nil {
			if old.Revision != f.Revision && (old.DeletedAt == nil || f.Revision != 0) {
				return fmt.Errorf("%w: the folder is at revision %d; read it again", orchestrator.ErrIdempotencyConflict, old.Revision)
			}
			revision = old.Revision + 1
		} else if !errors.Is(err, store.ErrPAMFolderNotFound) {
			return err
		} else if f.Revision != 0 {
			return fmt.Errorf("%w: a new folder has revision 0", orchestrator.ErrIdempotencyConflict)
		}
		return s.appendProject(ctx, tenantID, projections.EventPAMFolderSaved, projections.PAMFolderSaved{Name: f.Name, TemplateID: f.TemplateID,
			Description: f.Description, Revision: revision, Actor: actor, At: s.clock().UTC()})
	})
	if err != nil {
		return api.PAMFolder{}, err
	}
	saved, err := s.store.GetPAMFolder(ctx, tenantID, f.Name)
	if err != nil {
		return api.PAMFolder{}, err
	}
	n, err := s.store.CountPAMTargetsInFolder(ctx, tenantID, f.Name)
	return folderView(saved, n), err
}

func (s *pamService) ListPAMFolders(ctx context.Context, tenantID string) ([]api.PAMFolder, error) {
	folders, err := s.store.ListPAMFolders(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]api.PAMFolder, 0, len(folders))
	for _, f := range folders {
		n, err := s.store.CountPAMTargetsInFolder(ctx, tenantID, f.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, folderView(f, n))
	}
	return out, nil
}

func (s *pamService) DeletePAMFolder(ctx context.Context, tenantID, actor, name string, revision int64) error {
	if actor == "" {
		return fmt.Errorf("%w: an authenticated author is required", api.ErrPAMInvalid)
	}
	return s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		f, err := s.store.GetPAMFolder(ctx, tenantID, name)
		if err != nil {
			return err
		}
		if revision != f.Revision {
			return fmt.Errorf("%w: the folder changed; read it again", orchestrator.ErrIdempotencyConflict)
		}
		n, err := s.store.CountPAMTargetsInFolder(ctx, tenantID, name)
		if err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("%w: move the folder's %d targets out before deleting it", api.ErrPAMTargetConflict, n)
		}
		return s.appendProject(ctx, tenantID, projections.EventPAMFolderDeleted, projections.PAMFolderDeleted{Name: name, Revision: revision + 1, Actor: actor, At: s.clock().UTC()})
	})
}

func (s *pamService) SetPAMTargetFolder(ctx context.Context, tenantID, actor, targetType, id, folder string) (api.PAMTarget, error) {
	if actor == "" {
		return api.PAMTarget{}, fmt.Errorf("%w: an authenticated author is required", api.ErrPAMInvalid)
	}
	err := s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		target, err := s.store.GetPAMTarget(ctx, tenantID, targetType, id)
		if err != nil {
			return err
		}
		if err := s.requirePAMFolder(ctx, tenantID, folder); err != nil {
			return err
		}
		if target.Folder == folder {
			return nil
		}
		return s.appendProject(ctx, tenantID, projections.EventPAMTargetFolderSet, projections.PAMTargetFolderSet{TargetType: targetType, ID: id,
			Folder: folder, Previous: target.Folder, Actor: actor, At: s.clock().UTC()})
	})
	if err != nil {
		return api.PAMTarget{}, err
	}
	return s.GetPAMTarget(ctx, tenantID, targetType, id)
}

func (s *pamService) requirePAMFolder(ctx context.Context, tenantID, name string) error {
	if name == "" {
		return nil
	}
	if _, err := s.store.GetPAMFolder(ctx, tenantID, name); errors.Is(err, store.ErrPAMFolderNotFound) {
		return fmt.Errorf("%w: folder %q does not exist", api.ErrPAMInvalid, name)
	} else {
		return err
	}
}

// pamRequestTemplate resolves the folder before the caller's template. A
// caller can repeat that exact template ID, but cannot override it. The
// revision references become part of the approval's immutable command.
func (s *pamService) pamRequestTemplate(ctx context.Context, tenantID, targetType, targetID, requested string) (*store.PAMAccessTemplate, []string, bool, error) {
	target, err := s.getPAMTarget(ctx, tenantID, targetType, targetID)
	if errors.Is(err, store.ErrPAMTargetNotFound) {
		return nil, nil, false, fmt.Errorf("%w: unknown target %q", api.ErrPAMInvalid, targetID)
	}
	if err != nil {
		return nil, nil, false, err
	}
	refs := []string{}
	if target.Folder != "" {
		folder, err := s.store.GetPAMFolder(ctx, tenantID, target.Folder)
		if errors.Is(err, store.ErrPAMFolderNotFound) {
			return nil, nil, false, fmt.Errorf("%w: target's folder is unavailable", api.ErrPAMInvalid)
		}
		if err != nil {
			return nil, nil, false, err
		}
		refs = append(refs, fmt.Sprintf("pam-folder:%s@%d", folder.Name, folder.Revision))
		if folder.TemplateID != "" {
			if requested != "" && requested != folder.TemplateID {
				return nil, nil, false, fmt.Errorf("%w: folder %q requires its own access template", api.ErrPAMInvalid, folder.Name)
			}
			requested = folder.TemplateID
		}
	}
	if requested == "" {
		return nil, refs, target.GatewayAgentID != "" && s.recordings != nil && target.TargetType != pamTargetAWSConsole, nil
	}
	if !validUUID(requested) {
		return nil, nil, false, fmt.Errorf("%w: template_id must be a UUID", api.ErrPAMInvalid)
	}
	t, err := s.store.GetPAMTemplate(ctx, tenantID, requested)
	if errors.Is(err, store.ErrPAMTemplateNotFound) {
		return nil, nil, false, fmt.Errorf("%w: access template %s does not exist", api.ErrPAMInvalid, requested)
	}
	if err != nil {
		return nil, nil, false, err
	}
	refs = append(refs, fmt.Sprintf("pam-template:%s@%d", t.Name, t.Revision), "pam-template-id:"+t.ID)
	return &t, refs, target.GatewayAgentID != "" && s.recordings != nil && target.TargetType != pamTargetAWSConsole, nil
}

func (s *Server) SavePAMFolder(ctx context.Context, tenantID, actor string, f api.PAMFolder) (api.PAMFolder, error) {
	if s.pam == nil {
		return api.PAMFolder{}, api.ErrPAMUnavailable
	}
	return s.pam.SavePAMFolder(ctx, tenantID, actor, f)
}
func (s *Server) ListPAMFolders(ctx context.Context, tenantID string) ([]api.PAMFolder, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMFolders(ctx, tenantID)
}
func (s *Server) DeletePAMFolder(ctx context.Context, tenantID, actor, name string, revision int64) error {
	if s.pam == nil {
		return api.ErrPAMUnavailable
	}
	return s.pam.DeletePAMFolder(ctx, tenantID, actor, name, revision)
}
func (s *Server) SetPAMTargetFolder(ctx context.Context, tenantID, actor, targetType, id, folder string) (api.PAMTarget, error) {
	if s.pam == nil {
		return api.PAMTarget{}, api.ErrPAMUnavailable
	}
	return s.pam.SetPAMTargetFolder(ctx, tenantID, actor, targetType, id, folder)
}
