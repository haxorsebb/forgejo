// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pam

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"forgejo.org/models/auth"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/auth/pam"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/validation"

	"github.com/google/uuid"
)

// Authenticate queries if login/password is valid against the PAM,
// and create a local user if success when enabled.
func (source *Source) Authenticate(ctx context.Context, user *user_model.User, userName, password string) (*user_model.User, error) {
	// The appliance policy is opt-in; ordinary Forgejo PAM sources retain their behavior.
	managedGroups := []string(nil)
	if marker := os.Getenv("FORGEJO_APPLIANCE_PAM_GROUP_MARKER"); marker != "" {
		var err error
		managedGroups, err = applianceManagedGroups(userName, marker)
		if err != nil {
			return nil, err
		}
		if len(managedGroups) == 0 {
			return nil, user_model.ErrUserNotExist{Name: userName}
		}
	}

	pamLogin, err := pam.Auth(source.ServiceName, userName, password)
	if err != nil {
		if errors.Is(err, pam.ErrInvalidCredentials) {
			return nil, user_model.ErrUserNotExist{Name: userName}
		}
		return nil, err
	}

	if user != nil {
		if managedGroups != nil {
			isAdmin := slices.Contains(managedGroups, "forgejo-admins")
			if user.IsAdmin != isAdmin {
				user.IsAdmin = isAdmin
				if err := user_model.UpdateUserCols(ctx, user, "is_admin"); err != nil {
					return nil, err
				}
			}
		}
		return user, nil
	}

	// Allow PAM sources with `@` in their name, like from Active Directory
	username := pamLogin
	email := pamLogin
	before, _, ok := strings.Cut(pamLogin, "@")
	if ok {
		username = before
	}
	if validation.ValidateEmail(email) != nil {
		if source.EmailDomain != "" {
			email = fmt.Sprintf("%s@%s", username, source.EmailDomain)
		} else {
			email = fmt.Sprintf("%s@%s", username, setting.Service.NoReplyAddress)
		}
		if validation.ValidateEmail(email) != nil {
			email = uuid.New().String() + "@localhost"
		}
	}

	user = &user_model.User{
		LowerName:   strings.ToLower(username),
		Name:        username,
		Email:       email,
		Passwd:      password,
		LoginType:   auth.PAM,
		LoginSource: source.authSource.ID,
		LoginName:   userName, // This is what the user typed in
		IsAdmin:     managedGroups != nil && slices.Contains(managedGroups, "forgejo-admins"),
	}
	overwriteDefault := &user_model.CreateUserOverwriteOptions{
		IsActive: optional.Some(true),
	}

	if err := user_model.CreateUser(ctx, user, overwriteDefault); err != nil {
		return user, err
	}

	return user, nil
}

// IsSkipLocalTwoFA returns if this source should skip local 2fa for password authentication
func (source *Source) IsSkipLocalTwoFA() bool {
	return source.SkipLocalTwoFA
}

// applianceManagedGroups identifies the user\x27s supplementary NSS groups marked
// for appliance-managed Forgejo access. Fail closed on NSS or group lookup errors.
func applianceManagedGroups(username, marker string) ([]string, error) {
	out, err := exec.Command("id", "-nG", username).Output()
	if err != nil {
		return nil, fmt.Errorf("resolve Forgejo system groups for %s: %w", username, err)
	}
	var managed []string
	for _, group := range strings.Fields(string(out)) {
		entry, err := exec.Command("getent", "group", group).Output()
		if err != nil {
			return nil, fmt.Errorf("resolve Forgejo group %s: %w", group, err)
		}
		parts := strings.SplitN(strings.TrimSpace(string(entry)), ":", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("malformed NSS group entry for %s", group)
		}
		if slices.Contains(strings.Split(parts[3], ","), marker) {
			managed = append(managed, group)
		}
	}
	return managed, nil
}
