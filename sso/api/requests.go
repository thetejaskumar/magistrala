// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	apiutil "github.com/absmach/supermq/api/http/util"
)

// ssoCallbackReq represents the request for SSO callback
type ssoCallbackReq struct {
	token string // SSO JWT token from query parameter
}

func (req ssoCallbackReq) validate() error {
	if req.token == "" {
		return apiutil.ErrValidation
	}
	return nil
}
