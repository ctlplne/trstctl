// SPDX-License-Identifier: BUSL-1.1

package spireupstream

import "net/http"

type Plugin struct {
	client *http.Client
}

func New() *Plugin {
	return &Plugin{client: http.DefaultClient}
}

func (p *Plugin) httpClient() *http.Client {
	if p.client != nil {
		return p.client
	}
	return http.DefaultClient
}
