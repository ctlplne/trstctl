// SPDX-License-Identifier: LicenseRef-trstctl-EE

package api

import "trstctl.com/trstctl/internal/api"

// schemas declares the agreement surface's contract.
//
// `configured` and `replay_watermark` are REQUIRED rather than optional, which
// is a deliberate contract decision. Both are the fields that qualify every
// count beside them, and an optional field is one a client may omit and a reader
// may not notice is missing — leaving "0 open witnesses" to be read as agreement
// when it is silence.
func schemas() map[string]*api.Schema {
	return map[string]*api.Schema{
		"AuthorityAgreementReport": api.ObjectSchema(map[string]*api.Schema{
			"authorities":               api.ArraySchema(api.SchemaRef("AuthorityAgreement")),
			"open_witnesses":            api.IntegerSchema(),
			"replay_watermark":          api.IntegerSchema(),
			"median_resolution_seconds": api.IntegerSchema(),
			"resolved_in_window":        api.IntegerSchema(),
			"configured":                api.BooleanSchema(),
			"collecting":                api.BooleanSchema(),
			"detail":                    api.StringSchema(),
			"guidance":                  api.StringSchema(),
		}, "authorities", "open_witnesses", "replay_watermark", "configured", "collecting", "detail", "guidance"),
		"AuthorityAgreement": api.ObjectSchema(map[string]*api.Schema{
			"authority_id":    api.StringSchema(),
			"witnesses":       api.ArraySchema(api.SchemaRef("AuthorityWitnessClassCount")),
			"total":           api.IntegerSchema(),
			"last_witness_at": api.StringSchema(),
		}, "authority_id", "witnesses", "total"),
		"AuthorityWitnessClassCount": api.ObjectSchema(map[string]*api.Schema{
			"class": api.StringSchema(),
			"count": api.IntegerSchema(),
		}, "class", "count"),
	}
}
