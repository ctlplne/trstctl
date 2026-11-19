-- SPDX-License-Identifier: BUSL-1.1
-- Only a worker's versioned observation can project a refused origin here.
ALTER TABLE discovery_findings ADD COLUMN attack_path_refused_origin text NOT NULL DEFAULT '';
