-- Old first/last observations do not prove that the intervening time was
-- observed. Keep those historical values, but do not manufacture a range from
-- them. NULL also lets older backup rows restore without inventing coverage.
-- Only a recorder flush may add a range, in the counter-write transaction.
ALTER TABLE provider_usage_coverage ADD COLUMN observed_ranges tstzmultirange;
