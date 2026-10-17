-- KEM rewrap stage rows are serving projections of the accepted-request and
-- recorded-paired-successor events. Zero marks historical direct-write rows;
-- full replay never manufactures a missing historical source event.
ALTER TABLE pcas_rewrap_job ADD COLUMN source_sequence bigint NOT NULL DEFAULT 0;
ALTER TABLE pcas_rewrap_job ADD COLUMN request_digest bytea;
CREATE INDEX pcas_rewrap_job_source_sequence_idx
    ON pcas_rewrap_job (source_sequence) WHERE source_sequence > 0;
