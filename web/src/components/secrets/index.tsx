import { useState } from "react";
import { cn } from "@/lib/utils";
import { SectionCard, AttentionList, AttentionRow } from "@/components/dashboard";
import { api, type SecretMeta } from "@/lib/api";
import { translateNow } from "@/i18n/I18nProvider";

export interface SecretFolder {
  path: string;
  secrets: SecretMeta[];
}

export function groupSecretsByFolder(secrets: SecretMeta[]): SecretFolder[] {
  const folders = new Map<string, SecretMeta[]>();
  for (const secret of secrets) {
    const index = secret.name.lastIndexOf("/");
    const path = index === -1 ? "/" : secret.name.slice(0, index);
    const list = folders.get(path) ?? [];
    list.push(secret);
    folders.set(path, list);
  }
  return [...folders.entries()].map(([path, items]) => ({ path, secrets: items })).sort((a, b) => a.path.localeCompare(b.path));
}

function leafName(name: string): string {
  const index = name.lastIndexOf("/");
  return index === -1 ? name : name.slice(index + 1);
}

export function SecretTree({ secrets, onSelect, selectedName }: { secrets: SecretMeta[]; onSelect?: (name: string) => void; selectedName?: string }) {
  const folders = groupSecretsByFolder(secrets);
  return (
    <SectionCard title={translateNow("source.browse.by.folder.2bd11442a2")} description="secrets grouped by path, like environments and folders">
      {folders.length === 0 ? (
        <p className="text-caption text-muted-foreground">{translateNow("source.no.secrets.yet.b9b321718c")}</p>
      ) : (
        <nav aria-label={translateNow("source.secret.folders.78f2cd9fca")} className="grid gap-3">
          {folders.map((folder) => (
            <div key={folder.path}>
              <p className="font-mono text-caption font-medium text-muted-foreground">
                {folder.path === "/" ? translateNow("source.root.44c4ce0579") : folder.path}
              </p>
              <ul className="mt-1 grid gap-0.5">
                {folder.secrets.map((secret) => (
                  <li key={secret.name}>
                    <button
                      type="button"
                      onClick={() => onSelect?.(secret.name)}
                      aria-pressed={selectedName === secret.name}
                      className={cn("w-full truncate rounded-control px-2 py-1 text-left text-body hover:bg-muted", selectedName === secret.name && "bg-muted")}
                    >
                      {leafName(secret.name)}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
      )}
    </SectionCard>
  );
}

export function ReferenceResolver() {
  const [name, setName] = useState("");
  const [resolved, setResolved] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function resolve() {
    setBusy(true);
    setError(null);
    setResolved(null);
    try {
      const value = await api.getSecret(name.trim(), { resolve: true });
      setResolved(value.value);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <SectionCard
      title={translateNow("source.secret.references.4afbc504fa")}
      description="resolve ${...} references — a base secret propagates to everything that points at it"
    >
      <div className="flex flex-wrap items-end gap-2">
        <label className="grid gap-1 text-body">
          <span className="font-medium">{translateNow("source.secret.name.5cdf573b89")}</span>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder={translateNow("source.prod.db.url.708742f8f1")}
            className="rounded-control border border-border bg-background px-3 py-2"
          />
        </label>
        <button
          type="button"
          onClick={() => void resolve()}
          disabled={busy || !name.trim()}
          className="min-h-9 rounded-control border border-border px-3 text-body disabled:opacity-60"
        >
          {translateNow("source.resolve.references.df9921d3ac")}
        </button>
      </div>
      {resolved !== null ? (
        <p className="mt-2 break-all font-mono text-caption">
          {translateNow("source.resolved.8db3c92ddc")} {resolved}
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="mt-2 text-caption text-risk-critical">
          {error}
        </p>
      ) : null}
    </SectionCard>
  );
}

export interface SecretDiff {
  added: string[];
  removed: string[];
  changed: string[];
}

export function diffSecrets(left: SecretMeta[], right: SecretMeta[]): SecretDiff {
  const leftMap = new Map(left.map((secret) => [secret.name, secret.version]));
  const rightMap = new Map(right.map((secret) => [secret.name, secret.version]));
  const added: string[] = [];
  const removed: string[] = [];
  const changed: string[] = [];
  for (const [name, version] of rightMap) {
    if (!leftMap.has(name)) added.push(name);
    else if (leftMap.get(name) !== version) changed.push(name);
  }
  for (const name of leftMap.keys()) {
    if (!rightMap.has(name)) removed.push(name);
  }
  return { added: added.sort(), removed: removed.sort(), changed: changed.sort() };
}

function toLeaves(secrets: SecretMeta[]): SecretMeta[] {
  return secrets.map((secret) => ({ ...secret, name: leafName(secret.name) }));
}

export function EnvDiffPanel({ secrets }: { secrets: SecretMeta[] }) {
  const folders = groupSecretsByFolder(secrets);
  const [leftPath, setLeftPath] = useState(folders[0]?.path ?? "");
  const [rightPath, setRightPath] = useState(folders[1]?.path ?? folders[0]?.path ?? "");
  const left = toLeaves(folders.find((folder) => folder.path === leftPath)?.secrets ?? []);
  const right = toLeaves(folders.find((folder) => folder.path === rightPath)?.secrets ?? []);
  const diff = diffSecrets(left, right);
  const same = diff.added.length + diff.removed.length + diff.changed.length === 0;
  return (
    <SectionCard title={translateNow("source.environment.diff.ed4e460569")} description="spot missing or changed secrets across two folders at a glance">
      <div className="mb-3 flex flex-wrap gap-2">
        <select
          aria-label={translateNow("source.left.environment.a42bb38048")}
          value={leftPath}
          onChange={(event) => setLeftPath(event.target.value)}
          className="min-h-9 rounded-control border border-border bg-background px-2 text-body"
        >
          {folders.map((folder) => (
            <option key={folder.path} value={folder.path}>
              {folder.path === "/" ? translateNow("source.root.44c4ce0579") : folder.path}
            </option>
          ))}
        </select>
        <span aria-hidden="true" className="self-center text-muted-foreground">
          →
        </span>
        <select
          aria-label={translateNow("source.right.environment.17dc94151f")}
          value={rightPath}
          onChange={(event) => setRightPath(event.target.value)}
          className="min-h-9 rounded-control border border-border bg-background px-2 text-body"
        >
          {folders.map((folder) => (
            <option key={folder.path} value={folder.path}>
              {folder.path === "/" ? translateNow("source.root.44c4ce0579") : folder.path}
            </option>
          ))}
        </select>
      </div>
      <div className="grid gap-1 font-mono text-caption">
        {diff.added.map((name) => (
          <p key={`a-${name}`} className="text-status-success">
            + {name}
          </p>
        ))}
        {diff.removed.map((name) => (
          <p key={`r-${name}`} className="text-risk-critical">
            - {name}
          </p>
        ))}
        {diff.changed.map((name) => (
          <p key={`c-${name}`} className="text-status-warning">
            ~ {name}
          </p>
        ))}
        {same ? <p className="text-muted-foreground">{translateNow("source.these.environments.are.identical.3a4421cc16")}</p> : null}
      </div>
    </SectionCard>
  );
}

export function VersionHistory({ name, latestVersion }: { name: string; latestVersion: number }) {
  const [revealed, setRevealed] = useState<{ version: number; value: string } | null>(null);
  const [at, setAt] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const versions = Array.from({ length: latestVersion }, (_unused, index) => latestVersion - index);

  async function reveal(version: number) {
    setError(null);
    try {
      const value = await api.getSecretVersion(name, version);
      setRevealed({ version, value: value.value });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }
  async function recover() {
    setError(null);
    setNote(null);
    try {
      const meta = await api.recoverSecret(name, { at: at.trim() });
      setNote(`Recovered to version ${meta.version}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <SectionCard
      title={translateNow("source.version.history.a6df11e706")}
      description="every version is retained; reveal a version or recover to a point in time"
    >
      <AttentionList ariaLabel="Secret versions">
        {versions.map((version) => (
          <AttentionRow key={version}>
            <span className="flex-1 tabular-nums">
              {translateNow("source.version.5ca4f3850c")} {version}
            </span>
            <button type="button" onClick={() => void reveal(version)} className="rounded-control border border-border px-2 py-1 text-caption">
              {translateNow("source.reveal.36b830bdb4")}
            </button>
          </AttentionRow>
        ))}
      </AttentionList>
      {revealed ? (
        <p className="mt-2 break-all font-mono text-caption">
          v{revealed.version}: {revealed.value}
        </p>
      ) : null}
      <div className="mt-3 flex flex-wrap items-end gap-2">
        <label className="grid gap-1 text-body">
          <span className="font-medium">{translateNow("source.recover.to.timestamp.c9cb99538c")}</span>
          <input
            value={at}
            onChange={(event) => setAt(event.target.value)}
            placeholder={translateNow("source.2026.01.01t00.00.00z.06fea089d5")}
            className="rounded-control border border-border bg-background px-3 py-2"
          />
        </label>
        <button
          type="button"
          onClick={() => void recover()}
          disabled={!at.trim()}
          className="min-h-9 rounded-control border border-border px-3 text-body disabled:opacity-60"
        >
          {translateNow("source.recover.0c5327fd45")}
        </button>
      </div>
      {note ? <p className="mt-2 text-caption text-status-success">{note}</p> : null}
      {error ? (
        <p role="alert" className="mt-2 text-caption text-risk-critical">
          {error}
        </p>
      ) : null}
    </SectionCard>
  );
}

export function SecretImport({ onImported }: { onImported?: (names: string[]) => void }) {
  const [prefix, setPrefix] = useState("");
  const [text, setText] = useState("");
  const [imported, setImported] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  function parse(input: string): Record<string, unknown> {
    const values: Record<string, unknown> = {};
    for (const line of input.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const eq = trimmed.indexOf("=");
      if (eq === -1) continue;
      values[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
    }
    return values;
  }

  async function submit() {
    setError(null);
    setImported(null);
    try {
      const result = await api.importSecrets({ values: parse(text), ...(prefix.trim() ? { prefix: prefix.trim() } : {}) });
      const names = (result.items ?? []).map((item) => item.name);
      setImported(names);
      onImported?.(names);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <SectionCard title={translateNow("source.import.secrets.a657cdf701")} description="bulk-import key=value pairs into a folder">
      <div className="grid gap-2">
        <label className="grid gap-1 text-body">
          <span className="font-medium">{translateNow("source.folder.prefix.2d63670e07")}</span>
          <input
            value={prefix}
            onChange={(event) => setPrefix(event.target.value)}
            placeholder={translateNow("source.prod.imported.b9342ac821")}
            className="rounded-control border border-border bg-background px-3 py-2"
          />
        </label>
        <label className="grid gap-1 text-body">
          <span className="font-medium">Key=value pairs</span>
          <textarea
            value={text}
            onChange={(event) => setText(event.target.value)}
            rows={3}
            placeholder={"DB_URL=postgres://...\nAPI_KEY=..."}
            className="rounded-control border border-border bg-background px-3 py-2 font-mono text-caption"
          />
        </label>
        <div>
          <button
            type="button"
            onClick={() => void submit()}
            disabled={!text.trim()}
            className="min-h-9 rounded-control border border-border px-3 text-body disabled:opacity-60"
          >
            Import
          </button>
        </div>
      </div>
      {imported ? (
        <p className="mt-2 text-caption text-status-success">
          {translateNow("source.imported.321f179c80")} {imported.length} {translateNow("source.secrets.cdefff020a")} {imported.join(", ")}
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="mt-2 text-caption text-risk-critical">
          {error}
        </p>
      ) : null}
    </SectionCard>
  );
}
