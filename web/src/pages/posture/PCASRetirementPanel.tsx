import { useState } from "react";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { pcasApi, type PCASRetirementMember, type PCASRetirementPolicy, type PCASRetirementPolicyRequest } from "@/lib/pcasApi";

export function PCASRetirementPanel({ identityID }: { identityID: string }) {
  const { t } = useTranslation();
  const [epoch, setEpoch] = useState(0);
  const [threshold, setThreshold] = useState(1);
  const [windowSeconds, setWindowSeconds] = useState(0);
  const [roster, setRoster] = useState<PCASRetirementMember[]>([{ relying_party: "", public_der: "" }]);
  const [saved, setSaved] = useState<PCASRetirementPolicy | null>(null);
  const [reviewedTuple, setReviewedTuple] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const draft: PCASRetirementPolicyRequest = {
    identity_id: identityID,
    predecessor_epoch: epoch,
    threshold,
    roster: roster.map((member) => ({ relying_party: member.relying_party.trim(), public_der: member.public_der.trim() })),
    validity_window_seconds: windowSeconds,
  };
  const tuple = JSON.stringify(draft);
  const valid =
    identityID.length > 0 &&
    Number.isSafeInteger(epoch) &&
    epoch >= 0 &&
    Number.isSafeInteger(threshold) &&
    threshold > 0 &&
    threshold <= roster.length &&
    Number.isSafeInteger(windowSeconds) &&
    windowSeconds >= 0 &&
    roster.every((member) => member.relying_party.trim() && member.public_der.trim()) &&
    new Set(roster.map((member) => member.relying_party.trim())).size === roster.length;

  function updateMember(index: number, key: keyof PCASRetirementMember, value: string) {
    setRoster((current) => current.map((member, position) => (position === index ? { ...member, [key]: value } : member)));
    setReviewedTuple("");
  }

  async function readPolicy() {
    if (!identityID || !Number.isSafeInteger(epoch) || epoch < 0) return;
    setBusy(true);
    setError("");
    setReviewedTuple("");
    try {
      const policy = await pcasApi.retirementStatus(identityID, epoch);
      setSaved(policy);
      setThreshold(policy.threshold);
      setWindowSeconds(policy.validity_window_seconds);
      setRoster(policy.roster.map((member) => ({ ...member })));
    } catch (cause) {
      setSaved(null);
      setError(cause instanceof Error ? cause.message : t("pcas.retirement.readError"));
    } finally {
      setBusy(false);
    }
  }

  async function savePolicy() {
    if (!valid || reviewedTuple !== tuple) {
      setReviewedTuple("");
      setError(t("pcas.error.reviewChanged"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      const policy = await pcasApi.configureRetirement(draft);
      setSaved(policy);
      setReviewedTuple("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("pcas.retirement.saveError"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="grid gap-3 border-t border-border pt-4" aria-labelledby="pcas-retirement-heading">
      <h3 id="pcas-retirement-heading" className="font-semibold">
        {t("pcas.retirement.title")}
      </h3>
      <p className="text-sm text-muted-foreground">{t("pcas.retirement.description")}</p>
      <label className="grid gap-1 text-sm">
        <span>{t("pcas.retirement.epoch")}</span>
        <input
          className="ui-input"
          type="number"
          min="0"
          step="1"
          value={epoch}
          onChange={(event) => {
            setEpoch(Number(event.target.value));
            setSaved(null);
            setReviewedTuple("");
            setThreshold(1);
            setWindowSeconds(0);
            setRoster([{ relying_party: "", public_der: "" }]);
          }}
        />
      </label>
      <Button type="button" variant="outline" disabled={busy || !identityID} onClick={() => void readPolicy()}>
        {t("pcas.retirement.read")}
      </Button>
      {saved ? (
        <div className="grid gap-1 rounded-panel border border-border bg-background p-3 text-sm" aria-live="polite">
          <strong>{t("pcas.retirement.saved")}</strong>
          <p>
            {t("pcas.retirement.status")}: {saved.status}
          </p>
          <p>
            {t("pcas.retirement.rewrap")}: {saved.rewrap_complete ? t("pcas.retirement.yes") : t("pcas.retirement.no")}
          </p>
          <p>
            {t("pcas.retirement.updated")}: {saved.updated_at}
          </p>
          <p>{t("pcas.retirement.savedQuorum", { threshold: saved.threshold, count: saved.roster.length })}</p>
        </div>
      ) : null}
      <div className="grid gap-3 md:grid-cols-2">
        <label className="grid gap-1 text-sm">
          <span>{t("pcas.retirement.threshold")}</span>
          <input
            className="ui-input"
            type="number"
            min="1"
            step="1"
            value={threshold}
            onChange={(event) => {
              setThreshold(Number(event.target.value));
              setReviewedTuple("");
            }}
          />
        </label>
        <label className="grid gap-1 text-sm">
          <span>{t("pcas.retirement.window")}</span>
          <input
            className="ui-input"
            type="number"
            min="0"
            step="1"
            value={windowSeconds}
            onChange={(event) => {
              setWindowSeconds(Number(event.target.value));
              setReviewedTuple("");
            }}
          />
        </label>
      </div>
      <p className="text-sm text-muted-foreground">{t("pcas.retirement.handle")}</p>
      <p className="text-sm text-muted-foreground">{t("pcas.retirement.rosterHelp")}</p>
      {roster.map((member, index) => (
        <div key={index} className="grid gap-2 rounded-panel border border-border p-3 md:grid-cols-[1fr_2fr_auto]">
          <label className="grid gap-1 text-sm">
            <span>{t("pcas.retirement.party", { index: index + 1 })}</span>
            <input className="ui-input" value={member.relying_party} onChange={(event) => updateMember(index, "relying_party", event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            <span>{t("pcas.retirement.publicDER", { index: index + 1 })}</span>
            <input className="ui-input font-mono" value={member.public_der} onChange={(event) => updateMember(index, "public_der", event.target.value)} />
          </label>
          <Button
            type="button"
            variant="outline"
            disabled={busy || roster.length === 1}
            onClick={() => {
              setRoster((current) => current.filter((_, position) => position !== index));
              setReviewedTuple("");
            }}
          >
            {t("pcas.retirement.remove")}
          </Button>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        disabled={busy}
        onClick={() => {
          setRoster((current) => [...current, { relying_party: "", public_der: "" }]);
          setReviewedTuple("");
        }}
      >
        {t("pcas.retirement.add")}
      </Button>
      <Button
        type="button"
        disabled={busy || !valid}
        onClick={() => {
          setReviewedTuple(tuple);
          setError("");
        }}
      >
        {t("pcas.retirement.review")}
      </Button>
      {reviewedTuple === tuple ? (
        <div className="grid gap-2 rounded-panel border border-border bg-background p-3 text-sm">
          <strong>{t("pcas.retirement.reviewTitle")}</strong>
          <p>{t("pcas.retirement.effect")}</p>
          <code className="break-all">
            {identityID} · {t("pcas.epoch")}: {epoch} · {t("pcas.retirement.savedQuorum", { threshold, count: roster.length })} · {windowSeconds}s
          </code>
          <ul className="grid gap-1">
            {draft.roster.map((member) => (
              <li key={member.relying_party} className="break-all font-mono">
                {member.relying_party}: {member.public_der}
              </li>
            ))}
          </ul>
          <Button type="button" disabled={busy} onClick={() => void savePolicy()}>
            {t("pcas.retirement.save")}
          </Button>
        </div>
      ) : null}
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </section>
  );
}
