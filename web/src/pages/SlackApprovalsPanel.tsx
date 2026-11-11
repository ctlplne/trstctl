import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { ErrorState } from "@/components/StatePrimitives";
import { useCan } from "@/components/rbac";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { api, ApiError, type SlackApp, type SlackChannelList, type SlackInstallStart, type SlackLinkCode } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

// N8: approval requests posted to one Slack channel with Approve and Deny
// buttons. Connector operators install the app through Slack's consent screen
// and pick the channel; reviewers link their Slack user with a one-time code.
// N8-L1: the panel says whether the install checks the channel before posting,
// so a post retried after its answer was lost is not posted twice, and asks an
// install made before trstctl asked for the channel's history to install
// again.

type SlackChannel = SlackChannelList["items"][number];

export function SlackApprovalsPanel() {
  const { t } = useTranslation();
  const canRead = useCan("connectors:read");
  const canWrite = useCan("connectors:write");
  const canReview = useCan("approvals:review");
  const [status, setStatus] = useState<SlackApp | null>(null);
  const [notConfigured, setNotConfigured] = useState(false);
  const [consent, setConsent] = useState<SlackInstallStart | null>(null);
  const [channels, setChannels] = useState<SlackChannel[] | null>(null);
  const [channel, setChannel] = useState("");
  const [code, setCode] = useState<SlackLinkCode | null>(null);
  const [confirmUninstall, setConfirmUninstall] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // The install is read once per mount and after each change, never on a
  // re-render: a read must not undo a channel being picked. A failed read is
  // kept as its cause and worded when shown.
  const [readError, setReadError] = useState<unknown>(null);
  const refresh = useCallback(async () => {
    try {
      const next = await api.getSlackApp();
      setStatus(next);
      setNotConfigured(!next.configured);
      setReadError(null);
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 404) {
        setNotConfigured(true);
        setStatus(null);
        return;
      }
      setReadError(cause);
    }
  }, []);

  useEffect(() => {
    if (canRead) void refresh();
  }, [canRead, refresh]);

  if (!canRead && !canReview) return null;

  async function run(action: () => Promise<void>, failure: MessageKey) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (cause) {
      setError(apiProblemMessage(cause, t(failure)));
    } finally {
      setBusy(false);
    }
  }

  const install = () =>
    run(async () => {
      setConsent(await api.startSlackInstall());
    }, "approvals.slack.installFailed");

  const loadChannels = () =>
    run(async () => {
      setChannels((await api.listSlackChannels()).items.filter((item) => item.id));
      setChannel(status?.approval_channel_id ?? "");
    }, "approvals.slack.channelsFailed");

  const saveChannel = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void run(async () => {
      const next = await api.setSlackApprovalChannel({ channel_id: channel });
      setStatus(next);
      setChannels(null);
    }, "approvals.slack.saveFailed");
  };

  const link = () =>
    run(async () => {
      setCode(await api.createSlackLinkCode());
    }, "approvals.slack.linkFailed");

  const uninstall = () =>
    run(async () => {
      await api.uninstallSlackApp();
      setConfirmUninstall(false);
      setConsent(null);
      await refresh();
    }, "approvals.slack.uninstallFailed");

  const installed = Boolean(status?.installed);
  return (
    <section aria-labelledby="slack-approvals-heading" className="grid max-w-2xl gap-3">
      <div>
        <h2 id="slack-approvals-heading" className="text-title font-semibold">
          {t("approvals.slack.heading")}
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">{t("approvals.slack.description")}</p>
      </div>
      {error ? <ErrorState title={t("approvals.slack.error")}>{error}</ErrorState> : null}
      {readError ? <ErrorState title={t("approvals.slack.error")}>{apiProblemMessage(readError, t("approvals.slack.readFailed"))}</ErrorState> : null}
      {canRead && notConfigured ? <p className="text-sm text-muted-foreground">{t("approvals.slack.notConfigured")}</p> : null}
      {canRead && status && !notConfigured && !installed ? <p className="text-sm">{t("approvals.slack.notInstalled")}</p> : null}
      {canRead && installed && status ? (
        <dl className="grid gap-1 text-sm">
          <div>
            <dt className="inline font-medium">{t("approvals.slack.workspace")}: </dt>
            <dd className="inline">{status.team_name || status.team_id}</dd>
          </div>
          <div>
            <dt className="inline font-medium">{t("approvals.slack.channel")}: </dt>
            <dd className="inline">
              {status.approval_channel_name ? t("approvals.slack.publicChannel", { name: status.approval_channel_name }) : t("approvals.slack.channelNone")}
            </dd>
          </div>
          {status.installed_at ? (
            <div>
              <dt className="inline font-medium">{t("approvals.slack.installed")}: </dt>
              <dd className="inline">{t("approvals.slack.installedBy", { by: status.installed_by ?? "", at: formatDateTime(status.installed_at) })}</dd>
            </div>
          ) : null}
        </dl>
      ) : null}
      {canRead && installed && status ? (
        <p role="note" className={status.duplicate_post_check ? "text-sm text-muted-foreground" : "text-sm text-status-warning"}>
          {status.duplicate_post_check ? t("approvals.slack.checkOn") : t("approvals.slack.checkOff")}
        </p>
      ) : null}
      {canWrite && status && !notConfigured ? (
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" variant={installed ? "outline" : "default"} disabled={busy} onClick={() => void install()}>
            {installed ? t("approvals.slack.installAgain") : t("approvals.slack.install")}
          </Button>
          {consent ? (
            <a className="text-sm underline" href={consent.authorize_url} target="_blank" rel="noopener noreferrer">
              {t("approvals.slack.consent", { at: formatDateTime(consent.expires_at) })}
            </a>
          ) : null}
          {consent ? (
            <Button type="button" variant="ghost" disabled={busy} onClick={() => void refresh()}>
              {t("approvals.slack.refresh")}
            </Button>
          ) : null}
        </div>
      ) : null}
      {canWrite && installed ? (
        channels === null ? (
          <div>
            <Button type="button" variant="outline" disabled={busy} onClick={() => void loadChannels()}>
              {t("approvals.slack.pickChannel")}
            </Button>
          </div>
        ) : (
          <form className="grid max-w-md gap-2" onSubmit={saveChannel}>
            <Field label={t("approvals.slack.channel")}>
              {(control) => (
                <Select {...control} value={channel} required onChange={(event) => setChannel(event.target.value)}>
                  <option value="">{t("approvals.slack.channelChoose")}</option>
                  {channels.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.is_private
                        ? t("approvals.slack.privateChannel", { name: item.name ?? item.id ?? "" })
                        : t("approvals.slack.publicChannel", { name: item.name ?? item.id ?? "" })}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <div>
              <Button type="submit" disabled={busy || !channel}>
                {t("approvals.slack.saveChannel")}
              </Button>
            </div>
          </form>
        )
      ) : null}
      {canReview ? (
        <div className="grid gap-1">
          <div>
            <Button type="button" variant="outline" disabled={busy} onClick={() => void link()}>
              {t("approvals.slack.link")}
            </Button>
          </div>
          {code ? (
            <p role="status" className="text-sm">
              {t("approvals.slack.linkCode", { code: code.code, at: formatDateTime(code.expires_at) })}
            </p>
          ) : null}
        </div>
      ) : null}
      {canWrite && installed ? (
        confirmUninstall ? (
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm">{t("approvals.slack.uninstallConfirm")}</p>
            <Button type="button" variant="destructive" disabled={busy} onClick={() => void uninstall()}>
              {t("approvals.slack.uninstallYes")}
            </Button>
            <Button type="button" variant="ghost" disabled={busy} onClick={() => setConfirmUninstall(false)}>
              {t("approvals.slack.uninstallNo")}
            </Button>
          </div>
        ) : (
          <div>
            <Button type="button" variant="ghost" disabled={busy} onClick={() => setConfirmUninstall(true)}>
              {t("approvals.slack.uninstall")}
            </Button>
          </div>
        )
      ) : null}
    </section>
  );
}
