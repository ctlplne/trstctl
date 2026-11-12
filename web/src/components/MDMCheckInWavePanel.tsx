import { useEffect, useState } from "react";
import { useCan } from "@/components/rbac";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, ApiError, type MDMCheckInWave, type MDMCheckInWaveApproval } from "@/lib/api";
import type { MDMDevice } from "@/lib/api-types.gen";
import { apiProblemMessage } from "@/lib/apiProblem";

const MAX_WAVE_DEVICES = 200;

type WaveNotice = { tone: "status" | "alert"; text: string };

/**
 * N9-L2: check in every device of a renewal wave under one approval. The
 * requester picks the devices (or those whose renewal is at risk) and asks;
 * another reviewer approves exactly that set; Run then queues one check-in per
 * device. The waves list says how many devices checked in, failed or wait.
 */
export function MDMCheckInWavePanel() {
  const { t, formatDateTime } = useTranslation();
  const canRead = useCan("certs:read");
  const canAsk = useCan("certs:write");
  const [mdm, setMDM] = useState<"intune" | "jamf">("intune");
  const [devices, setDevices] = useState<MDMDevice[]>([]);
  const [waves, setWaves] = useState<MDMCheckInWave[]>([]);
  const [picked, setPicked] = useState<string[]>([]);
  const [reason, setReason] = useState("");
  const [approval, setApproval] = useState<MDMCheckInWaveApproval | null>(null);
  const [notice, setNotice] = useState<WaveNotice | null>(null);
  const [busy, setBusy] = useState(false);
  const [reloads, setReloads] = useState(0);

  useEffect(() => {
    if (!canRead) return;
    let cancelled = false;
    void Promise.allSettled([api.mdmDevices(), api.mdmCheckInWaves(mdm)]).then(([deviceResult, waveResult]) => {
      if (cancelled) return;
      if (deviceResult.status === "fulfilled") setDevices(deviceResult.value.items ?? []);
      setWaves(waveResult.status === "fulfilled" ? waveResult.value : []);
    });
    return () => {
      cancelled = true;
    };
  }, [canRead, mdm, reloads]);

  if (!canRead || devices.length === 0) return null;
  const ofMDM = devices.filter((device) => device.mdm === mdm);
  const atRisk = ofMDM.filter((device) => device.renewal_at_risk).map((device) => device.mdm_device_id);
  const tooMany = picked.length > MAX_WAVE_DEVICES;

  function toggle(id: string, on: boolean) {
    setPicked((current) => (on ? [...current.filter((value) => value !== id), id] : current.filter((value) => value !== id)));
  }

  function switchMDM(next: string) {
    setMDM(next === "jamf" ? "jamf" : "intune");
    setPicked([]);
    setApproval(null);
    setNotice(null);
  }

  async function ask() {
    setBusy(true);
    setNotice(null);
    try {
      const requested = await api.requestMDMCheckInWaveApproval(mdm, { device_ids: picked, reason: reason.trim() });
      setApproval(requested);
      setNotice({ tone: "status", text: t("mdm.wave.asked", { count: requested.devices.length }) });
    } catch (err) {
      setNotice({ tone: "alert", text: apiProblemMessage(err, t("mdm.wave.askFailed")) });
    } finally {
      setBusy(false);
    }
  }

  async function run() {
    if (!approval) return;
    setBusy(true);
    setNotice(null);
    try {
      const wave = await api.executeMDMCheckInWave(mdm, {
        approval_request_id: approval.approval_request_id,
        approval_intent_digest: approval.approval_intent_digest,
        device_ids: approval.devices.map((device) => device.device_id),
      });
      setNotice({ tone: "status", text: t("mdm.wave.queued", { count: wave.device_count }) });
      setApproval(null);
      setPicked([]);
      setReloads((count) => count + 1);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setNotice({ tone: "status", text: t("mdm.wave.waitsForApproval") });
      } else {
        setNotice({ tone: "alert", text: apiProblemMessage(err, t("mdm.wave.runFailed")) });
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="mdm-wave-heading" className="grid gap-3 border-t border-border pt-4">
      <div>
        <h2 id="mdm-wave-heading" className="text-title font-semibold">
          {t("mdm.wave.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("mdm.wave.description")}</p>
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <Field label={t("mdm.wave.mdmLabel")} className="w-48">
          {(control) => (
            <Select {...control} value={mdm} onChange={(event) => switchMDM(event.target.value)}>
              <option value="intune">{t("mdm.wave.intune")}</option>
              <option value="jamf">{t("mdm.wave.jamf")}</option>
            </Select>
          )}
        </Field>
        {canAsk && (
          <Button type="button" variant="outline" size="sm" disabled={atRisk.length === 0} onClick={() => setPicked(atRisk.slice(0, MAX_WAVE_DEVICES))}>
            {t("mdm.wave.pickAtRisk", { count: atRisk.length })}
          </Button>
        )}
      </div>
      {ofMDM.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("mdm.wave.noDevices")}</p>
      ) : (
        <table className="ui-table">
          <thead>
            <tr>
              <th scope="col">
                <span className="sr-only">{t("mdm.wave.pick")}</span>
              </th>
              <th scope="col">{t("mdm.wave.device")}</th>
              <th scope="col">{t("mdm.wave.serial")}</th>
              <th scope="col">{t("mdm.wave.renewal")}</th>
            </tr>
          </thead>
          <tbody>
            {ofMDM.map((device) => (
              <tr key={device.mdm_device_id}>
                <td>
                  {canAsk && (
                    <Checkbox
                      aria-label={t("mdm.wave.pickDevice", { name: device.device_name || device.mdm_device_id })}
                      checked={picked.includes(device.mdm_device_id)}
                      onChange={(event) => toggle(device.mdm_device_id, event.target.checked)}
                    />
                  )}
                </td>
                <td>{device.device_name || device.mdm_device_id}</td>
                <td className="font-mono">{device.serial_number || "-"}</td>
                <td>{device.renewal_at_risk ? t("mdm.wave.atRisk") : device.renewal_not_after ? formatDateTime(device.renewal_not_after) : "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {canAsk && (
        <div className="flex flex-wrap items-end gap-3">
          <Field label={t("mdm.wave.reason")} className="min-w-72 flex-1" error={tooMany ? t("mdm.wave.tooMany") : undefined}>
            {(control) => <Input {...control} value={reason} maxLength={200} onChange={(event) => setReason(event.target.value)} />}
          </Field>
          <Button type="button" disabled={busy || picked.length === 0 || tooMany || reason.trim() === ""} onClick={() => void ask()}>
            {t("mdm.wave.ask", { count: picked.length })}
          </Button>
        </div>
      )}
      {approval && (
        <div className="ui-panel p-comfortable text-sm">
          <p>{t("mdm.wave.approval", { id: approval.approval_request_id, count: approval.devices.length, status: approval.status })}</p>
          <Button type="button" size="sm" className="mt-2" disabled={busy} onClick={() => void run()}>
            {t("mdm.wave.run")}
          </Button>
        </div>
      )}
      {notice && (
        <p role={notice.tone} className={notice.tone === "alert" ? "text-sm text-destructive" : "text-sm"}>
          {notice.text}
        </p>
      )}
      {waves.length > 0 && (
        <table className="ui-table">
          <caption className="text-left text-sm font-semibold">{t("mdm.wave.waves")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("mdm.wave.queuedAt")}</th>
              <th scope="col">{t("mdm.wave.requestedBy")}</th>
              <th scope="col">{t("mdm.wave.devices")}</th>
              <th scope="col">{t("mdm.wave.checkedIn")}</th>
              <th scope="col">{t("mdm.wave.failed")}</th>
              <th scope="col">{t("mdm.wave.waiting")}</th>
            </tr>
          </thead>
          <tbody>
            {waves.map((wave) => (
              <tr key={wave.id}>
                <td>{formatDateTime(wave.queued_at)}</td>
                <td>{wave.requested_by}</td>
                <td>{wave.device_count}</td>
                <td>{wave.checked_in}</td>
                <td>{wave.failed}</td>
                <td>{wave.queued}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
