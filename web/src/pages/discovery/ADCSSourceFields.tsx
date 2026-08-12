import { Field } from "@/components/ui/field";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";

export type ADCSEnrollmentEndpointTarget = {
  enrollment_service: string;
  kind: "web_enrollment" | "ndes" | "ndes_admin";
  url: string;
};

export function parseADCSEnrollmentEndpoints(raw: string): ADCSEnrollmentEndpointTarget[] {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, index) => {
      const [enrollmentService, kind, url, ...extra] = line.split("|").map((part) => part.trim());
      if (!enrollmentService || !url || extra.length > 0 || !["web_enrollment", "ndes", "ndes_admin"].includes(kind)) {
        throw new Error(`AD CS endpoint line ${index + 1} must be SERVICE | web_enrollment|ndes|ndes_admin | URL`);
      }
      return { enrollment_service: enrollmentService, kind: kind as ADCSEnrollmentEndpointTarget["kind"], url };
    });
}

export function parseADCSPrivateEgressCIDRs(raw: string): string[] {
  return raw
    .split(/[\n,]/)
    .map((value) => value.trim())
    .filter(Boolean);
}

export function ADCSSourceFields({
  url,
  configurationDN,
  bindDN,
  passwordRef,
  relayAgentID,
  enrollmentEndpoints,
  allowPrivateEndpoint,
  privateEgressCIDRs,
  onURL,
  onConfigurationDN,
  onBindDN,
  onPasswordRef,
  onRelayAgentID,
  onEnrollmentEndpoints,
  onAllowPrivateEndpoint,
  onPrivateEgressCIDRs,
}: {
  url: string;
  configurationDN: string;
  bindDN: string;
  passwordRef: string;
  relayAgentID: string;
  enrollmentEndpoints: string;
  allowPrivateEndpoint: boolean;
  privateEgressCIDRs: string;
  onURL: (value: string) => void;
  onConfigurationDN: (value: string) => void;
  onBindDN: (value: string) => void;
  onPasswordRef: (value: string) => void;
  onRelayAgentID: (value: string) => void;
  onEnrollmentEndpoints: (value: string) => void;
  onAllowPrivateEndpoint: (value: boolean) => void;
  onPrivateEgressCIDRs: (value: string) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-3 md:grid-cols-2">
      <ADCSField label={translateNow("source.directory.url.2029b746ff")} value={url} onValue={onURL} className="md:col-span-2" />
      <ADCSField
        label={translateNow("protocols.dns01.config")}
        value={configurationDN}
        onValue={onConfigurationDN}
        placeholder="CN=Configuration,DC=corp,DC=example"
        className="md:col-span-2"
      />
      <ADCSField label={translateNow("source.bind.56b9b63d28")} value={bindDN} onValue={onBindDN} />
      <ADCSField label={translateNow("notifications.routing.credentialRef")} value={passwordRef} onValue={onPasswordRef} />
      <ADCSField
        label={t("discovery.source.relayAgent")}
        value={relayAgentID}
        onValue={onRelayAgentID}
        placeholder={t("discovery.source.relayAgentPlaceholder")}
        className="md:col-span-2"
        required={false}
      />
      <Field label={translateNow("source.adcs.endpoints.aud370001")} className="md:col-span-2">
        {(control) => (
          <>
            <Textarea
              {...control}
              className="min-h-24 font-mono text-xs"
              value={enrollmentEndpoints}
              onChange={(event) => onEnrollmentEndpoints(event.target.value)}
              placeholder={translateNow("source.adcs.endpoints.placeholder.aud370017")}
            />
            <p className="mt-1 text-xs text-muted-foreground">{translateNow("source.adcs.endpoints.help.aud370002")}</p>
          </>
        )}
      </Field>
      <label className="inline-flex items-center gap-2 text-sm font-medium md:col-span-2">
        <Checkbox checked={allowPrivateEndpoint} onChange={(event) => onAllowPrivateEndpoint(event.target.checked)} />
        {translateNow("source.adcs.private.allow.aud370020")}
      </label>
      {allowPrivateEndpoint ? (
        <Field label={translateNow("source.adcs.private.cidrs.aud370021")} className="md:col-span-2" required>
          {(control) => (
            <>
              <Textarea
                {...control}
                className="min-h-16 font-mono text-xs"
                required
                value={privateEgressCIDRs}
                onChange={(event) => onPrivateEgressCIDRs(event.target.value)}
                placeholder={translateNow("source.adcs.private.placeholder.aud370023")}
              />
              <p className="mt-1 text-xs text-muted-foreground">{translateNow("source.adcs.private.help.aud370022")}</p>
            </>
          )}
        </Field>
      ) : null}
    </div>
  );
}

function ADCSField({
  label,
  value,
  onValue,
  placeholder,
  className,
  required = true,
}: {
  label: string;
  value: string;
  onValue: (value: string) => void;
  placeholder?: string;
  className?: string;
  required?: boolean;
}) {
  return (
    <Field label={label} className={className} required={required}>
      {(control) => (
        <Input
          {...control}
          className="font-mono text-xs"
          value={value}
          onChange={(event) => onValue(event.target.value)}
          placeholder={placeholder}
          required={required}
        />
      )}
    </Field>
  );
}
