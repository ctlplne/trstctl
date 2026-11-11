import { mutate, req } from "./apiTransport";
import type { SlackApp, SlackApprovalChannel, SlackChannelList, SlackInstallStart, SlackLinkCode } from "./api";

// N8: the Slack app. Connector operators install it in their workspace
// through Slack's consent screen and pick the channel approval requests are
// posted to with Approve and Deny buttons; reviewers link their Slack user
// with a one-time code typed into Slack.

export const getSlackApp = () => req<SlackApp>("/api/v1/integrations/slack");

export const startSlackInstall = (idempotencyKey?: string) => mutate<SlackInstallStart>("POST", "/api/v1/integrations/slack/install", {}, idempotencyKey);

export const listSlackChannels = () => req<SlackChannelList>("/api/v1/integrations/slack/channels");

export const setSlackApprovalChannel = (input: SlackApprovalChannel, idempotencyKey?: string) =>
  mutate<SlackApp>("PUT", "/api/v1/integrations/slack/approval-channel", input, idempotencyKey);

export const createSlackLinkCode = (idempotencyKey?: string) => mutate<SlackLinkCode>("POST", "/api/v1/integrations/slack/link-codes", {}, idempotencyKey);

export const uninstallSlackApp = (idempotencyKey?: string) => mutate<void>("DELETE", "/api/v1/integrations/slack", undefined, idempotencyKey);
