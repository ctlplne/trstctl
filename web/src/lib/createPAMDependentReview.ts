import type { api, PAMServiceDependentRotationPreview } from "@/lib/api";
import type { PAMServiceDependentReviewHost, PAMServiceDependentReviewOpenRequest } from "@/lib/api-types.gen";
import { dependentReviewPages, type DependentReviewDraftRow } from "./pamDependentReviewPages";

type ReviewClient = Pick<
  typeof api,
  "openPAMServiceDependentReview" | "appendPAMServiceDependentReviewPage" | "sealPAMServiceDependentReview" | "pamServiceDependentReview"
>;
const isDigest = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

export async function createPAMDependentReview(
  client: ReviewClient,
  accountID: string,
  input: PAMServiceDependentReviewOpenRequest,
  hosts: readonly PAMServiceDependentReviewHost[],
  rows: readonly DependentReviewDraftRow[],
  key: (value: unknown) => string,
  invalid: string,
): Promise<PAMServiceDependentRotationPreview> {
  // Even opening the root is bound to the complete draft. A changed probe,
  // order, selected host or scan starts a new immutable review on retry.
  const draft = { accountID, input, hosts, rows };
  const root = await client.openPAMServiceDependentReview(accountID, input, key({ open: draft }));
  if (
    !root.header.id ||
    !isDigest(root.header_digest) ||
    root.header.account.account_id !== accountID ||
    root.header.secret_name !== input.secret_name ||
    root.header.mode !== input.mode
  )
    throw new Error(invalid);
  let previous = root.header_digest;
  let number = 0;
  for (const body of dependentReviewPages(root, hosts, rows, invalid)) {
    const request = { ...body, previous_digest: previous };
    const page = await client.appendPAMServiceDependentReviewPage(root.header.id, number, request, key({ append: root.header.id, number, request }));
    if (
      page.version !== 1 ||
      page.id !== root.header.id ||
      page.header_digest !== root.header_digest ||
      page.page_number !== number ||
      page.previous_digest !== previous ||
      !isDigest(page.digest)
    )
      throw new Error(invalid);
    previous = page.digest;
    number++;
  }
  const sealRequest = { header_digest: root.header_digest, tail_digest: previous };
  await client.sealPAMServiceDependentReview(root.header.id, sealRequest, key({ seal: root.header.id, sealRequest }));
  const sealed = await client.pamServiceDependentReview(root.header.id);
  const intent = sealed.intent;
  if (
    !sealed.seal ||
    !intent ||
    !isDigest(sealed.intent_digest) ||
    sealed.header_digest !== root.header_digest ||
    sealed.header.id !== root.header.id ||
    sealed.seal.id !== root.header.id ||
    sealed.seal.header_digest !== root.header_digest ||
    sealed.seal.tail_digest !== previous ||
    sealed.seal.page_count !== number ||
    sealed.seal.entry_count !== rows.length ||
    sealed.seal.host_count !== hosts.length ||
    intent.plan.id !== root.header.id ||
    intent.plan.manifest?.digest !== sealed.seal.digest ||
    intent.plan.account.account_id !== accountID ||
    intent.plan.secret_name !== input.secret_name ||
    intent.mode !== input.mode
  )
    throw new Error(invalid);
  return { intent, intent_digest: sealed.intent_digest };
}
