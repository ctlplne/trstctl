/** Reusable defaults an application view hands to the destination form
 * (A244): an existing certificate's owner, profile and CA travel in the link,
 * so the next certificate starts from the same choices. */
export type EndpointBindingDefaults = { owner_id?: string; profile_name?: string; issuer_key?: string };

const searchKeys = { owner_id: "bind_owner", profile_name: "bind_profile", issuer_key: "bind_issuer" } as const;

export function endpointBindingDefaultsHref(defaults: { owner_id?: string; profile_name?: string; issuer_source?: string; issuer_id?: string }): string | null {
  const search = new URLSearchParams();
  if (defaults.owner_id) search.set(searchKeys.owner_id, defaults.owner_id);
  if (defaults.profile_name) search.set(searchKeys.profile_name, defaults.profile_name);
  if (defaults.issuer_source && defaults.issuer_id) search.set(searchKeys.issuer_key, `${defaults.issuer_source}:${defaults.issuer_id}`);
  const query = search.toString();
  return query ? `/connectors?${query}` : null;
}

export function endpointBindingDefaultsFromSearch(search: URLSearchParams): EndpointBindingDefaults | undefined {
  const defaults: EndpointBindingDefaults = {};
  for (const field of Object.keys(searchKeys) as (keyof EndpointBindingDefaults)[]) {
    const value = search.get(searchKeys[field])?.trim();
    if (value) defaults[field] = value;
  }
  return Object.keys(defaults).length > 0 ? defaults : undefined;
}
