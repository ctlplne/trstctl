import { req } from "./apiTransport";
import type { Brand } from "./api-types.gen";

// MSP-1: the white-label brand the control plane resolves for this host.
// Public on purpose: the sign-in page is branded before anyone has a session.
export const getPublicBrand = () => req<Brand>("/api/v1/brand");
