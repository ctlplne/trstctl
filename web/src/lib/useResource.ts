import { useEffect, useState } from "react";

export interface Resource<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  errorCause: unknown | null;
}

/** useResource loads async data once on mount and tracks loading/error state. */
export function useResource<T>(loader: () => Promise<T>): Resource<T> {
  const [state, setState] = useState<Resource<T>>({ data: null, loading: true, error: null, errorCause: null });
  useEffect(() => {
    let active = true;
    loader()
      .then((data) => active && setState({ data, loading: false, error: null, errorCause: null }))
      .catch((err) => active && setState({ data: null, loading: false, error: String(err), errorCause: err }));
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return state;
}
