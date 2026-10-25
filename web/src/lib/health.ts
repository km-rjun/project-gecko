/** Result of probing the gateway's unauthenticated health endpoint. */
export type GatewayHealth =
	| { state: 'ok' }
	| { state: 'error'; detail: string };

/** Interprets a `/api/health` response. Only `{"status":"ok"}` with HTTP 200 counts as healthy. */
export function parseHealth(status: number, body: unknown): GatewayHealth {
	if (status !== 200) return { state: 'error', detail: `HTTP ${status}` };
	if (typeof body === 'object' && body !== null && (body as { status?: unknown }).status === 'ok') {
		return { state: 'ok' };
	}
	return { state: 'error', detail: 'unexpected response body' };
}

/** Fetches `/api/health` (same origin; proxied to the gateway by the dev server). */
export async function probeHealth(fetchFn: typeof fetch = fetch): Promise<GatewayHealth> {
	try {
		const res = await fetchFn('/api/health', { headers: { accept: 'application/json' } });
		const body: unknown = await res.json().catch(() => null);
		return parseHealth(res.status, body);
	} catch (e) {
		return { state: 'error', detail: e instanceof Error ? e.message : 'network error' };
	}
}
