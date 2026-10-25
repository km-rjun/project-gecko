import { describe, expect, it } from 'vitest';
import { parseHealth, probeHealth } from './health';

describe('parseHealth', () => {
	it('accepts only HTTP 200 with status ok', () => {
		expect(parseHealth(200, { status: 'ok' })).toEqual({ state: 'ok' });
	});
	it('rejects non-200', () => {
		expect(parseHealth(502, { status: 'ok' })).toEqual({ state: 'error', detail: 'HTTP 502' });
	});
	it('rejects unexpected bodies', () => {
		expect(parseHealth(200, null).state).toBe('error');
		expect(parseHealth(200, { status: 'degraded' }).state).toBe('error');
	});
});

describe('probeHealth', () => {
	it('reports network failures as errors', async () => {
		const failing = (() => Promise.reject(new Error('connection refused'))) as unknown as typeof fetch;
		expect(await probeHealth(failing)).toEqual({ state: 'error', detail: 'connection refused' });
	});
});
