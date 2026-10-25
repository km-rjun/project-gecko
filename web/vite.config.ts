import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import tailwindcss from '@tailwindcss/vite';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';

/** Product display name from ../branding.toml (single rename point). */
function brandDisplayName(): string {
	const path = fileURLToPath(new URL('../branding.toml', import.meta.url));
	const match = readFileSync(path, 'utf8').match(/^\s*display_name\s*=\s*"([^"]+)"/m);
	if (!match) throw new Error(`branding.toml: display_name not found (${path})`);
	return match[1];
}

/** Gateway used by the dev server proxy. */
const gatewayUrl = process.env.GATEWAY_DEV_URL ?? 'http://127.0.0.1:8443';

export default defineConfig({
	define: {
		__BRAND_DISPLAY_NAME__: JSON.stringify(brandDisplayName())
	},
	server: {
		host: '127.0.0.1',
		port: 5173,
		strictPort: true,
		proxy: {
			'/api': { target: gatewayUrl, ws: true, changeOrigin: false }
		}
	},
	plugins: [
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			// SPA: no SSR, every route served by the fallback page (embedded into the gateway in CP7).
			adapter: adapter({ fallback: 'index.html', strict: true })
		})
	],
	test: {
		expect: { requireAssertions: true },
		projects: [
			{
				extends: './vite.config.ts',
				test: {
					name: 'unit',
					environment: 'node',
					include: ['src/**/*.{test,spec}.{js,ts}'],
					exclude: ['src/**/*.svelte.{test,spec}.{js,ts}']
				}
			}
		]
	}
});
