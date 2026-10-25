// See https://svelte.dev/docs/kit/types#app.d.ts
declare global {
	/** Product display name injected from branding.toml by vite.config.ts. */
	const __BRAND_DISPLAY_NAME__: string;

	namespace App {
		// interface Error {}
		// interface Locals {}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

export {};
