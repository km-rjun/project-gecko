<script lang="ts">
	import { onMount } from 'svelte';
	import { probeHealth, type GatewayHealth } from '#lib/health.js';

	let health = $state<GatewayHealth | null>(null);
	let checkedAt = $state<string>('');

	async function refresh() {
		health = await probeHealth();
		checkedAt = new Date().toLocaleTimeString();
	}

	onMount(refresh);
</script>

<!-- Checkpoint 1 placeholder shell. The real workspace (explorer, tiling, palette) lands in Checkpoint 4. -->
<div class="grid h-full grid-rows-[1fr_var(--statusbar-h)] bg-canvas text-primary">
	<main class="flex items-center justify-center">
		<section class="w-[360px] rounded-ui border border-line bg-panel p-4">
			<h1 class="m-0 text-lg font-medium">{__BRAND_DISPLAY_NAME__}</h1>
			<p class="mt-1 mb-3 text-sm text-muted">Workspace scaffold · checkpoint 1</p>
			<dl class="m-0 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-sm">
				<dt class="text-muted">gateway</dt>
				<dd class="m-0" data-testid="health">
					{#if health === null}
						<span class="text-muted">checking…</span>
					{:else if health.state === 'ok'}
						<span class="text-ok">ok</span>
					{:else}
						<span class="text-error">unreachable ({health.detail})</span>
					{/if}
				</dd>
				<dt class="text-muted">checked</dt>
				<dd class="m-0">{checkedAt || '—'}</dd>
			</dl>
			<button
				class="mt-3 cursor-pointer rounded-ui border border-line-strong bg-input px-2 py-1 text-sm text-primary hover:bg-hover"
				onclick={refresh}>Re-check</button
			>
		</section>
	</main>
	<footer
		class="flex items-center justify-between border-t border-line bg-panel px-2 font-mono text-xs text-muted"
	>
		<span>no session</span>
		<span>gateway {health?.state ?? '…'}</span>
	</footer>
</div>
