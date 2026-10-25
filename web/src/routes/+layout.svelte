<script lang="ts">
	import '../app.css';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();
</script>

<svelte:head>
	<title>{__BRAND_DISPLAY_NAME__}</title>
</svelte:head>

{@render children()}
