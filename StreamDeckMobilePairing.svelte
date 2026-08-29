<script lang="ts">
	import Popup from "./Popup.svelte";
	import { invoke } from "@tauri-apps/api/core";

	export let show = false;

	type PairingInfo = {
		qr_url: string;
		qr_data_url: string;
		address: string;
		legacy_port: number;
		vsd2_port: number;
		token: string;
		workstation_id: string;
		hostname: string;
		public_key_fingerprint: string;
	};

	type PendingPairing = {
		fingerprint: string;
		name: string;
		peer: string;
		approved: boolean;
	};

	let info: PairingInfo | null = null;
	let pending: PendingPairing[] = [];
	let loading = false;
	let error = "";
	let loaded = false;
	let pollTimer: number | undefined;

	$: if (show && !loaded) load();
	$: if (show) startPolling();
	$: if (!show) stopPolling();

	async function load() {
		loading = true;
		error = "";
		try {
			info = await invoke<PairingInfo>("streamdeck_mobile_pairing_info");
			loaded = true;
		} catch (e) {
			error = String(e);
		} finally {
			loading = false;
		}
	}

	async function poll() {
		if (!show) return;
		try {
			pending = await invoke<PendingPairing[]>("streamdeck_mobile_pending_pairings");
		} catch {}
	}

	function startPolling() {
		if (pollTimer !== undefined) return;
		void poll();
		pollTimer = window.setInterval(poll, 250);
	}

	function stopPolling() {
		if (pollTimer !== undefined) {
			window.clearInterval(pollTimer);
			pollTimer = undefined;
		}
	}

	async function resolve(fingerprint: string, approve: boolean) {
		try {
			await invoke("streamdeck_mobile_resolve_pairing", { fingerprint, approve });
			await poll();
		} catch (e) {
			error = String(e);
		}
	}

	async function copyPayload() {
		if (info?.qr_url) await navigator.clipboard?.writeText(info.qr_url);
	}
</script>

<Popup {show} label="Add Stream Deck Mobile">
	<svelte:fragment slot="header">
		<button class="mr-2 my-1 float-right text-xl text-neutral-300" on:click={() => (show = false)} aria-label="Close">✕</button>
		<h2 class="m-2 font-semibold text-xl text-neutral-300">Add Stream Deck Mobile</h2>
	</svelte:fragment>

	<div class="flex flex-col items-center p-4 min-w-[500px]">
		{#if info?.qr_data_url}
			<div class="p-4 bg-white rounded-xl shadow-lg">
				<img src={info.qr_data_url} alt="Stream Deck Mobile pairing QR code" class="w-[420px] h-[420px]" />
			</div>

			<p class="mt-4 text-center text-neutral-200 font-medium">
				Scan this QR code from Stream Deck Mobile.
			</p>

			{#if pending.length > 0}
				{#each pending as pair}
					<div class="mt-4 w-full max-w-[460px] rounded-xl border border-neutral-500 bg-neutral-800 p-4">
						<div class="text-sm font-semibold text-neutral-100">Stream Deck Mobile verification</div>
						<div class="mt-1 text-xs text-neutral-400">
							Compare this 6-character code with the code shown on the phone.
						</div>
						<div class="mt-4 text-center font-mono text-4xl font-semibold tracking-[0.28em] text-neutral-100 select-all">
							{pair.fingerprint.toUpperCase()}
						</div>
						<div class="mt-2 text-center text-xs text-neutral-500">{pair.name} · {pair.peer}</div>
						<div class="mt-4 flex gap-2 justify-end">
							<button class="px-3 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white" on:click={() => resolve(pair.fingerprint, false)}>Reject</button>
							<button class="px-3 py-2 rounded-lg bg-green-600 hover:bg-green-500 text-white" on:click={() => resolve(pair.fingerprint, true)}>Approve</button>
						</div>
					</div>
				{/each}
			{/if}

			<div class="mt-3 w-full max-w-[460px] p-3 rounded-lg bg-neutral-800 border border-neutral-700">
				<div class="text-xs text-neutral-400 mb-1">QR URL</div>
				<div class="text-xs text-neutral-300 break-all font-mono select-text">{info.qr_url}</div>
			</div>

			<button class="mt-3 px-3 py-1.5 text-sm text-neutral-200 bg-neutral-700 hover:bg-neutral-600 border border-neutral-600 rounded-lg" on:click={copyPayload}>Copy QR URL</button>

			<div class="mt-4 text-xs text-neutral-500 text-center space-y-1">
				<div>{info.hostname} · {info.address}</div>
				<div>VSD2: {info.address}:{info.vsd2_port}</div>
				<div>Workstation: {info.workstation_id}</div>
			</div>
		{:else if loading}
			<p class="p-10 text-neutral-400">Generating pairing QR…</p>
		{:else}
			<p class="p-10 text-red-400">{error || "Unable to generate pairing QR."}</p>
		{/if}
	</div>
</Popup>
