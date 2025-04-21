export const prerender = false;

import type { APIRoute } from "astro";

export const GET: APIRoute = async (_) => {
	return new Response("ok", { status: 200 });
};
