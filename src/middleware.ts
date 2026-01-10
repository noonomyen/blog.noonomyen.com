import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineMiddleware } from "astro:middleware";

const redirectsPath = path.resolve(
	path.dirname(fileURLToPath(import.meta.url)),
	"../public/_redirects",
);

type RedirectRule = {
	from: string;
	to: string;
	status: number;
};

const parseRedirects = (text: string): RedirectRule[] => {
	return text
		.split("\n")
		.map((line) => line.trim())
		.filter((line) => line.length > 0 && !line.startsWith("#"))
		.map((line) => line.split(/\s+/))
		.filter((parts) => parts.length >= 2)
		.map((parts) => ({
			from: parts[0],
			to: parts[1],
			status: Number(parts[2] ?? 302),
		}))
		.filter((rule) => Number.isFinite(rule.status));
};

export const onRequest = defineMiddleware(async (context, next) => {
	if (!import.meta.env.DEV) {
		return next();
	}

	let rules: RedirectRule[] = [];
	try {
		const text = await readFile(redirectsPath, "utf8");
		rules = parseRedirects(text);
	} catch {
		return next();
	}

	const pathname = new URL(context.request.url).pathname;
	const match = rules.find((rule) => rule.from === pathname);
	if (match) {
		const target = new URL(match.to, context.request.url);
		return Response.redirect(target, match.status);
	}

	return next();
});
