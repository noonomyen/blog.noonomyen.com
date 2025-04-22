import path from "node:path";

export function isLocalSrc(src: string): boolean {
	return !(
		src.startsWith("/") ||
		src.startsWith("http") ||
		src.startsWith("https") ||
		src.startsWith("data:")
	);
}

export async function getImageLocalMetadata(
	src: string,
	basePath: string,
): Promise<ImageMetadata> {
	const files = import.meta.glob<ImageMetadata>("../**", {
		import: "default",
	});
	const normalizedPath = path
		.normalize(path.join("../", basePath, src))
		.replace(/\\/g, "/");
	const file = files[normalizedPath];
	if (!file) {
		console.error(
			`\n[ERROR] Image file not found, src:${src} basePath:${basePath}`,
		);
	}

	return await file();
}
