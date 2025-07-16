import { defineCollection, z } from "astro:content";

// Temporary fix: isolated declaration type checking error
// The impact is that InferEntrySchema<"posts"> becomes unusable.

const postsCollection: import("astro/content/config").CollectionConfig<
	import("astro/content/config").BaseSchema
> = defineCollection({
	schema: z.object({
		title: z.string(),
		published: z.date(),
		updated: z.date().optional(),
		draft: z.boolean().optional().default(false),
		description: z.string().optional().default(""),
		image: z.string().optional().default(""),
		ogimage: z.string().optional().default(""),
		tags: z.array(z.string()).optional().default([]),
		category: z.string().optional().default(""),
		lang: z.string().optional().default(""),

		/* For internal use */
		prevTitle: z.string().default(""),
		prevSlug: z.string().default(""),
		nextTitle: z.string().default(""),
		nextSlug: z.string().default(""),
	}),
});

export const collections: { posts: typeof postsCollection } = {
	posts: postsCollection,
};
