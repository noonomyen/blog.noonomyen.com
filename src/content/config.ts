import { defineCollection, z } from "astro:content";
import type { BaseSchema, CollectionConfig } from "astro:content";

const postsCollectionSchema: BaseSchema = {
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
};

const postsCollection: CollectionConfig<typeof postsCollectionSchema> =
	defineCollection(postsCollectionSchema);

export const collections: Record<string, typeof postsCollection> = {
	posts: postsCollection,
};
