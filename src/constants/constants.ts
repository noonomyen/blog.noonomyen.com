export const UNCATEGORIZED = "__uncategorized__";

export const PAGE_SIZE = 8;

export const LIGHT_MODE = "light",
	DARK_MODE = "dark",
	AUTO_MODE = "auto";
export type ThemeMode = typeof LIGHT_MODE | typeof DARK_MODE | typeof AUTO_MODE;
export const DEFAULT_THEME: ThemeMode = AUTO_MODE;

// Banner height unit: vh
export const BANNER_HEIGHT = 35;
export const BANNER_HEIGHT_EXTEND = 30;
export const BANNER_HEIGHT_HOME: number = BANNER_HEIGHT + BANNER_HEIGHT_EXTEND;

// The height the main panel overlaps the banner, unit: rem
export const MAIN_PANEL_OVERLAPS_BANNER_HEIGHT = 3.5;

// Page width: rem
export const PAGE_WIDTH = 75;
