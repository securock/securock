#!/usr/bin/env node
// Regenerate docs/assets/logo.svg: SECUROCK set in Barlow Black Italic.
//
// The text is converted to outlines, so the SVG renders the same everywhere
// without the font installed. The output is deterministic.
//
//   cd scripts && pnpm install --frozen-lockfile && node make-logo.mjs [--font Barlow-BlackItalic.ttf]
//
// Without --font it uses the static Barlow 900 italic from the pinned
// @fontsource/barlow package (SIL OFL 1.1), so no network is needed.
//
// Spacing: Barlow has no kerning for these pairs, so each pair is placed from
// the white space its two facing sides enclose (flat stems get more, round and
// open sides less, with the depth capped, as in HT Letterspacer). ADJUST then
// matches the blurred grey of every pair to Barlow's own H-H / O-O reference
// pairs, and MIN_GAP keeps any pair from closing in tighter than the font's
// round-round distance. TRACKING opens every pair evenly for display use.
// Options: --tracking 0.01, --flat-gap, --depth, --weight, --min-gap,
// --adjust SE=0.01,EC=-0.005, --text, --native, --debug.
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import opentype from 'opentype.js';

const DEFAULT_FONT = fileURLToPath(
	import.meta.resolve('@fontsource/barlow/files/barlow-latin-900-italic.woff'),
);
const TEXT = process.argv.includes('--text')
	? process.argv[process.argv.indexOf('--text') + 1]
	: 'SECUROCK';
const HEIGHT = 72; // cap height in output units
const PAD = 12;
const FLAT_GAP = 0.09; // gap between two flat sides (stem to stem), in em
const DEPTH = 0.1; // how deep a notch or curve counts as white space, in em
const WEIGHT = 0.35; // how much of that notch space is taken off the gap
const MIN_GAP = 0.058; // letters never come closer than this at any row, in em
const TRACKING = 0; // extra space between every pair, in em (display sizes: try 0.01)
const ROWS = 96; // horizontal scanlines used to measure outlines
// Hand tuning per pair after the automatic pass, in em: positive widens,
// negative tightens.
const ADJUST = {
	EC: -0.014,
	UR: -0.012,
};
// Pairs whose open or round shapes would have to go closer than MIN_GAP to match
// the grey of Barlow's own H-H / O-O reference pairs. They sit exactly at MIN_GAP.
const AT_FLOOR = ['SE', 'CU', 'RO', 'OC', 'CK'];

const args = process.argv.slice(2);
const opt = (name) => {
	const i = args.indexOf(name);
	return i >= 0 ? args[i + 1] : undefined;
};
const num = (name, fallback) => (opt(name) === undefined ? fallback : Number(opt(name)));
const adjust = { ...ADJUST };
for (const part of (opt('--adjust') ?? '').split(',').filter(Boolean)) {
	const [pair, value] = part.split('=');
	adjust[pair] = Number(value);
}
const native = args.includes('--native');
const tracking = num('--tracking', TRACKING);
const flatGap = num('--flat-gap', FLAT_GAP);
const depth = num('--depth', DEPTH);
const weight = num('--weight', WEIGHT);
const minGap = num('--min-gap', MIN_GAP);
const fontPath = opt('--font');
const outPath = opt('--out') ?? fileURLToPath(new URL('../docs/assets/logo.svg', import.meta.url));

const bytes = await readFile(fontPath ?? DEFAULT_FONT);
const font = opentype.parse(
	bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
);

const scale = HEIGHT / font.tables.os2.sCapHeight;
const em = font.unitsPerEm;
const capH = font.tables.os2.sCapHeight;
// Horizontal shift per unit of height along a slanted stem. Profiles are
// measured with this removed so a straight italic stem counts as a flat side.
const slant = Math.tan((-font.tables.post.italicAngle * Math.PI) / 180);

// The font ships no kerning for these pairs, so space them optically. Each
// glyph is measured on a set of scanlines (left and right outline per row).
// Because both neighbours are measured on the same rows, the gap per row is
// the same whether or not the slant is removed.
function profile(glyph) {
	const segs = [];
	let cur = null;
	let start = null;
	const pt = (x, y) => [x, -y];
	for (const c of glyph.getPath(0, 0, em).commands) {
		if (c.type === 'M') {
			cur = start = pt(c.x, c.y);
		} else if (c.type === 'L') {
			const n = pt(c.x, c.y);
			segs.push([cur, n]);
			cur = n;
		} else if (c.type === 'Q' || c.type === 'C') {
			const ctrl = c.type === 'Q' ? [pt(c.x1, c.y1)] : [pt(c.x1, c.y1), pt(c.x2, c.y2)];
			const end = pt(c.x, c.y);
			const pts = [cur, ...ctrl, end];
			let prev = cur;
			for (let i = 1; i <= 24; i++) {
				const t = i / 24;
				let p = pts;
				while (p.length > 1) {
					p = p
						.slice(1)
						.map((q, k) => [p[k][0] + (q[0] - p[k][0]) * t, p[k][1] + (q[1] - p[k][1]) * t]);
				}
				segs.push([prev, p[0]]);
				prev = p[0];
			}
			cur = end;
		} else if (c.type === 'Z') {
			segs.push([cur, start]);
			cur = start;
		}
	}
	const left = [];
	const right = [];
	for (let r = 0; r < ROWS; r++) {
		const y = ((r + 0.5) / ROWS) * capH;
		let lo = Infinity;
		let hi = -Infinity;
		for (const [[x0, y0], [x1, y1]] of segs) {
			if ((y0 - y) * (y1 - y) > 0 || y0 === y1) continue;
			const x = x0 + ((y - y0) / (y1 - y0)) * (x1 - x0);
			lo = Math.min(lo, x);
			hi = Math.max(hi, x);
		}
		left.push(lo - y * slant);
		right.push(hi - y * slant);
	}
	return { left, right };
}

// White space a side contributes, in em: the mean distance from the outermost
// point of that side to its outline, with each row capped at `depth` so a deep
// notch (E, C, K) does not count as more than a shallow curve. Flat sides give
// 0, round and open sides give more, so they get a smaller sidebearing.
function sideArea(p) {
	const L = Math.min(...p.left);
	const R = Math.max(...p.right);
	let left = 0;
	let right = 0;
	for (let r = 0; r < ROWS; r++) {
		left += Math.min(p.left[r] - L, depth * em);
		right += Math.min(R - p.right[r], depth * em);
	}
	return { L, R, left: left / ROWS, right: right / ROWS };
}

const glyphs = [...TEXT].map((ch) => font.charToGlyph(ch));
const profiles = glyphs.map(profile);
const areas = profiles.map(sideArea);
const placed = [{ glyph: glyphs[0], x: 0 }];
for (let i = 1; i < glyphs.length; i++) {
	const a = areas[i - 1];
	const b = areas[i];
	// Outermost point to outermost point, so that the white space between the
	// two letters (gap plus both sides' notches) is the same for every pair.
	const extGap = flatGap * em - weight * (a.right + b.left);
	const byArea = placed[i - 1].x + a.R + extGap - b.L;
	// Balanced spacing must not make strokes collide where the gap is tight.
	let tight = Infinity;
	for (let r = 0; r < ROWS; r++) {
		tight = Math.min(tight, profiles[i].left[r] - profiles[i - 1].right[r]);
	}
	const byGuard = placed[i - 1].x + minGap * em - tight;
	const hand = (adjust[TEXT[i - 1] + TEXT[i]] ?? 0) * em;
	const pair = TEXT[i - 1] + TEXT[i];
	const spaced = AT_FLOOR.includes(pair) ? byGuard : Math.max(byArea + hand, byGuard);
	const x = native
		? placed[i - 1].x + glyphs[i - 1].advanceWidth + tracking * em
		: spaced + tracking * em;
	placed.push({ glyph: glyphs[i], x });
}

if (args.includes('--debug')) {
	// Per-pair report in em/1000: gap between outermost points, tightest row,
	// and the guard (true when MIN_GAP, not the area rule, set the position).
	for (let i = 1; i < placed.length; i++) {
		const g = [];
		for (let r = 0; r < ROWS; r++) {
			g.push(placed[i].x + profiles[i].left[r] - (placed[i - 1].x + profiles[i - 1].right[r]));
		}
		const ext = placed[i].x + areas[i].L - (placed[i - 1].x + areas[i - 1].R);
		console.log(
			TEXT[i - 1] + TEXT[i],
			'ext',
			Math.round(ext),
			'min',
			Math.round(Math.min(...g)),
			'notch',
			Math.round(areas[i - 1].right + areas[i].left),
		);
	}
}

let minX = Infinity;
let maxX = -Infinity;
for (const { glyph, x: ox } of placed) {
	const b = glyph.getPath(ox, 0, em).getBoundingBox();
	minX = Math.min(minX, b.x1);
	maxX = Math.max(maxX, b.x2);
}

// getPath already flips y; baseline sits at PAD + HEIGHT.
const d = placed
	.map(({ glyph, x: ox }) =>
		glyph.getPath(PAD + (ox - minX) * scale, PAD + HEIGHT, font.unitsPerEm * scale).toPathData(2),
	)
	.join('');

const w = Math.round((maxX - minX) * scale + 2 * PAD);
const h = HEIGHT + 2 * PAD;

// One flat blue in both light and dark mode.
const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="Securock">
  <title>Securock</title>
  <path fill="#2563eb" d="${d}"/>
</svg>
`;
await writeFile(outPath, svg);
