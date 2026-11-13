#!/usr/bin/env node
// Regenerate docs/assets/logo.svg: SECUROCK set in Barlow ExtraBold (800, upright).
//
// The text is converted to outlines, so the SVG renders the same everywhere
// without the font installed. The output is deterministic.
//
//   cd scripts && pnpm install --frozen-lockfile && node make-logo.mjs [--font Barlow-ExtraBold.ttf]
//
// Without --font it uses the static Barlow 800 from the pinned
// @fontsource/barlow package (SIL OFL 1.1), so no network is needed.
//
// Spacing: Barlow has no kerning for these pairs, so each pair is placed from
// the white space on its two facing sides, using the approach of HT Letterspacer
// (Huerta Tipografica): for every side, measure how far the outline sits from the
// side's extreme point on horizontal scanlines across the cap height, clamp that
// depth, close open counters at 45 degrees, and take the mean. The gap between
// the two extreme points is then
//
//   gap = BASE_GAP - SIDE_WEIGHT * (white area of right side + white area of left side)
//
// so a flat side (H, E, K stem) gets a wider gap and a round or open side (O, C, S)
// a narrower one. BASE_GAP and SIDE_WEIGHT are not hand-picked: they are the
// least-squares fit of this model to the spacing Barlow ExtraBold itself uses for
// its 287 uppercase pairs that have no kerning (B C D E F G H K L M N O P Q R S T U).
// The fit reproduces them with a root-mean-square error of 3.6 per 1000 em, and a
// uniform minimum distance between letters made it worse, so none is imposed
// beyond a collision guard. For another weight, fit the two constants again.
// Options: --tracking 0.01, --adjust SE=0.005,EC=-0.005, --text, --native, --debug.
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import opentype from 'opentype.js';

const DEFAULT_FONT = fileURLToPath(
	import.meta.resolve('@fontsource/barlow/files/barlow-latin-800-normal.woff'),
);
const TEXT = process.argv.includes('--text')
	? process.argv[process.argv.indexOf('--text') + 1]
	: 'SECUROCK';
const HEIGHT = 72; // cap height in output units
const PAD = 12;
const ROWS = 96; // horizontal scanlines used to measure outlines
const DEPTH = 0.1; // deepest notch or curve that counts as white space, in em
const SLOPE = 1; // open counters close at this slope (1 = 45 degrees)
const BASE_GAP = 0.0971; // gap between two flat sides, in em (fitted)
const SIDE_WEIGHT = 0.395; // how much of a side's white area narrows the gap (fitted)
const GUARD = 0.04; // letters never come closer than this at any row, in em
const TRACKING = 0; // extra space between every pair, in em (display sizes: try 0.01)
// Hand tuning per pair after the model, in em: positive widens, negative tightens.
const ADJUST = {};

const args = process.argv.slice(2);
const opt = (name) => {
	const i = args.indexOf(name);
	return i >= 0 ? args[i + 1] : undefined;
};
const adjust = { ...ADJUST };
for (const part of (opt('--adjust') ?? '').split(',').filter(Boolean)) {
	const [pair, value] = part.split('=');
	adjust[pair] = Number(value);
}
const native = args.includes('--native');
const tracking = opt('--tracking') === undefined ? TRACKING : Number(opt('--tracking'));
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

// Left and right outline x for each scanline across the cap height.
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
	return { left, right, L: Math.min(...left), R: Math.max(...right) };
}

// Mean white depth of one side, in em units: each row's distance from the side's
// extreme point, clamped to DEPTH and with counters closed at SLOPE.
function whiteDepth(p, side) {
	const step = capH / ROWS;
	const d = p[side].map((x) => Math.min(side === 'right' ? p.R - x : x - p.L, DEPTH * em));
	for (let i = 1; i < d.length; i++) d[i] = Math.min(d[i], d[i - 1] + SLOPE * step);
	for (let i = d.length - 2; i >= 0; i--) d[i] = Math.min(d[i], d[i + 1] + SLOPE * step);
	return d.reduce((s, v) => s + v, 0) / d.length;
}

const glyphs = [...TEXT].map((ch) => font.charToGlyph(ch));
const profiles = glyphs.map(profile);
const white = profiles.map((p) => ({ left: whiteDepth(p, 'left'), right: whiteDepth(p, 'right') }));
const placed = [{ glyph: glyphs[0], x: 0 }];
for (let i = 1; i < glyphs.length; i++) {
	const a = profiles[i - 1];
	const b = profiles[i];
	const pair = TEXT[i - 1] + TEXT[i];
	const gap =
		BASE_GAP * em - SIDE_WEIGHT * (white[i - 1].right + white[i].left) + (adjust[pair] ?? 0) * em;
	let x = placed[i - 1].x + a.R + gap - b.L;
	// The model must not make strokes collide where the gap is tight.
	let tight = Infinity;
	for (let r = 0; r < ROWS; r++) tight = Math.min(tight, b.left[r] - a.right[r]);
	x = Math.max(x, placed[i - 1].x + GUARD * em - tight);
	if (native) x = placed[i - 1].x + glyphs[i - 1].advanceWidth;
	placed.push({ glyph: glyphs[i], x: x + tracking * em });
}

if (args.includes('--debug')) {
	// Per-pair report in 1/1000 em: gap between the extreme points, the tightest
	// row, and the white area the two facing sides contribute.
	for (let i = 1; i < placed.length; i++) {
		const g = [];
		for (let r = 0; r < ROWS; r++) {
			g.push(placed[i].x + profiles[i].left[r] - (placed[i - 1].x + profiles[i - 1].right[r]));
		}
		const ext = placed[i].x + profiles[i].L - (placed[i - 1].x + profiles[i - 1].R);
		console.log(
			TEXT[i - 1] + TEXT[i],
			'gap',
			Math.round(ext),
			'tightest',
			Math.round(Math.min(...g)),
			'white',
			Math.round(white[i - 1].right + white[i].left),
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

// Flat blue; dark mode shifts it lighter so it keeps contrast on a dark page.
const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="Securock">
  <title>Securock</title>
  <path fill="#2563eb" d="${d}"/>
</svg>
`;
await writeFile(outPath, svg);
