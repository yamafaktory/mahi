import { always, eventually, now } from "@antithesishq/bombadil";
import { actions, extract, weighted } from "@antithesishq/bombadil/terminal";
import {
  CharSets,
  lastAction,
  typeFromSet,
} from "@antithesishq/bombadil/terminal/defaults/actions";
export {
  exitSuccess,
  noReplacementChars,
} from "@antithesishq/bombadil/terminal/defaults";

const FOOTER = "Ctrl-Space palette  ? help  q quit";
const PALETTE_HINTS = "↑↓ move  enter run  esc close";
const DIALOG_HINTS = /esc (cancel|close)|enter (close|done|pick)|ctrl-c stop/;

const cells = extract((state) => {
  const grid: string[][] = [];
  for (let index = 0; index < state.grid.size.rows; index++) {
    grid.push(state.grid.row(index).map((cell) => cell.contents));
  }
  return grid;
});

const exited = extract((state) => state.exitStatus !== null);

function rows(): string[] {
  return cells.current.map((row) => row.join(""));
}

function lastTyped(): string {
  const action = lastAction.current;
  return action !== null && "TypeText" in action ? action.TypeText : "";
}

function resized(): boolean {
  const action = lastAction.current;
  return action !== null && "Resize" in action;
}

function paletteEntries(grid: string[][]): string[][] | null {
  const hints = grid.findIndex((row) => row.join("").includes(PALETTE_HINTS));
  if (hints < 0) return null;
  const row = grid[hints];
  const left = row.findIndex((cell, column) => cell === "│" && row[column + 2] === "↑");
  const right = row.findIndex((cell, column) => column > left && cell === "│");
  if (left < 0 || right < 0) return null;
  let top = hints;
  while (top > 0 && grid[top][left] !== "╭") top--;
  const entries: string[][] = [];
  for (let index = top + 1; index < hints; index++) {
    const text = grid[index].slice(left + 1, right).join("").trim();
    if (text !== "") entries.push(text.split(/\s{2,}/));
  }
  return entries;
}

function showsDialog(lines: string[]): boolean {
  return lines.some((line) => DIALOG_HINTS.test(line));
}

function boxesAreWhole(lines: string[]): boolean {
  const count = (line: string, corner: string) => line.split(corner).length - 1;
  return lines.every(
    (line) =>
      count(line, "╭") === count(line, "╮") && count(line, "╰") === count(line, "╯"),
  );
}

function footerIsRight(): boolean {
  const lines = rows();
  if (exited.current || showsDialog(lines)) return true;
  const last = (lines[lines.length - 1] ?? "").trim();
  return last === FOOTER || lines.every((line) => line.trim() === "");
}

export const footerNamesThePaletteHelpAndQuitWhileNoDialogShows = always(
  eventually(footerIsRight).within(2, "seconds"),
);

export const everyPaletteEntryShowsAKeyOfItsOwn = always(() => {
  const entries = paletteEntries(cells.current);
  if (entries === null) return true;
  const keys = entries.map((entry) => entry[entry.length - 1]);
  const keyed = entries.every((entry) => entry.length >= 2);
  return keyed && new Set(keys).size === keys.length;
});

export const escapeClosesThePalette = always(
  now(() => paletteEntries(cells.current) !== null && lastTyped() === "\x1b")
    .implies(eventually(() => paletteEntries(cells.current) === null).within(2, "seconds")),
);

export const everyBoxIsWholeSoonAfterAResize = always(
  now(() => resized() && !exited.current).implies(
    eventually(() => exited.current || boxesAreWhole(rows())).within(2, "seconds"),
  ),
);

export const exploreTheHomeScreen = weighted([
  [30, actions(() => [{ TypeText: { Regexp: "[a-pr-zA-NP-Z0-9?]" } }])],
  [15, actions(() => [{ TypeText: { Regexp: "\\x00" } }])],
  [15, typeFromSet(CharSets.CONTROL_ARROWS)],
  [10, actions(() => [{ TypeText: { Regexp: "\\r" } }])],
  [5, typeFromSet(CharSets.UNICODE_SAFE)],
  [1, actions(() => [{ TypeText: { Regexp: "\\x1b" } }])],
  [1, actions(() => [{ TypeText: { Regexp: "q" } }])],
  [1, actions(() => [{ Resize: { rows: [12, 60], columns: [60, 200] } }])],
]);
