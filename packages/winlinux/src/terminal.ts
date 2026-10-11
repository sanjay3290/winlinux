// Server text on a terminal. C0 controls (except tab), DEL and C1
// controls let text clear the screen, move the cursor, rewrite a line or
// set the window title. Each becomes a visible \xNN. With `newlines`, a
// line break (\n, or \r\n) is kept, for text that spans lines.
const CONTROLS = /[\x00-\x08\x0a-\x1f\x7f-\x9f]/g;
const CONTROLS_BUT_NEWLINE = /[\x00-\x08\x0b-\x1f\x7f-\x9f]/g;

const visible = (c: string) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`;

export function terminalSafe(text: string, opts: { newlines?: boolean } = {}): string {
  return opts.newlines
    ? text.replace(/\r\n/g, '\n').replace(CONTROLS_BUT_NEWLINE, visible)
    : text.replace(CONTROLS, visible);
}

// Any control character, tab and newline included.
export const hasControls = (text: string): boolean => /[\x00-\x1f\x7f-\x9f]/.test(text);
