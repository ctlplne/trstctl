import blue from "./desktop-blue.json";
export const desktopLines = (frame = 1) =>
  Array.from({ length: 13 }, (_, row) => ({
    e: "desktop",
    c: 1,
    t: (frame - 1) * 1000,
    d: blue.trim(),
    desktop: { codec: "png", frame, width: 320, height: 208, y: row * 16, rows: 16, last: row === 12 },
  }));
