// Vite resolves `?raw` imports to the file's text. Declared here, for that
// suffix only, rather than pulling in all of vite/client's globals: the
// UTC guard test reads page sources this way (ADR-079).
declare module "*?raw" {
  const content: string;
  export default content;
}
