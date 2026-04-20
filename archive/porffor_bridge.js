import compile from './node_modules/porffor/compiler/index.js';

export const porffor_compile = (code) => {
  // Mocking minimal prefs for Porffor
  globalThis.Prefs = {
    O: 1, // Optimization level 1
  };

  // We try to compile. Returns { wasm: Uint8Array, ... }
  return compile(code);
};
