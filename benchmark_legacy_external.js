
import { porffor_compile } from './porffor_blob_c.js';
import * as std from 'std';

console.log("Compiling Fibonacci benchmark to C...");
const code = `
function fib(n) {
  if (n <= 1) return n;
  return fib(n - 1) + fib(n - 2);
}
console.log(fib(40));
`;

try {
  const startParam = Date.now();
  const cCode = porffor_compile(code, ['c']);
  const endParam = Date.now();
  console.log(`Compilation took ${endParam - startParam}ms`);

  if (typeof cCode !== 'string' || cCode.length === 0) {
    throw new Error("Compilation failed: Empty output");
  }

  const file = std.open("out.c", "w");
  file.puts(cCode);
  file.close();
  console.log(`Wrote ${cCode.length} bytes to out.c`);
} catch (e) {
  console.log("Error:", e);
  std.exit(1);
}
