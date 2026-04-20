import { porffor_compile } from './porffor_blob_c.js';

console.log("Compiling...");
const code = `
function fib(n) {
  if (n <= 1) return n;
  return fib(n - 1) + fib(n - 2);
}
console.log(fib(10));
`;

try {
  const result = porffor_compile(code, ['c']);
  console.log("Compiled.");
  console.log("Result keys:", Object.keys(result));
} catch (e) {
  console.log("Error:", e);
}
