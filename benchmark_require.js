function fib(n) {
  if (n <= 1) return n;
  return fib(n - 1) + fib(n - 2);
}

const n = 35;
const start = Date.now();
const result = fib(n);
const end = Date.now();

console.log(`Fibonacci(${n}) = ${result}`);
console.log(`Execution time: ${end - start}ms`);
