
function fib(n) {
  if (n <= 1) return n;
  return fib(n - 1) + fib(n - 2);
}
// Just calculate, no output effectively
// If this runs without error, we can measure the time
fib(35);
