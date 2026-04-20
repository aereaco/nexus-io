try {
  console.log(`TextEncoder: ${typeof TextEncoder}`);
  console.log(`TextDecoder: ${typeof TextDecoder}`);
} catch (e) {
  console.log(`Error checking globals: ${e}`);
}

try {
  console.log(`process: ${typeof process}`);
  console.log(`performance: ${typeof performance}`);
} catch (e) {
  console.log(`Error checking globals: ${e}`);
}
