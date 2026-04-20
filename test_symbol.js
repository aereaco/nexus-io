try {
  console.log(`Symbol: ${typeof Symbol}`);
  console.log(`Symbol.iterator: ${typeof Symbol.iterator}`);
  const arr = [1, 2, 3];
  console.log(`Array iterator: ${typeof arr[Symbol.iterator]}`);
} catch (e) {
  console.log(`Error checking Symbol: ${e}`);
}
