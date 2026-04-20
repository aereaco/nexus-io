print ">> [Test] Putting object..."
storage put "test-bucket" "hello.txt" "Hello from Sovereign Cloud!"

print ">> [Test] Getting object..."
let content = (storage get "test-bucket" "hello.txt")
print $"Content: ($content)"

if ($content == "Hello from Sovereign Cloud!") {
    print ">> [Test] SUCCESS: Zero-copy integration working!"
} else {
    print ">> [Test] FAIL: Content mismatch"
    exit 1
}
