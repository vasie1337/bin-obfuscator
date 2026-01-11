# Testing Strategy

Comprehensive test suite for the binary obfuscator, ensuring all obfuscation passes preserve program functionality.

## Test Architecture

### Test Binary (`crates/test-binary`)

A Rust program designed to exercise all obfuscation transformations. Contains 64+ test cases covering:

#### Arithmetic Operations
- **Addition/Subtraction**: Basic and overflow scenarios
- **Multiplication**: Standard and power-of-two optimizations
- **Division/Modulo**: With zero checks
- **Increment/Decrement**: Single and loop patterns

#### Bitwise Operations
- **Basic**: AND, OR, XOR, NOT
- **Shifts**: Left and right shifts
- **Complex**: Compound operations like `(a & b) | (c ^ a)`
- **Bit Counting**: Population count patterns

#### Control Flow
- **Simple Conditionals**: Single if/else
- **Nested Conditionals**: Multiple levels of nesting
- **Multiple Branches**: Switch-like patterns
- **Early Returns**: Multiple exit points
- **Match Patterns**: Rust match statements (potential jump tables)

#### Loops
- **Simple Loops**: While and for loops
- **Nested Loops**: Multiple nesting levels
- **Break/Continue**: Early exit and skip patterns
- **Recursion**: Fibonacci and factorial

#### Arrays & Memory
- **Array Access**: Indexing operations
- **Array Iteration**: Sum, max, reverse
- **Pointer Arithmetic**: LEA-heavy operations
- **Struct Access**: Multi-field structures

#### Edge Cases
- **Zero Operations**: Comparisons with zero
- **Overflow/Underflow**: Wrapping arithmetic
- **Negative Numbers**: Sign handling
- **All Comparisons**: <, <=, >, >=, ==, !=
- **Deep Nesting**: Nested blocks and expressions

### Integration Tests (`crates/cli/tests`)

#### `test_original_binary_passes_all_tests`
Verifies the unobfuscated test binary passes all its internal tests. Ensures baseline functionality.

**Expectations**:
- All 64+ tests pass (excluding match pattern tests which may invoke jump-table functions)
- Exit code 0
- Output contains "RESULT: SUCCESS"

#### `test_obfuscation_preserves_functionality`
The main integration test. Obfuscates the binary and verifies identical output.

**Steps**:
1. Build test-binary
2. Run original binary, capture output
3. Obfuscate binary
4. Run obfuscated binary, capture output
5. Compare outputs (must be identical)

**Verifications**:
- Original binary passes all tests
- Obfuscated binary passes all tests
- Outputs match exactly
- Both exit with code 0

#### `test_obfuscation_increases_binary_size`
Verifies obfuscation produces larger binaries.

**Expectations**:
- Obfuscated binary > 10% larger than original
- Typical increase: 20-50%

#### `test_obfuscation_with_verbose_logging`
Tests obfuscation with logging enabled (integration test for error handling).

#### `test_multiple_obfuscation_runs_consistent`
Verifies multiple obfuscation runs produce consistent results.

**Expectations**:
- Size variation < 20% (allows for randomization)
- Both runs complete successfully

#### `test_obfuscated_binary_output_format`
Verifies obfuscated binary produces well-formed output.

**Expectations**:
- Contains test markers ([PASS]/[FAIL])
- Contains result summary
- At least some tests pass

## Test Coverage by Pass

### Arithmetic Pass
**Tested by**:
- All array operations (LEA chains)
- Pointer arithmetic in `array_reverse_sum`, `array_index`
- Complex math operations
- Struct field access (`Point`)

**What's tested**:
- LEA displacement splitting
- Multi-instruction LEA chains
- Compensating arithmetic

### Stack Pass
**Tested by**:
- All function calls (PUSH/POP operations)
- `nested_calls` - multiple stack frames
- `deep_call_chain` - deep call stacks
- Recursive functions (`fibonacci`, `factorial`)

**What's tested**:
- PUSH → MOV + LEA expansion
- POP → MOV + LEA expansion
- Stack frame preservation

### Control Flow Pass
**Tested by**:
- All function calls
- Recursive calls
- Nested function calls

**What's tested**:
- Call instruction obfuscation
- Return address manipulation
- Call target preservation

### Opaque Predicates Pass
**Tested by**:
- All functions (noise inserted between instructions)
- Complex operations provide more insertion opportunities

**What's tested**:
- Dead store insertion
- Useless arithmetic chains
- Stack reference obfuscation
- Semantic preservation

## Running Tests

### Run all tests
```bash
cargo test
```

### Run integration tests only
```bash
cargo test --test integration_test
```

### Run with verbose output
```bash
cargo test -- --nocapture
```

### Run specific test
```bash
cargo test test_obfuscation_preserves_functionality
```

## Expected Output

### Successful Test Run
```
test test_original_binary_passes_all_tests ... ok
test test_obfuscation_preserves_functionality ... ok
test test_obfuscation_increases_binary_size ... ok
test test_obfuscation_with_verbose_logging ... ok
test test_multiple_obfuscation_runs_consistent ... ok
test test_obfuscated_binary_output_format ... ok

test result: ok. 6 passed; 0 failed
```

### Test Binary Output (Example)
```
[PASS] add_i32(5, 3) == 8
[PASS] multiply_i32(6, 7) == 42
[PASS] fibonacci(7) == 13
[PASS] nested_conditions(1, 1, 1) == 3
...
=== RESULT: SUCCESS (75 tests passed) ===
```

## Adding New Tests

### To test binary (`main.rs`)
1. Add new `#[inline(never)]` function
2. Add test case to `main()` using `runner.run()`
3. Use `black_box()` to prevent optimization

```rust
#[inline(never)]
fn my_function(x: i32) -> i32 {
    x + 1
}

// In main():
runner.run("my_function(5) == 6", || {
    black_box(my_function(black_box(5))) == 6
});
```

### To integration tests
Add new test function to `integration_test.rs`:

```rust
#[test]
fn test_my_scenario() {
    build_package("test-binary");
    // ... test implementation
}
```

## Debugging Failed Tests

### If original binary fails
- Check test logic in `main.rs`
- Run `cargo build --package test-binary`
- Run `.\target\debug\test-binary.exe` directly

### If obfuscated binary fails
- Enable verbose logging
- Check which specific tests fail
- Look for patterns (e.g., all arithmetic tests fail)
- May indicate issues in specific obfuscation pass

### If outputs differ
- Compare outputs line by line
- Look for calculation errors
- Check for deterministic behavior (no timing/randomness)

## Performance Benchmarks

Typical obfuscation performance (320 functions):
- **Analysis**: ~50ms
- **Obfuscation**: ~150ms
- **Compilation**: ~100ms
- **Total**: ~300-350ms

Test binary execution:
- **Original**: 1-5ms
- **Obfuscated**: 2-10ms
- **Overhead**: ~2-5x (acceptable for obfuscated code)
