//! Test binary for the obfuscator.
//!
//! This binary tests various instruction patterns that the mutation pass targets.
//! It outputs structured results that can be verified by integration tests.

use std::hint::black_box;

/// Test result tracking
struct TestRunner {
    passed: u32,
    failed: u32,
}

impl TestRunner {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
        }
    }

    fn run<F: FnOnce() -> bool>(&mut self, name: &str, test: F) {
        let result = test();
        if result {
            println!("[PASS] {}", name);
            self.passed += 1;
        } else {
            println!("[FAIL] {}", name);
            self.failed += 1;
        }
    }

    fn finish(self) -> bool {
        println!();
        if self.failed == 0 {
            println!("=== RESULT: SUCCESS ({} tests passed) ===", self.passed);
            true
        } else {
            println!(
                "=== RESULT: FAILURE ({} passed, {} failed) ===",
                self.passed, self.failed
            );
            false
        }
    }
}

// ============================================================================
// Test functions - each targets specific mutation patterns
// ============================================================================

/// Tests ADD instruction mutation (ADD -> CLC + ADC)
#[inline(never)]
fn add_i32(a: i32, b: i32) -> i32 {
    a + b
}

#[inline(never)]
fn add_i64(a: i64, b: i64) -> i64 {
    a + b
}

/// Tests SUB instruction
#[inline(never)]
fn sub_i32(a: i32, b: i32) -> i32 {
    a - b
}

/// Tests INC mutation (INC -> CLC + ADC 1)
#[inline(never)]
fn increment(mut x: i32) -> i32 {
    x += 1;
    x
}

#[inline(never)]
fn increment_loop(mut x: i32, times: i32) -> i32 {
    for _ in 0..times {
        x += 1;
    }
    x
}

/// Tests DEC mutation (DEC -> CLC + SBB 1)
#[inline(never)]
fn decrement(mut x: i32) -> i32 {
    x -= 1;
    x
}

/// Tests LEA mutation (adds displacement + compensating SUB)
#[inline(never)]
fn array_sum(arr: &[i32]) -> i32 {
    let mut sum = 0;
    for &val in arr {
        sum = add_i32(sum, val);
    }
    sum
}

#[inline(never)]
fn array_index(arr: &[i32], idx: usize) -> i32 {
    arr[idx]
}

/// Tests PUSH mutation (PUSH -> MOV [rsp-8] + SUB rsp)
#[inline(never)]
fn nested_calls(a: i32, b: i32, c: i32) -> i32 {
    let x = add_i32(a, b);
    let y = add_i32(x, c);
    add_i32(y, a)
}

#[inline(never)]
fn deep_call_chain(x: i32) -> i32 {
    let a = add_i32(x, 1);
    let b = add_i32(a, 2);
    let c = add_i32(b, 3);
    let d = add_i32(c, 4);
    add_i32(d, 5)
}

/// Tests OR mutation (OR -> ANDN + BLSI + TZCNT sequence)
#[inline(never)]
fn bitwise_or(a: u32, b: u32) -> u32 {
    a | b
}

#[inline(never)]
fn bitwise_and(a: u32, b: u32) -> u32 {
    a & b
}

#[inline(never)]
fn bitwise_xor(a: u32, b: u32) -> u32 {
    a ^ b
}

/// Tests conditional branches (ensures branch fixups work)
#[inline(never)]
fn conditional_positive(x: i32) -> i32 {
    if x > 0 {
        1
    } else {
        0
    }
}

#[inline(never)]
fn conditional_compare(a: i32, b: i32) -> i32 {
    if a > b {
        a
    } else {
        b
    }
}

/// Tests loops (branch targets after mutation)
#[inline(never)]
fn sum_to_n(n: i32) -> i32 {
    let mut sum = 0;
    let mut i = 1;
    while i <= n {
        sum = add_i32(sum, i);
        i = increment(i);
    }
    sum
}

#[inline(never)]
fn factorial(n: i32) -> i32 {
    if n <= 1 {
        1
    } else {
        n * factorial(n - 1)
    }
}

/// Tests mixed operations
#[inline(never)]
fn complex_math(a: i32, b: i32, c: i32) -> i32 {
    let x = add_i32(a, b);
    let y = sub_i32(x, c);
    let z = increment(y);
    add_i32(z, a)
}

fn main() {
    let mut runner = TestRunner::new();

    // ADD tests
    runner.run("add_i32(5, 3) == 8", || {
        black_box(add_i32(black_box(5), black_box(3))) == 8
    });

    runner.run("add_i32(-10, 15) == 5", || {
        black_box(add_i32(black_box(-10), black_box(15))) == 5
    });

    runner.run("add_i32(0, 0) == 0", || {
        black_box(add_i32(black_box(0), black_box(0))) == 0
    });

    runner.run("add_i64(1000000, 2000000) == 3000000", || {
        black_box(add_i64(black_box(1000000), black_box(2000000))) == 3000000
    });

    // SUB tests
    runner.run("sub_i32(10, 3) == 7", || {
        black_box(sub_i32(black_box(10), black_box(3))) == 7
    });

    runner.run("sub_i32(5, 10) == -5", || {
        black_box(sub_i32(black_box(5), black_box(10))) == -5
    });

    // INC tests
    runner.run("increment(0) == 1", || {
        black_box(increment(black_box(0))) == 1
    });

    runner.run("increment(99) == 100", || {
        black_box(increment(black_box(99))) == 100
    });

    runner.run("increment_loop(0, 10) == 10", || {
        black_box(increment_loop(black_box(0), black_box(10))) == 10
    });

    // DEC tests
    runner.run("decrement(10) == 9", || {
        black_box(decrement(black_box(10))) == 9
    });

    runner.run("decrement(0) == -1", || {
        black_box(decrement(black_box(0))) == -1
    });

    // Array/LEA tests
    runner.run("array_sum([1,2,3,4,5]) == 15", || {
        let arr = [1, 2, 3, 4, 5];
        black_box(array_sum(black_box(&arr))) == 15
    });

    runner.run("array_index([10,20,30], 1) == 20", || {
        let arr = [10, 20, 30];
        black_box(array_index(black_box(&arr), black_box(1))) == 20
    });

    // PUSH/Call tests
    runner.run("nested_calls(1, 2, 3) == 7", || {
        black_box(nested_calls(black_box(1), black_box(2), black_box(3))) == 7
    });

    runner.run("deep_call_chain(0) == 15", || {
        black_box(deep_call_chain(black_box(0))) == 15
    });

    // Bitwise tests
    runner.run("bitwise_or(0b1010, 0b0101) == 0b1111", || {
        black_box(bitwise_or(black_box(0b1010), black_box(0b0101))) == 0b1111
    });

    runner.run("bitwise_and(0b1110, 0b0111) == 0b0110", || {
        black_box(bitwise_and(black_box(0b1110), black_box(0b0111))) == 0b0110
    });

    runner.run("bitwise_xor(0b1010, 0b1100) == 0b0110", || {
        black_box(bitwise_xor(black_box(0b1010), black_box(0b1100))) == 0b0110
    });

    // Conditional tests
    runner.run("conditional_positive(5) == 1", || {
        black_box(conditional_positive(black_box(5))) == 1
    });

    runner.run("conditional_positive(-5) == 0", || {
        black_box(conditional_positive(black_box(-5))) == 0
    });

    runner.run("conditional_compare(10, 5) == 10", || {
        black_box(conditional_compare(black_box(10), black_box(5))) == 10
    });

    runner.run("conditional_compare(3, 7) == 7", || {
        black_box(conditional_compare(black_box(3), black_box(7))) == 7
    });

    // Loop tests
    runner.run("sum_to_n(10) == 55", || {
        black_box(sum_to_n(black_box(10))) == 55
    });

    runner.run("factorial(5) == 120", || {
        black_box(factorial(black_box(5))) == 120
    });

    // Complex tests
    runner.run("complex_math(10, 5, 3) == 23", || {
        // (10 + 5) - 3 + 1 + 10 = 23
        black_box(complex_math(black_box(10), black_box(5), black_box(3))) == 23
    });

    // Exit with proper code
    let success = runner.finish();
    std::process::exit(if success { 0 } else { 1 });
}
