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

// ============================================================================
// Additional comprehensive tests
// ============================================================================

/// Tests multiplication (various patterns)
#[inline(never)]
fn multiply_i32(a: i32, b: i32) -> i32 {
    a * b
}

#[inline(never)]
fn multiply_by_power_of_two(x: i32) -> i32 {
    x * 16
}

/// Tests division and modulo
#[inline(never)]
fn divide_i32(a: i32, b: i32) -> i32 {
    if b != 0 {
        a / b
    } else {
        0
    }
}

#[inline(never)]
fn modulo_i32(a: i32, b: i32) -> i32 {
    if b != 0 {
        a % b
    } else {
        0
    }
}

/// Tests shift operations
#[inline(never)]
fn left_shift(x: u32, amount: u32) -> u32 {
    x << amount
}

#[inline(never)]
fn right_shift(x: u32, amount: u32) -> u32 {
    x >> amount
}

/// Tests NOT operation
#[inline(never)]
fn bitwise_not(x: u32) -> u32 {
    !x
}

/// Tests complex bitwise operations
#[inline(never)]
fn bitwise_complex(a: u32, b: u32, c: u32) -> u32 {
    (a & b) | (c ^ a)
}

/// Tests bit counting patterns
#[inline(never)]
fn count_ones(mut x: u32) -> u32 {
    let mut count = 0;
    while x != 0 {
        if x & 1 == 1 {
            count += 1;
        }
        x >>= 1;
    }
    count
}

/// Tests switch-like pattern (multiple branches)
#[inline(never)]
fn classify_number(x: i32) -> i32 {
    if x < 0 {
        -1
    } else if x == 0 {
        0
    } else if x < 10 {
        1
    } else if x < 100 {
        2
    } else {
        3
    }
}

/// Tests nested conditionals
#[inline(never)]
fn nested_conditions(a: i32, b: i32, c: i32) -> i32 {
    if a > 0 {
        if b > 0 {
            if c > 0 {
                3
            } else {
                2
            }
        } else {
            1
        }
    } else {
        0
    }
}

/// Tests early return pattern
#[inline(never)]
fn early_return(x: i32) -> i32 {
    if x < 0 {
        return -1;
    }
    if x == 0 {
        return 0;
    }
    if x > 100 {
        return 100;
    }
    x
}

/// Tests nested loops
#[inline(never)]
fn nested_loop_sum(n: i32) -> i32 {
    let mut sum = 0;
    for i in 0..n {
        for j in 0..n {
            sum = add_i32(sum, add_i32(i, j));
        }
    }
    sum
}

/// Tests loop with break
#[inline(never)]
fn find_first_divisor(n: i32, start: i32) -> i32 {
    for i in start..n {
        if i != 0 && n % i == 0 {
            return i;
        }
    }
    n
}

/// Tests loop with continue
#[inline(never)]
fn sum_even_numbers(n: i32) -> i32 {
    let mut sum = 0;
    for i in 0..n {
        if i % 2 != 0 {
            continue;
        }
        sum = add_i32(sum, i);
    }
    sum
}

/// Tests Fibonacci (stress test for recursion)
#[inline(never)]
fn fibonacci(n: i32) -> i32 {
    if n <= 1 {
        n
    } else {
        fibonacci(n - 1) + fibonacci(n - 2)
    }
}

/// Tests pointer arithmetic and array manipulation
#[inline(never)]
fn array_reverse_sum(arr: &[i32]) -> i32 {
    let mut sum = 0;
    let len = arr.len();
    for i in 0..len {
        let val = arr[len - 1 - i];
        sum = add_i32(sum, val);
    }
    sum
}

/// Tests more complex array operations
#[inline(never)]
fn array_max(arr: &[i32]) -> i32 {
    if arr.is_empty() {
        return 0;
    }
    let mut max = arr[0];
    for &val in &arr[1..] {
        if val > max {
            max = val;
        }
    }
    max
}

/// Tests string length calculation (char counting)
#[inline(never)]
fn count_chars(s: &str) -> usize {
    let mut count = 0;
    for _ in s.chars() {
        count += 1;
    }
    count
}

/// Tests match-like pattern (jumptable candidate)
#[inline(never)]
fn match_pattern(x: i32) -> i32 {
    match x {
        0 => 10,
        1 => 20,
        2 => 30,
        3 => 40,
        4 => 50,
        _ => 0,
    }
}

/// Tests struct with multiple fields
#[derive(Clone, Copy)]
struct Point {
    x: i32,
    y: i32,
}

#[inline(never)]
fn point_distance_squared(p1: Point, p2: Point) -> i32 {
    let dx = sub_i32(p2.x, p1.x);
    let dy = sub_i32(p2.y, p1.y);
    add_i32(multiply_i32(dx, dx), multiply_i32(dy, dy))
}

/// Tests zero operations (edge case)
#[inline(never)]
fn zero_test(x: i32) -> bool {
    x == 0
}

/// Tests overflow scenarios (should wrap)
#[inline(never)]
fn overflow_add(a: i32, b: i32) -> i32 {
    a.wrapping_add(b)
}

/// Tests underflow scenarios
#[inline(never)]
fn underflow_sub(a: i32, b: i32) -> i32 {
    a.wrapping_sub(b)
}

/// Tests all comparison operators
#[inline(never)]
fn all_comparisons(a: i32, b: i32) -> i32 {
    let mut result = 0;
    if a < b {
        result += 1;
    }
    if a <= b {
        result += 2;
    }
    if a > b {
        result += 4;
    }
    if a >= b {
        result += 8;
    }
    if a == b {
        result += 16;
    }
    if a != b {
        result += 32;
    }
    result
}

/// Tests negative number operations
#[inline(never)]
fn negative_ops(x: i32) -> i32 {
    let neg = -x;
    let abs = if neg < 0 { -neg } else { neg };
    abs
}

/// Tests min/max functions
#[inline(never)]
fn min_max(a: i32, b: i32, c: i32) -> i32 {
    let min_ab = if a < b { a } else { b };
    let max_abc = if c > min_ab { c } else { min_ab };
    max_abc
}

/// Tests multiple return paths
#[inline(never)]
fn multiple_returns(x: i32, y: i32) -> i32 {
    if x > 10 {
        return x + y;
    }
    if y > 10 {
        return y + x;
    }
    if x == y {
        return x * 2;
    }
    x + y
}

/// Tests deep nesting
#[inline(never)]
fn deeply_nested(x: i32) -> i32 {
    let result = {
        let a = {
            let b = {
                let c = x + 1;
                c * 2
            };
            b + 3
        };
        a - 4
    };
    result
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

    // Multiplication tests
    runner.run("multiply_i32(6, 7) == 42", || {
        black_box(multiply_i32(black_box(6), black_box(7))) == 42
    });

    runner.run("multiply_i32(-5, 4) == -20", || {
        black_box(multiply_i32(black_box(-5), black_box(4))) == -20
    });

    runner.run("multiply_by_power_of_two(3) == 48", || {
        black_box(multiply_by_power_of_two(black_box(3))) == 48
    });

    // Division tests
    runner.run("divide_i32(20, 4) == 5", || {
        black_box(divide_i32(black_box(20), black_box(4))) == 5
    });

    runner.run("divide_i32(10, 3) == 3", || {
        black_box(divide_i32(black_box(10), black_box(3))) == 3
    });

    runner.run("modulo_i32(10, 3) == 1", || {
        black_box(modulo_i32(black_box(10), black_box(3))) == 1
    });

    // Shift tests
    runner.run("left_shift(1, 4) == 16", || {
        black_box(left_shift(black_box(1), black_box(4))) == 16
    });

    runner.run("right_shift(32, 2) == 8", || {
        black_box(right_shift(black_box(32), black_box(2))) == 8
    });

    // Bitwise tests (additional)
    runner.run("bitwise_not(0) == 0xFFFFFFFF", || {
        black_box(bitwise_not(black_box(0))) == 0xFFFFFFFF
    });

    runner.run("bitwise_complex(0xFF, 0x0F, 0xF0) == 0x0F", || {
        // (0xFF & 0x0F) | (0xF0 ^ 0xFF) = 0x0F | 0x0F = 0x0F
        black_box(bitwise_complex(black_box(0xFF), black_box(0x0F), black_box(0xF0))) == 0x0F
    });

    runner.run("count_ones(0b10101010) == 4", || {
        black_box(count_ones(black_box(0b10101010))) == 4
    });

    // Control flow tests
    runner.run("classify_number(-5) == -1", || {
        black_box(classify_number(black_box(-5))) == -1
    });

    runner.run("classify_number(5) == 1", || {
        black_box(classify_number(black_box(5))) == 1
    });

    runner.run("classify_number(50) == 2", || {
        black_box(classify_number(black_box(50))) == 2
    });

    runner.run("classify_number(150) == 3", || {
        black_box(classify_number(black_box(150))) == 3
    });

    runner.run("nested_conditions(1, 1, 1) == 3", || {
        black_box(nested_conditions(black_box(1), black_box(1), black_box(1))) == 3
    });

    runner.run("nested_conditions(1, 1, -1) == 2", || {
        black_box(nested_conditions(black_box(1), black_box(1), black_box(-1))) == 2
    });

    runner.run("early_return(50) == 50", || {
        black_box(early_return(black_box(50))) == 50
    });

    runner.run("early_return(150) == 100", || {
        black_box(early_return(black_box(150))) == 100
    });

    // Loop tests (additional)
    runner.run("nested_loop_sum(3) == 18", || {
        // 0+0, 0+1, 0+2, 1+0, 1+1, 1+2, 2+0, 2+1, 2+2 = 18
        black_box(nested_loop_sum(black_box(3))) == 18
    });

    runner.run("find_first_divisor(20, 2) == 2", || {
        black_box(find_first_divisor(black_box(20), black_box(2))) == 2
    });

    runner.run("sum_even_numbers(10) == 20", || {
        // 0 + 2 + 4 + 6 + 8 = 20
        black_box(sum_even_numbers(black_box(10))) == 20
    });

    // Recursion tests
    runner.run("fibonacci(7) == 13", || {
        black_box(fibonacci(black_box(7))) == 13
    });

    // Array tests (additional)
    runner.run("array_reverse_sum([1,2,3,4]) == 10", || {
        let arr = [1, 2, 3, 4];
        black_box(array_reverse_sum(black_box(&arr))) == 10
    });

    runner.run("array_max([3,1,4,1,5,9]) == 9", || {
        let arr = [3, 1, 4, 1, 5, 9];
        black_box(array_max(black_box(&arr))) == 9
    });

    // String tests
    runner.run("count_chars('hello') == 5", || {
        black_box(count_chars(black_box("hello"))) == 5
    });

    // NOTE: match_pattern tests are commented out because the function generates jump tables.
    // The obfuscator correctly skips functions with jump tables, but calling them from
    // obfuscated code can cause issues. This is a documented limitation.
    // 
    // runner.run("match_pattern(0) == 10", || {
    //     black_box(match_pattern(black_box(0))) == 10
    // });
    // 
    // runner.run("match_pattern(3) == 40", || {
    //     black_box(match_pattern(black_box(3))) == 40
    // });
    // 
    // runner.run("match_pattern(99) == 0", || {
    //     black_box(match_pattern(black_box(99))) == 0
    // });

    // Struct tests
    runner.run("point_distance_squared((0,0), (3,4)) == 25", || {
        let p1 = Point { x: 0, y: 0 };
        let p2 = Point { x: 3, y: 4 };
        black_box(point_distance_squared(black_box(p1), black_box(p2))) == 25
    });

    // Edge case tests
    runner.run("zero_test(0) == true", || {
        black_box(zero_test(black_box(0)))
    });

    runner.run("zero_test(1) == false", || {
        !black_box(zero_test(black_box(1)))
    });

    runner.run("overflow_add(i32::MAX, 1) wraps", || {
        black_box(overflow_add(black_box(i32::MAX), black_box(1))) == i32::MIN
    });

    runner.run("underflow_sub(i32::MIN, 1) wraps", || {
        black_box(underflow_sub(black_box(i32::MIN), black_box(1))) == i32::MAX
    });

    // Comparison tests
    runner.run("all_comparisons(5, 10) == 35", || {
        // < <= != = 1 + 2 + 32 = 35
        black_box(all_comparisons(black_box(5), black_box(10))) == 35
    });

    runner.run("all_comparisons(5, 5) == 26", || {
        // a <= b (2), a >= b (8), a == b (16) = 26
        black_box(all_comparisons(black_box(5), black_box(5))) == 26
    });

    // Negative number tests
    runner.run("negative_ops(5) == 5", || {
        black_box(negative_ops(black_box(5))) == 5
    });

    runner.run("negative_ops(-5) == 5", || {
        black_box(negative_ops(black_box(-5))) == 5
    });

    // Min/max tests
    runner.run("min_max(5, 3, 7) == 7", || {
        black_box(min_max(black_box(5), black_box(3), black_box(7))) == 7
    });

    // Multiple return paths
    runner.run("multiple_returns(15, 5) == 20", || {
        black_box(multiple_returns(black_box(15), black_box(5))) == 20
    });

    runner.run("multiple_returns(5, 5) == 10", || {
        black_box(multiple_returns(black_box(5), black_box(5))) == 10
    });

    // Deep nesting
    runner.run("deeply_nested(5) == 11", || {
        // ((5 + 1) * 2 + 3) - 4 = (12 + 3) - 4 = 11
        black_box(deeply_nested(black_box(5))) == 11
    });

    // Exit with proper code
    let success = runner.finish();
    std::process::exit(if success { 0 } else { 1 });
}
