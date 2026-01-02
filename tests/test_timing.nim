# Timing verification tests for constant-time operations
# These tests verify that operations take similar time regardless of input values

import unittest, times, strutils
import nim_chacha20_poly1305/[common, poly1305, helpers]

const
  ITERATIONS = 100000
  WARMUP = 10000
  TIMING_THRESHOLD = 0.30  # Allow 30% variance (timing tests are inherently noisy on fast ops)

suite "timing_verification":
  test "mulMod_constant_time":
    # Test that mulMod takes similar time for different carry scenarios
    # Before fix: carry > 0 branch caused timing variation

    # Create inputs that produce different carry patterns
    var a_no_carry, b_no_carry: Poly130
    var a_with_carry, b_with_carry: Poly130

    # Small values - likely no final carry
    for i in 0..4:
      a_no_carry.limbs[i] = 100
      b_no_carry.limbs[i] = 100

    # Large values near MASK26 - likely to produce carries
    for i in 0..4:
      a_with_carry.limbs[i] = MASK26 - 10
      b_with_carry.limbs[i] = MASK26 - 10

    var result1, result2: Poly130

    # Warmup
    for _ in 0..<WARMUP:
      result1 = mulMod(a_no_carry, b_no_carry)
      result2 = mulMod(a_with_carry, b_with_carry)

    # Measure no-carry case
    let start1 = cpuTime()
    for _ in 0..<ITERATIONS:
      result1 = mulMod(a_no_carry, b_no_carry)
    let time_no_carry = (cpuTime() - start1) / ITERATIONS.float

    # Measure with-carry case
    let start2 = cpuTime()
    for _ in 0..<ITERATIONS:
      result2 = mulMod(a_with_carry, b_with_carry)
    let time_with_carry = (cpuTime() - start2) / ITERATIONS.float

    # Calculate timing ratio
    let ratio = if time_no_carry > time_with_carry:
      time_no_carry / time_with_carry
    else:
      time_with_carry / time_no_carry

    echo "  mulMod timing ratio: ", $ratio
    echo "  no_carry: ", $(time_no_carry * 1e9), " ns"
    echo "  with_carry: ", $(time_with_carry * 1e9), " ns"

    # Times should be similar (within threshold)
    check(ratio < 1.0 + TIMING_THRESHOLD)

  test "poly1305_verify_constant_time":
    # Test that MAC verification takes similar time for early vs late differences

    let tag1: Tag = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]

    # Difference in first byte (early exit opportunity for non-CT impl)
    var tag_diff_early = tag1
    tag_diff_early[0] = 255

    # Difference in last byte (late exit for non-CT impl)
    var tag_diff_late = tag1
    tag_diff_late[15] = 255

    var result1, result2: bool

    # Warmup to prime caches
    for _ in 0..<WARMUP:
      result1 = poly1305_verify(tag1, tag_diff_early)
      result2 = poly1305_verify(tag1, tag_diff_late)

    # Measure early diff
    let start1 = cpuTime()
    for _ in 0..<ITERATIONS:
      result1 = poly1305_verify(tag1, tag_diff_early)
    let time_early = (cpuTime() - start1) / ITERATIONS.float

    # Measure late diff
    let start2 = cpuTime()
    for _ in 0..<ITERATIONS:
      result2 = poly1305_verify(tag1, tag_diff_late)
    let time_late = (cpuTime() - start2) / ITERATIONS.float

    let ratio = if time_early > time_late:
      time_early / time_late
    else:
      time_late / time_early

    echo "  verify timing ratio: ", $ratio
    echo "  early_diff: ", $(time_early * 1e9), " ns"
    echo "  late_diff: ", $(time_late * 1e9), " ns"

    check(ratio < 1.0 + TIMING_THRESHOLD)
    check(result1 == false)
    check(result2 == false)

  test "constantTimeEquals_timing":
    # Test that constantTimeEquals takes similar time regardless of difference position

    let data1 = @[byte(1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]

    var data_diff_early = data1
    data_diff_early[0] = 255

    var data_diff_late = data1
    data_diff_late[15] = 255

    var result1, result2: bool

    # Warmup
    for _ in 0..<WARMUP:
      result1 = constantTimeEquals(data1, data_diff_early)
      result2 = constantTimeEquals(data1, data_diff_late)

    # Measure early diff
    let start1 = cpuTime()
    for _ in 0..<ITERATIONS:
      result1 = constantTimeEquals(data1, data_diff_early)
    let time_early = (cpuTime() - start1) / ITERATIONS.float

    # Measure late diff
    let start2 = cpuTime()
    for _ in 0..<ITERATIONS:
      result2 = constantTimeEquals(data1, data_diff_late)
    let time_late = (cpuTime() - start2) / ITERATIONS.float

    let ratio = if time_early > time_late:
      time_early / time_late
    else:
      time_late / time_early

    echo "  constantTimeEquals ratio: ", $ratio

    check(ratio < 1.0 + TIMING_THRESHOLD)
    check(result1 == false)
    check(result2 == false)
