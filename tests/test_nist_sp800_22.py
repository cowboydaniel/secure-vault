"""
NIST SP 800-22 Statistical Test Suite Implementation

This module implements a subset of the NIST SP 800-22 statistical tests
for evaluating the quality of random number generators and entropy sources.
"""

import math
import numpy as np
from typing import List, Tuple, Optional
from scipy.special import gammaincc, erfc


class NISTTestError(Exception):
    """Exception raised for errors in NIST test execution."""
    pass


def monobit_test(binary_sequence: bytes) -> Tuple[float, float]:
    """
    NIST Monobit Test (Frequency Test)
    
    Args:
        binary_sequence: Binary sequence to test (as bytes)
        
    Returns:
        Tuple of (p_value, is_random)
    """
    n = len(binary_sequence) * 8
    if n < 100:
        raise NISTTestError(f"Sequence too short: {n} bits (minimum 100 required)")
    
    # Convert bytes to bits (big-endian)
    bits = np.unpackbits(np.frombuffer(binary_sequence, dtype='>B'))
    
    # Calculate the sum of bits (0->-1, 1->1)
    s_n = 2 * np.sum(bits) - len(bits)
    
    # Compute the test statistic
    s_obs = abs(s_n) / math.sqrt(n)
    
    # Compute P-value
    p_value = erfc(s_obs / math.sqrt(2))
    
    return p_value, p_value >= 0.01


def runs_test(binary_sequence: bytes) -> Tuple[float, float]:
    """
    NIST Runs Test (Test for the number of runs of ones and zeros)
    
    Args:
        binary_sequence: Binary sequence to test (as bytes)
        
    Returns:
        Tuple of (p_value, is_random)
    """
    n = len(binary_sequence) * 8
    if n < 100:
        raise NISTTestError(f"Sequence too short: {n} bits (minimum 100 required)")
    
    # Convert bytes to bits (big-endian)
    bits = np.unpackbits(np.frombuffer(binary_sequence, dtype='>B'))
    
    # Calculate the proportion of ones
    pi = np.sum(bits) / n
    
    # Check if the test is applicable
    if abs(pi - 0.5) >= (2.0 / math.sqrt(n)):
        return 0.0, False  # Test is not applicable
    
    # Count the number of runs (both 1s and 0s)
    runs = 1
    for i in range(1, len(bits)):
        if bits[i] != bits[i-1]:
            runs += 1
    
    # Calculate the test statistic
    runs_expected = 2 * n * pi * (1 - pi)
    runs_std = 2 * math.sqrt(n) * pi * (1 - pi)
    
    # Compute P-value
    p_value = erfc(abs(runs - runs_expected) / (runs_std * math.sqrt(2)))
    
    return p_value, p_value >= 0.01


def binary_matrix_rank_test(binary_sequence: bytes, matrix_dims: Tuple[int, int] = (32, 32)) -> Tuple[float, float]:
    """
    NIST Binary Matrix Rank Test
    
    Args:
        binary_sequence: Binary sequence to test (as bytes)
        matrix_dims: Dimensions of the binary matrices to test (rows, cols)
        
    Returns:
        Tuple of (p_value, is_random)
    """
    M, Q = matrix_dims
    n = len(binary_sequence) * 8
    N = n // (M * Q)  # Number of matrices
    
    if N < 38:  # NIST recommends at least 38 matrices
        raise NISTTestError(f"Not enough data for {M}x{Q} matrices (need at least {38*M*Q//8} bytes)")
    
    # Convert bytes to bits (big-endian)
    bits = np.unpackbits(np.frombuffer(binary_sequence, dtype='>B'))
    
    # Reshape into N matrices of MxQ
    matrices = bits[:N*M*Q].reshape((N, M, Q))
    
    # For each matrix, calculate its rank
    ranks = []
    for mat in matrices:
        rank = np.linalg.matrix_rank(mat.astype(int))
        ranks.append(rank)
    
    # Count ranks
    F_M = np.sum(np.array(ranks) == M)  # Full rank
    F_M1 = np.sum(np.array(ranks) == M-1)  # Rank M-1
    F_other = N - F_M - F_M1  # Rank <= M-2
    
    # Expected values for random data
    product = 1.0
    for i in range(1, M+1):
        product *= ((1.0 - (2.0 ** (-i))) * (1.0 - (2.0 ** (-Q)))) / (1.0 - (2.0 ** (i - M - Q)))
    
    expected_F_M = product * (2 ** (Q * (M + Q - M * Q - 1)))
    expected_F_M1 = expected_F_M * 2 ** (Q - 1)
    expected_other = N - expected_F_M - expected_F_M1
    
    # Chi-square test
    chi_square = ((F_M - expected_F_M) ** 2) / expected_F_M + \
                 ((F_M1 - expected_F_M1) ** 2) / expected_F_M1 + \
                 ((F_other - expected_other) ** 2) / expected_other
    
    # Compute P-value
    p_value = math.exp(-chi_square / 2)
    
    return p_value, p_value >= 0.01


def test_nist_suite(binary_sequence: bytes, tests: Optional[List[str]] = None) -> dict:
    """
    Run a suite of NIST SP 800-22 tests on a binary sequence.
    
    Args:
        binary_sequence: Binary sequence to test (as bytes)
        tests: List of test names to run (None for all tests)
        
    Returns:
        Dictionary of test results with p-values and pass/fail status
    """
    if tests is None:
        tests = ['monobit', 'runs', 'binary_matrix_rank']
    
    results = {}
    
    if 'monobit' in tests:
        try:
            p_value, passed = monobit_test(binary_sequence)
            results['monobit'] = {
                'p_value': p_value,
                'passed': passed,
                'description': 'Frequency (Monobit) Test'
            }
        except NISTTestError as e:
            results['monobit'] = {
                'error': str(e),
                'passed': False,
                'description': 'Frequency (Monobit) Test'
            }
    
    if 'runs' in tests:
        try:
            p_value, passed = runs_test(binary_sequence)
            results['runs'] = {
                'p_value': p_value,
                'passed': passed,
                'description': 'Runs Test'
            }
        except NISTTestError as e:
            results['runs'] = {
                'error': str(e),
                'passed': False,
                'description': 'Runs Test'
            }
    
    if 'binary_matrix_rank' in tests:
        try:
            p_value, passed = binary_matrix_rank_test(binary_sequence)
            results['binary_matrix_rank'] = {
                'p_value': p_value,
                'passed': passed,
                'description': 'Binary Matrix Rank Test'
            }
        except NISTTestError as e:
            results['binary_matrix_rank'] = {
                'error': str(e),
                'passed': False,
                'description': 'Binary Matrix Rank Test'
            }
    
    return results


if __name__ == "__main__":
    import os
    import argparse
    
    parser = argparse.ArgumentParser(description='Run NIST SP 800-22 statistical tests on random data')
    parser.add_argument('--bytes', type=int, default=1024,
                        help='Number of random bytes to test (default: 1024)')
    parser.add_argument('--source', choices=['urandom', 'system', 'test'], default='urandom',
                        help='Source of random data (default: urandom)')
    args = parser.parse_args()
    
    # Generate test data
    if args.source == 'urandom':
        data = os.urandom(args.bytes)
    elif args.source == 'system':
        with open('/dev/random', 'rb') as f:
            data = f.read(args.bytes)
    else:  # test mode with known pattern
        data = bytes([i % 256 for i in range(args.bytes)])
    
    print(f"Testing {len(data)} bytes from {args.source} source")
    print("-" * 50)
    
    # Run tests
    results = test_nist_suite(data)
    
    # Print results
    for test_name, result in results.items():
        print(f"{result['description']}:")
        if 'error' in result:
            print(f"  Error: {result['error']}")
        else:
            print(f"  p-value: {result['p_value']:.6f}")
            print(f"  Passed: {'Yes' if result['passed'] else 'No'}")
        print()
