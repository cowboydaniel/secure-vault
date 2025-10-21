"""
Cryptographic Property Validation

This module provides validation functions for cryptographic primitives,
particularly S-box properties, randomness quality, and other security properties.
"""

import math
from typing import List, Tuple, Dict, Optional
from collections import Counter
import struct


class SBoxValidator:
    """Validates S-box cryptographic properties"""

    @staticmethod
    def validate_permutation(sbox: List[int]) -> bool:
        """
        Validate that S-box is a valid permutation

        Args:
            sbox: S-box to validate (should be 256 elements)

        Returns:
            True if valid permutation
        """
        if len(sbox) != 256:
            return False

        # Check that every value 0-255 appears exactly once
        return set(sbox) == set(range(256))

    @staticmethod
    def compute_nonlinearity(sbox: List[int]) -> int:
        """
        Compute nonlinearity of S-box

        Nonlinearity measures resistance to linear approximation.
        Higher nonlinearity = better resistance to linear cryptanalysis.

        Args:
            sbox: S-box to analyze

        Returns:
            Nonlinearity value (higher is better)
        """
        n = 8  # 8-bit S-box
        max_correlation = 0

        # Simplified nonlinearity check (full analysis is very expensive)
        # Check a sample of linear approximations
        for a in [1, 3, 7, 15, 31, 63, 127, 255]:
            for b in [1, 3, 7, 15, 31, 63, 127, 255]:
                correlation = 0

                for x in range(256):
                    input_parity = bin(x & a).count('1') % 2
                    output_parity = bin(sbox[x] & b).count('1') % 2

                    if input_parity == output_parity:
                        correlation += 1

                # Bias from 128
                bias = abs(correlation - 128)
                max_correlation = max(max_correlation, bias)

        # Nonlinearity = 2^(n-1) - max_correlation
        nonlinearity = (1 << (n - 1)) - max_correlation

        return nonlinearity

    @staticmethod
    def compute_differential_uniformity(sbox: List[int]) -> int:
        """
        Compute differential uniformity of S-box

        Measures resistance to differential cryptanalysis.
        Lower differential uniformity = better resistance.

        Args:
            sbox: S-box to analyze

        Returns:
            Differential uniformity (lower is better)
        """
        max_count = 0

        # Sample differential pairs (full analysis is O(n^3))
        for delta_in in [1, 3, 7, 15, 31, 63, 127, 255]:
            for delta_out in range(256):
                count = 0

                for x in range(256):
                    x_prime = x ^ delta_in
                    if (sbox[x] ^ sbox[x_prime]) == delta_out:
                        count += 1

                max_count = max(max_count, count)

        return max_count

    @staticmethod
    def check_fixed_points(sbox: List[int]) -> Tuple[int, List[int]]:
        """
        Check for fixed points in S-box

        Fixed points (x where S(x) = x) can be weak points.

        Args:
            sbox: S-box to check

        Returns:
            (count, list of fixed points)
        """
        fixed_points = [x for x in range(256) if sbox[x] == x]
        return len(fixed_points), fixed_points

    @staticmethod
    def check_opposite_fixed_points(sbox: List[int]) -> Tuple[int, List[int]]:
        """
        Check for opposite fixed points

        Opposite fixed points: S(x) = ~x (bitwise complement)

        Args:
            sbox: S-box to check

        Returns:
            (count, list of opposite fixed points)
        """
        opposite_fixed = [x for x in range(256) if sbox[x] == (255 - x)]
        return len(opposite_fixed), opposite_fixed

    @staticmethod
    def validate_sbox_quality(sbox: List[int]) -> Dict[str, any]:
        """
        Comprehensive S-box quality validation

        Args:
            sbox: S-box to validate

        Returns:
            Dictionary with validation results
        """
        results = {
            'is_permutation': SBoxValidator.validate_permutation(sbox),
            'nonlinearity': SBoxValidator.compute_nonlinearity(sbox),
            'differential_uniformity': SBoxValidator.compute_differential_uniformity(sbox),
        }

        fixed_count, fixed_points = SBoxValidator.check_fixed_points(sbox)
        results['fixed_points_count'] = fixed_count
        results['fixed_points'] = fixed_points

        opp_count, opp_points = SBoxValidator.check_opposite_fixed_points(sbox)
        results['opposite_fixed_count'] = opp_count

        # Quality assessment
        results['quality'] = 'unknown'

        if results['is_permutation']:
            # Good nonlinearity for 8-bit S-box: >= 100
            # Good differential uniformity: <= 8
            if results['nonlinearity'] >= 100 and results['differential_uniformity'] <= 8:
                results['quality'] = 'good'
            elif results['nonlinearity'] >= 80 and results['differential_uniformity'] <= 16:
                results['quality'] = 'acceptable'
            else:
                results['quality'] = 'weak'
        else:
            results['quality'] = 'invalid'

        return results


class RandomnessValidator:
    """Validates randomness quality of byte sequences"""

    @staticmethod
    def chi_square_test(data: bytes) -> Tuple[float, bool]:
        """
        Chi-square test for randomness

        Tests if byte distribution is uniform.

        Args:
            data: Data to test

        Returns:
            (chi_square_value, passes_test)
        """
        if len(data) < 256:
            return 0.0, False

        # Count occurrences of each byte value
        counts = Counter(data)

        # Expected count for each byte
        expected = len(data) / 256

        # Compute chi-square statistic
        chi_square = sum(
            ((counts.get(i, 0) - expected) ** 2) / expected
            for i in range(256)
        )

        # Critical value for 255 degrees of freedom at 95% confidence
        # (simplified, actual value from chi-square distribution table)
        critical_value = 293.25

        passes = chi_square < critical_value

        return chi_square, passes

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """
        Compute Shannon entropy

        Measures information content. Max entropy for bytes is 8.0.

        Args:
            data: Data to analyze

        Returns:
            Entropy in bits per byte
        """
        if not data:
            return 0.0

        # Count byte frequencies
        counts = Counter(data)

        # Compute entropy
        entropy = 0.0
        length = len(data)

        for count in counts.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def runs_test(data: bytes) -> bool:
        """
        Runs test for randomness

        Tests for patterns in bit sequences.

        Args:
            data: Data to test

        Returns:
            True if test passes
        """
        if len(data) < 20:
            return False

        # Convert to bit string
        bits = ''.join(format(byte, '08b') for byte in data)

        # Count runs (sequences of same bit)
        runs = 1
        for i in range(1, len(bits)):
            if bits[i] != bits[i-1]:
                runs += 1

        # Expected number of runs
        n = len(bits)
        ones = bits.count('1')
        zeros = bits.count('0')

        if zeros == 0 or ones == 0:
            return False

        expected_runs = (2 * ones * zeros) / n + 1

        # Standard deviation
        variance = (2 * ones * zeros * (2 * ones * zeros - n)) / (n * n * (n - 1))
        std_dev = math.sqrt(variance)

        # Z-score
        z = abs((runs - expected_runs) / std_dev) if std_dev > 0 else float('inf')

        # Test passes if |z| < 1.96 (95% confidence)
        return z < 1.96

    @staticmethod
    def monobit_test(data: bytes) -> bool:
        """
        Monobit (frequency) test

        Tests if number of 0s and 1s are approximately equal.

        Args:
            data: Data to test

        Returns:
            True if test passes
        """
        if len(data) < 20:
            return False

        # Count total bits
        total_bits = len(data) * 8

        # Count ones
        ones = sum(bin(byte).count('1') for byte in data)

        # Expected: ~50% ones
        expected = total_bits / 2

        # Standard deviation
        std_dev = math.sqrt(total_bits) / 2

        # Z-score
        z = abs((ones - expected) / std_dev) if std_dev > 0 else float('inf')

        # Test passes if |z| < 2.58 (99% confidence)
        return z < 2.58

    @staticmethod
    def validate_randomness(data: bytes, min_entropy: float = 7.5) -> Dict[str, any]:
        """
        Comprehensive randomness validation

        Args:
            data: Data to validate
            min_entropy: Minimum acceptable entropy

        Returns:
            Dictionary with validation results
        """
        results = {}

        # Shannon entropy
        entropy = RandomnessValidator.shannon_entropy(data)
        results['entropy'] = entropy
        results['entropy_passes'] = entropy >= min_entropy

        # Chi-square test
        chi_sq, chi_passes = RandomnessValidator.chi_square_test(data)
        results['chi_square'] = chi_sq
        results['chi_square_passes'] = chi_passes

        # Monobit test
        results['monobit_passes'] = RandomnessValidator.monobit_test(data)

        # Runs test
        results['runs_passes'] = RandomnessValidator.runs_test(data)

        # Overall assessment
        tests_passed = sum([
            results['entropy_passes'],
            results['chi_square_passes'],
            results['monobit_passes'],
            results['runs_passes']
        ])

        if tests_passed >= 3:
            results['quality'] = 'good'
        elif tests_passed >= 2:
            results['quality'] = 'acceptable'
        else:
            results['quality'] = 'poor'

        results['tests_passed'] = tests_passed
        results['total_tests'] = 4

        return results


class KeyValidator:
    """Validates cryptographic key properties"""

    @staticmethod
    def validate_key_length(key: bytes, expected_length: int) -> bool:
        """Validate key is correct length"""
        return len(key) == expected_length

    @staticmethod
    def check_weak_keys(key: bytes) -> List[str]:
        """
        Check for weak key patterns

        Args:
            key: Key to check

        Returns:
            List of weaknesses found
        """
        weaknesses = []

        # All zeros
        if key == b'\x00' * len(key):
            weaknesses.append("all_zeros")

        # All ones
        if key == b'\xff' * len(key):
            weaknesses.append("all_ones")

        # Repeating pattern
        if len(key) >= 4:
            pattern = key[:4]
            if key == pattern * (len(key) // 4) + pattern[:len(key) % 4]:
                weaknesses.append("repeating_pattern")

        # Low entropy
        entropy = RandomnessValidator.shannon_entropy(key)
        if entropy < 7.0:
            weaknesses.append("low_entropy")

        return weaknesses

    @staticmethod
    def validate_key(key: bytes, expected_length: int) -> Dict[str, any]:
        """
        Comprehensive key validation

        Args:
            key: Key to validate
            expected_length: Expected key length

        Returns:
            Dictionary with validation results
        """
        results = {}

        results['correct_length'] = KeyValidator.validate_key_length(key, expected_length)
        results['weaknesses'] = KeyValidator.check_weak_keys(key)
        results['randomness'] = RandomnessValidator.validate_randomness(key)

        results['is_valid'] = (
            results['correct_length'] and
            len(results['weaknesses']) == 0 and
            results['randomness']['quality'] in ['good', 'acceptable']
        )

        return results


def validate_crypto_operation(operation_type: str, **kwargs) -> Dict[str, any]:
    """
    Validate cryptographic operation parameters

    Args:
        operation_type: Type of operation ('sbox', 'key', 'randomness')
        **kwargs: Operation-specific parameters

    Returns:
        Validation results
    """
    if operation_type == 'sbox':
        sbox = kwargs.get('sbox')
        return SBoxValidator.validate_sbox_quality(sbox)

    elif operation_type == 'key':
        key = kwargs.get('key')
        expected_length = kwargs.get('expected_length', 64)
        return KeyValidator.validate_key(key, expected_length)

    elif operation_type == 'randomness':
        data = kwargs.get('data')
        min_entropy = kwargs.get('min_entropy', 7.5)
        return RandomnessValidator.validate_randomness(data, min_entropy)

    else:
        raise ValueError(f"Unknown operation type: {operation_type}")
