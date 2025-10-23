"""
S-box Validation Tests

This module contains tests for validating the cryptographic properties of S-boxes
used in the encryption algorithm.
"""
import unittest
import numpy as np
from typing import List, Tuple

class SBoxValidator:
    """Class for validating S-box cryptographic properties."""
    
    @staticmethod
    def is_complete(sbox: List[int]) -> bool:
        """
        Check if the S-box is complete (all output bits depend on all input bits).
        A complete S-box has the property that for any input bit i, there exists
        at least one pair of inputs x and x' that differ only in bit i, such that
        S(x) and S(x') differ in at least one bit.
        """
        n = (len(sbox) - 1).bit_length()  # Input size in bits
        m = max(sbox).bit_length() if sbox else 0  # Output size in bits
        
        # For each input bit position
        for i in range(n):
            mask = 1 << i
            bit_dependent = False
            
            # Check all possible input pairs that differ only in bit i
            for x in range(len(sbox)):
                x_prime = x ^ mask
                if x_prime >= len(sbox):
                    continue
                    
                # If any output bit differs, this bit position is good
                if sbox[x] != sbox[x_prime]:
                    bit_dependent = True
                    break
            
            # If no output bit depends on this input bit, S-box is not complete
            if not bit_dependent:
                return False
                
        return True
    
    @staticmethod
    def is_balanced(sbox: List[int]) -> bool:
        """
        Check if the S-box is balanced (each output occurs equally often).
        For an n-bit to m-bit S-box, each output should occur exactly 2^(n-m) times.
        For bijective S-boxes (n=m), this means each output occurs exactly once.
        
        Args:
            sbox: List of integers representing the S-box outputs
            
        Returns:
            bool: True if the S-box is balanced, False otherwise
        """
        if not sbox:
            return True
            
        # Get the number of input bits (n)
        n = (len(sbox) - 1).bit_length()  # Input size in bits
        
        # Get all unique output values and determine the number of output bits needed
        unique_outputs = set(sbox)
        max_output = max(unique_outputs) if unique_outputs else 0
        m = (max_output).bit_length() if max_output > 0 else 0
        
        # Handle empty S-box or all zeros case
        if m == 0:
            # All outputs are 0, which is only balanced if there's exactly one output
            return len(sbox) == 1
            
        # For bijective S-boxes (n=m), just check if all outputs are unique
        if n == m:
            return len(unique_outputs) == len(sbox)
        
        # For non-bijective S-boxes, we need to check if the outputs are balanced
        # First, determine the actual number of unique output values
        actual_num_outputs = len(unique_outputs)
        
        # The number of unique outputs must be a power of 2
        if (actual_num_outputs & (actual_num_outputs - 1)) != 0:
            return False
            
        # The number of outputs must be a multiple of the number of unique outputs
        if len(sbox) % actual_num_outputs != 0:
            return False
            
        # Calculate how many times each output should appear
        expected_count = len(sbox) // actual_num_outputs
        
        # Count occurrences of each output value
        counts = {}
        for y in sbox:
            counts[y] = counts.get(y, 0) + 1
            
        # Check that each output appears exactly expected_count times
        return all(count == expected_count for count in counts.values())
    
    @staticmethod
    def nonlinearity(sbox: List[int]) -> int:
        """
        Calculate the nonlinearity of the S-box.
        The nonlinearity is the minimum Hamming distance between any non-zero linear
        combination of the component functions and the set of all affine functions.
        """
        n = (len(sbox) - 1).bit_length()  # Input size in bits
        m = max(sbox).bit_length() if sbox else 0  # Output size in bits
        
        if n == 0:
            return 0
            
        min_distance = float('inf')
        
        # For each non-zero linear combination of output bits
        for b in range(1, 1 << m):
            # For each affine function a·x + c
            for a in range(1 << n):
                for c in [0, 1]:
                    distance = 0
                    
                    # Calculate Hamming distance between the component function and the affine function
                    for x in range(len(sbox)):
                        # Component function: b·S(x) mod 2
                        component = bin(b & sbox[x]).count('1') % 2
                        
                        # Affine function: a·x + c mod 2
                        affine = (bin(a & x).count('1') + c) % 2
                        
                        # Accumulate Hamming distance
                        if component != affine:
                            distance += 1
                    
                    # Update minimum distance
                    min_distance = min(min_distance, distance)
        
        return min_distance
    
    @staticmethod
    def sac(sbox: List[int]) -> float:
        """Calculate the Strict Avalanche Criterion (SAC) score."""
        n = len(sbox).bit_length() - 1
        m = (sbox[0].bit_length() if sbox else 0)
        total = 0
        
        for i in range(n):
            mask = 1 << i
            for x in range(len(sbox)):
                y1 = sbox[x]
                y2 = sbox[x ^ mask]
                delta = y1 ^ y2
                total += bin(delta).count('1')
        
        return total / (n * len(sbox) * m)
    
    @staticmethod
    def differential_uniformity(sbox: List[int]) -> int:
        """Calculate the differential uniformity of the S-box."""
        n = len(sbox)
        delta = {}
        
        for a in range(1, n):
            for x in range(n):
                b = sbox[x] ^ sbox[x ^ a]
                delta[(a, b)] = delta.get((a, b), 0) + 1
        
        return max(delta.values()) if delta else 0
    
    @staticmethod
    def algebraic_degree(sbox: List[int]) -> int:
        """
        Calculate the algebraic degree of the S-box.
        The algebraic degree is the maximum degree of the algebraic normal form (ANF)
        of the component functions of the S-box.
        """
        n = (len(sbox) - 1).bit_length()  # Input size in bits
        m = max(sbox).bit_length() if sbox else 0  # Output size in bits
        
        if n == 0 or m == 0:
            return 0
            
        max_degree = 0
        
        # For each output bit
        for output_bit in range(m):
            # Create truth table for this output bit
            truth_table = [0] * (1 << n)
            for x in range(len(sbox)):
                truth_table[x] = (sbox[x] >> output_bit) & 1
            
            # Convert to algebraic normal form (ANF) using Moebius transform
            anf = truth_table.copy()
            for i in range(n):
                for j in range(1 << n):
                    if (j >> i) & 1:
                        anf[j] ^= anf[j ^ (1 << i)]
            
            # The degree is the maximum Hamming weight of any non-zero coefficient
            degree = max((bin(j).count('1') for j, coeff in enumerate(anf) if coeff), default=0)
            max_degree = max(max_degree, degree)
        
        return max_degree


class TestSBoxValidation(unittest.TestCase):
    """Test cases for S-box validation."""
    
    def setUp(self):
        # AES S-box for testing
        self.aes_sbox = [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        ]
        
        # Identity S-box for testing
        self.identity_sbox = list(range(256))
        
        # Validator instance
        self.validator = SBoxValidator()
    
    def test_completeness(self):
        """Test that the S-box is complete."""
        # Test with a small complete S-box
        complete_sbox = [0, 1, 3, 2, 6, 7, 5, 4]  # Example of a complete S-box
        self.assertTrue(self.validator.is_complete(complete_sbox))
        
        # Test with a small incomplete S-box (output doesn't change with input bit 0)
        incomplete_sbox = [0, 0, 1, 1, 2, 2, 3, 3]
        self.assertFalse(self.validator.is_complete(incomplete_sbox))
        
        # Test with a bijective S-box (should be complete)
        bijective_sbox = [1, 0, 3, 2, 5, 4, 7, 6]
        self.assertTrue(self.validator.is_complete(bijective_sbox))
    
    def test_balance(self):
        """Test that the S-box is balanced."""
        # Test with a small balanced S-box (bijective 2-bit)
        # Each output appears exactly once
        balanced_sbox = [1, 0, 3, 2]
        self.assertTrue(self.validator.is_balanced(balanced_sbox),
                       "Bijective S-box should be balanced")
        
        # Test with an unbalanced S-box (2-bit to 1-bit)
        # Output 0 appears 3 times, output 1 appears once
        unbalanced_sbox = [0, 0, 0, 1]
        self.assertFalse(self.validator.is_balanced(unbalanced_sbox),
                        "S-box with uneven output distribution should be unbalanced")
        
        # Test with a non-bijective but balanced S-box (3-bit to 2-bit)
        # Each output (0-3) appears exactly twice
        balanced_non_bijective = [0, 1, 1, 0, 2, 3, 3, 2]
        self.assertTrue(self.validator.is_balanced(balanced_non_bijective),
                      "Non-bijective but balanced S-box should be balanced")
    
    def test_nonlinearity(self):
        """Test the nonlinearity of the S-box."""
        # Test with a linear S-box (2-bit)
        # f(x1,x0) = x1 (linear function)
        linear_sbox = [0, 0, 1, 1]
        self.assertEqual(self.validator.nonlinearity(linear_sbox), 0,
                        "Linear S-box should have nonlinearity 0")
        
        # Test with a non-linear S-box (2-bit)
        # f(x1,x0) = x1 AND x0 (nonlinear)
        # This is the AND function which is maximally non-linear for 2 bits
        nonlinear_sbox = [0, 0, 0, 1]
        self.assertEqual(self.validator.nonlinearity(nonlinear_sbox), 1,
                        "Nonlinear S-box should have positive nonlinearity")
        
        # Test with the identity S-box (should be linear)
        identity_sbox = [0, 1, 2, 3]
        self.assertEqual(self.validator.nonlinearity(identity_sbox), 0,
                        "Identity S-box should be linear (nonlinearity=0)")
        
        # Test that the nonlinearity is within expected bounds for AES S-box
        nl = self.validator.nonlinearity(self.aes_sbox)
        self.assertGreaterEqual(nl, 100, 
                              f"AES S-box nonlinearity ({nl}) should be >= 100")
        self.assertLessEqual(nl, 120, 
                           f"AES S-box nonlinearity ({nl}) should be <= 120")
        
    def test_sac(self):
        """Test the Strict Avalanche Criterion."""
        # SAC should be close to 0.5 for good S-boxes
        sac_score = self.validator.sac(self.aes_sbox)
        self.assertAlmostEqual(sac_score, 0.5, delta=0.1)
    
    def test_differential_uniformity(self):
        """Test the differential uniformity of the S-box."""
        # AES S-box has differential uniformity of 4
        self.assertEqual(self.validator.differential_uniformity(self.aes_sbox), 4)
    
    def test_algebraic_degree(self):
        """Test the algebraic degree of the S-box."""
        # Test with a small S-box where we know the algebraic degree
        # For a 2-bit S-box [0, 1, 3, 2], the algebraic degree is 1 (linear)
        linear_sbox = [0, 1, 3, 2]  # f(x1,x0) = x1 + x0 (degree 1)
        self.assertEqual(self.validator.algebraic_degree(linear_sbox), 1)
        
        # Test with a quadratic S-box
        quadratic_sbox = [0, 1, 2, 3, 4, 5, 7, 6]  # f(x2,x1,x0) = x1 + x0 + x1x0 (degree 2)
        self.assertEqual(self.validator.algebraic_degree(quadratic_sbox), 2)
        
        # Test that the algebraic degree is within expected bounds for AES S-box
        degree = self.validator.algebraic_degree(self.aes_sbox)
        self.assertGreaterEqual(degree, 6)  # AES S-box has degree 7
        self.assertLessEqual(degree, 7)     # Maximum possible for 8-bit S-box


if __name__ == "__main__":
    unittest.main()
