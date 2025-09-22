# QuMail Quantum Key Distribution Simulator
# Task 21: BB84 QKD Protocol Implementation using Qiskit
# ETSI GS QKD 014 Compliant Quantum Key Distribution
# ISRO Smart India Hackathon 2025

import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple, Optional
import json

class BB84QKDSimulator:
    """
    BB84 Quantum Key Distribution Protocol Simulator
    Implements Alice-Bob quantum key exchange with eavesdropping detection
    """
    
    def __init__(self, key_length: int = 256, error_threshold: float = 0.15, fast_mode: bool = True):
        """
        Initialize BB84 QKD Simulator
        
        Args:
            key_length: Target key length in bits (default: 256)
            error_threshold: Maximum acceptable error rate (default: 15%)
            fast_mode: Use optimized simulation for demos (default: True)
        """
        self.key_length = key_length
        self.error_threshold = error_threshold
        self.fast_mode = fast_mode
        self.simulator = AerSimulator()
        
        # QKD Parameters (optimized for speed if fast_mode)
        if fast_mode:
            self.raw_key_multiplier = 2  # Reduced from 4 to 2 for speed
            self.sample_size = min(32, key_length // 8)  # Smaller sample for speed
        else:
            self.raw_key_multiplier = 4  # Full simulation
            self.sample_size = max(64, key_length // 4)  # Full error estimation
        
    def generate_random_bits(self, length: int) -> List[int]:
        """Generate cryptographically secure random bits"""
        return [secrets.randbelow(2) for _ in range(length)]
    
    def generate_random_bases(self, length: int) -> List[int]:
        """Generate random basis choices (0=rectilinear, 1=diagonal)"""
        return [secrets.randbelow(2) for _ in range(length)]
    
    def create_bb84_states(self, bits: List[int], bases: List[int]) -> List[QuantumCircuit]:
        """
        Create quantum states according to BB84 protocol
        
        Args:
            bits: List of classical bits to encode
            bases: List of basis choices (0=rectilinear, 1=diagonal)
            
        Returns:
            List of quantum circuits representing the encoded states
        """
        circuits = []
        
        for bit, basis in zip(bits, bases):
            qc = QuantumCircuit(1, 1)
            
            # Encode bit in chosen basis
            if basis == 0:  # Rectilinear basis {|0⟩, |1⟩}
                if bit == 1:
                    qc.x(0)  # |1⟩ state
                # |0⟩ state requires no operation
            else:  # Diagonal basis {|+⟩, |−⟩}
                if bit == 0:
                    qc.h(0)  # |+⟩ = (|0⟩ + |1⟩)/√2
                else:
                    qc.x(0)
                    qc.h(0)  # |−⟩ = (|0⟩ - |1⟩)/√2
            
            circuits.append(qc)
        
        return circuits
    
    def measure_bb84_states(self, circuits: List[QuantumCircuit], 
                           bob_bases: List[int]) -> List[int]:
        """
        Measure quantum states in Bob's chosen bases
        
        Args:
            circuits: List of quantum circuits from Alice
            bob_bases: Bob's basis choices for measurement
            
        Returns:
            Bob's measurement results
        """
        if self.fast_mode and len(circuits) > 50:
            # Batch processing for speed
            return self._measure_bb84_states_batch(circuits, bob_bases)
        
        measurements = []
        
        for qc, bob_basis in zip(circuits, bob_bases):
            # Create measurement circuit
            measure_qc = qc.copy()
            
            # Apply Bob's measurement basis
            if bob_basis == 1:  # Diagonal measurement
                measure_qc.h(0)  # Transform to diagonal basis
            
            # Measure in computational basis
            measure_qc.measure(0, 0)
            
            # Execute circuit
            transpiled_qc = transpile(measure_qc, self.simulator)
            job = self.simulator.run(transpiled_qc, shots=1)
            result = job.result()
            counts = result.get_counts()
            
            # Extract measurement result
            measured_bit = int(list(counts.keys())[0])
            measurements.append(measured_bit)
        
        return measurements
    
    def _measure_bb84_states_batch(self, circuits: List[QuantumCircuit], 
                                  bob_bases: List[int]) -> List[int]:
        """Fast batch measurement for demo purposes"""
        measurements = []
        batch_size = 50  # Process in smaller batches
        
        for i in range(0, len(circuits), batch_size):
            batch_circuits = circuits[i:i+batch_size]
            batch_bases = bob_bases[i:i+batch_size]
            
            # Prepare batch
            measure_circuits = []
            for qc, bob_basis in zip(batch_circuits, batch_bases):
                measure_qc = qc.copy()
                if bob_basis == 1:  # Diagonal measurement
                    measure_qc.h(0)
                measure_qc.measure(0, 0)
                measure_circuits.append(measure_qc)
            
            # Execute batch
            transpiled_circuits = transpile(measure_circuits, self.simulator)
            job = self.simulator.run(transpiled_circuits, shots=1)
            result = job.result()
            
            # Extract results
            for j, qc in enumerate(measure_circuits):
                counts = result.get_counts(j)
                measured_bit = int(list(counts.keys())[0])
                measurements.append(measured_bit)
        
        return measurements
    
    def sift_key(self, alice_bits: List[int], alice_bases: List[int],
                 bob_measurements: List[int], bob_bases: List[int]) -> Tuple[List[int], List[int]]:
        """
        Perform key sifting - keep only bits where Alice and Bob used same basis
        
        Returns:
            Tuple of (sifted_alice_key, sifted_bob_key)
        """
        alice_sifted = []
        bob_sifted = []
        
        for i, (a_basis, b_basis) in enumerate(zip(alice_bases, bob_bases)):
            if a_basis == b_basis:  # Same basis used
                alice_sifted.append(alice_bits[i])
                bob_sifted.append(bob_measurements[i])
        
        return alice_sifted, bob_sifted
    
    def estimate_error_rate(self, alice_key: List[int], bob_key: List[int],
                           sample_size: int) -> float:
        """
        Estimate quantum bit error rate (QBER) by comparing random sample
        
        Returns:
            Error rate as float (0.0 to 1.0)
        """
        if len(alice_key) < sample_size:
            sample_size = len(alice_key) // 2
        
        if sample_size == 0:
            return 0.0
        
        # Select random positions for error estimation
        total_length = len(alice_key)
        sample_positions = secrets.SystemRandom().sample(range(total_length), sample_size)
        
        errors = 0
        for pos in sample_positions:
            if alice_key[pos] != bob_key[pos]:
                errors += 1
        
        return errors / sample_size
    
    def add_channel_noise(self, circuits: List[QuantumCircuit], 
                         noise_level: float = 0.05) -> List[QuantumCircuit]:
        """
        Add realistic channel noise to quantum circuits
        
        Args:
            circuits: Original quantum circuits
            noise_level: Probability of bit flip error
            
        Returns:
            Noisy quantum circuits
        """
        noisy_circuits = []
        
        for qc in circuits:
            noisy_qc = qc.copy()
            
            # Add bit flip noise with given probability
            if secrets.SystemRandom().random() < noise_level:
                noisy_qc.x(0)  # Apply bit flip
            
            noisy_circuits.append(noisy_qc)
        
        return noisy_circuits
    
    def add_measurement_noise(self, measurements: List[int], 
                             noise_level: float = 0.05) -> List[int]:
        """
        Add realistic measurement noise to Bob's results
        
        Args:
            measurements: Bob's original measurement results
            noise_level: Probability of measurement error
            
        Returns:
            Noisy measurement results
        """
        noisy_measurements = []
        
        for measurement in measurements:
            # Add measurement error with given probability
            if secrets.SystemRandom().random() < noise_level:
                # Flip the measurement result
                noisy_measurements.append(1 - measurement)
            else:
                noisy_measurements.append(measurement)
        
        return noisy_measurements
    
    def generate_qkd_key(self, target_length: int = None, 
                        eavesdropper_present: bool = False) -> Dict:
        """
        Generate quantum key using BB84 protocol
        
        Args:
            target_length: Desired key length (default: self.key_length)
            eavesdropper_present: Simulate eavesdropping attack
            
        Returns:
            Dictionary with ETSI GS QKD 014 compliant key data
        """
        if target_length is None:
            target_length = self.key_length
        
        # Calculate required raw bits (accounting for sifting losses)
        raw_length = target_length * self.raw_key_multiplier
        
        if raw_length > 100:  # Show progress for larger keys
            print(f"  🔬 BB84 Protocol: Generating {raw_length} raw bits for {target_length}-bit key...")
        
        # Step 1: Alice generates random bits and bases
        alice_bits = self.generate_random_bits(raw_length)
        alice_bases = self.generate_random_bases(raw_length)
        
        # Step 2: Alice prepares quantum states
        quantum_states = self.create_bb84_states(alice_bits, alice_bases)
        
        # Step 3: Add channel noise and potential eavesdropping
        # Realistic QKD noise levels: 1-8% depending on distance and conditions
        base_noise = 0.01 + (secrets.SystemRandom().random() * 0.07)  # 1-8% random base noise
        if eavesdropper_present:
            base_noise += 0.08 + (secrets.SystemRandom().random() * 0.12)  # Additional 8-20% from Eve
        
        noisy_states = self.add_channel_noise(quantum_states, base_noise)
        
        # Step 4: Bob generates random measurement bases
        bob_bases = self.generate_random_bases(raw_length)
        
        # Step 5: Bob measures the quantum states
        bob_measurements = self.measure_bb84_states(noisy_states, bob_bases)
        
        # Step 5.5: Add realistic measurement noise (detector inefficiencies, etc.)
        measurement_noise = 0.005 + (secrets.SystemRandom().random() * 0.015)  # 0.5-2% measurement noise
        bob_measurements = self.add_measurement_noise(bob_measurements, measurement_noise)
        
        # Step 6: Public discussion and key sifting
        alice_sifted, bob_sifted = self.sift_key(alice_bits, alice_bases, 
                                               bob_measurements, bob_bases)
        
        # Step 7: Error estimation
        error_rate = self.estimate_error_rate(alice_sifted, bob_sifted, 
                                            self.sample_size)
        
        # Step 8: Privacy amplification (simple truncation for this simulation)
        if len(alice_sifted) >= target_length:
            final_key = alice_sifted[:target_length]
        else:
            # Pad with additional bits if needed (rare case)
            final_key = alice_sifted
            while len(final_key) < target_length:
                additional_bits = self.generate_random_bits(
                    min(32, target_length - len(final_key))
                )
                final_key.extend(additional_bits)
            final_key = final_key[:target_length]
        
        # Convert to hex string
        hex_key = self._bits_to_hex(final_key)
        
        # Calculate quantum metrics
        sifting_efficiency = len(alice_sifted) / len(alice_bits) if alice_bits else 0
        quantum_fidelity = 1.0 - error_rate
        
        # Add some realistic variation to fidelity (detector inefficiencies, etc.)
        fidelity_variation = (secrets.SystemRandom().random() - 0.5) * 0.02  # ±1% variation
        quantum_fidelity = max(0.0, min(1.0, quantum_fidelity + fidelity_variation))
        
        # Determine security level based on error rate and fidelity
        if error_rate <= 0.02 and quantum_fidelity >= 0.98:
            security_level = 1  # Excellent - Perfect conditions
        elif error_rate <= 0.05 and quantum_fidelity >= 0.95:
            security_level = 2  # Good - Good conditions
        elif error_rate <= 0.10 and quantum_fidelity >= 0.90:
            security_level = 3  # Acceptable - Moderate conditions
        elif error_rate <= 0.15 and quantum_fidelity >= 0.85:
            security_level = 4  # Poor - Challenging conditions
        else:
            security_level = 5  # Critical - Should be rejected
        
        # Generate unique key ID
        timestamp = int(time.time() * 1000)
        key_id = f"qkd_bb84_{timestamp}_{secrets.randbelow(1000)}"
        
        # ETSI GS QKD 014 compliant response
        qkd_key_data = {
            "key_id": key_id,
            "key": hex_key,
            "metadata": {
                "length": len(final_key),
                "error_rate": round(error_rate, 4),
                "protocol": "BB84",
                "security_level": security_level,
                "fidelity": round(quantum_fidelity, 4),
                "distance_km": round(10 + (secrets.randbelow(90)), 1),  # 10-100 km distance
                "sifting_efficiency": round(sifting_efficiency, 4),
                "raw_bits_generated": len(alice_bits),
                "sifted_bits": len(alice_sifted),
                "sample_size": self.sample_size,
                "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace('+00:00', 'Z'),
                "status": "available",
                "quantum_parameters": {
                    "basis_reconciliation_rate": round(sifting_efficiency, 4),
                    "channel_noise_level": round(base_noise, 4),
                    "measurement_noise_level": round(measurement_noise, 4),
                    "total_noise_level": round(base_noise + measurement_noise, 4),
                    "eavesdropper_detected": error_rate > self.error_threshold,
                    "bb84_efficiency": round(len(final_key) / raw_length, 4)
                }
            }
        }
        
        return qkd_key_data
    
    def _bits_to_hex(self, bits: List[int]) -> str:
        """Convert list of bits to hexadecimal string"""
        # Pad to multiple of 4 bits
        padded_bits = bits[:]
        while len(padded_bits) % 4 != 0:
            padded_bits.append(0)
        
        hex_string = ""
        for i in range(0, len(padded_bits), 4):
            nibble = padded_bits[i:i+4]
            hex_value = 0
            for j, bit in enumerate(nibble):
                hex_value += bit * (2 ** (3-j))
            hex_string += format(hex_value, 'x')
        
        return hex_string
    
    def generate_multiple_keys(self, count: int = 5, key_length: int = None) -> List[Dict]:
        """
        Generate multiple QKD keys for key pool management
        
        Args:
            count: Number of keys to generate
            key_length: Length of each key
            
        Returns:
            List of ETSI GS QKD 014 compliant key data
        """
        keys = []
        
        for i in range(count):
            # Randomly decide if eavesdropper is present (10% chance)
            eavesdropper = secrets.SystemRandom().random() < 0.1
            
            key_data = self.generate_qkd_key(
                target_length=key_length,
                eavesdropper_present=eavesdropper
            )
            
            keys.append(key_data)
            
            # Small delay between key generations
            time.sleep(0.1)
        
        return keys
    
    def validate_key_security(self, key_data: Dict) -> Dict:
        """
        Validate key security according to QKD standards
        
        Returns:
            Validation result with recommendations
        """
        metadata = key_data.get("metadata", {})
        error_rate = metadata.get("error_rate", 0)
        fidelity = metadata.get("fidelity", 1)
        
        validation = {
            "is_secure": error_rate <= self.error_threshold,
            "security_grade": metadata.get("security_level", 4),
            "recommendations": []
        }
        
        if error_rate > self.error_threshold:
            validation["recommendations"].append(
                f"ERROR RATE TOO HIGH: {error_rate*100:.2f}% > {self.error_threshold*100}% threshold"
            )
        
        if fidelity < 0.85:
            validation["recommendations"].append(
                f"LOW FIDELITY: {fidelity:.3f} < 0.85 minimum"
            )
        
        if metadata.get("quantum_parameters", {}).get("eavesdropper_detected", False):
            validation["recommendations"].append("EAVESDROPPING DETECTED: Consider key rejection")
        
        return validation

# Factory function for integration with Flask
def create_bb84_simulator(fast_mode: bool = True) -> BB84QKDSimulator:
    """Create and return a BB84 QKD simulator instance"""
    return BB84QKDSimulator(key_length=256, error_threshold=0.15, fast_mode=fast_mode)

# Test functions
def test_bb84_simulation():
    """Test the BB84 QKD simulator"""
    print("🔬 Testing BB84 QKD Simulator...")
    
    simulator = create_bb84_simulator()
    
    # Test single key generation
    print("\n📝 Generating single QKD key...")
    key_data = simulator.generate_qkd_key()
    
    print(f"✅ Key ID: {key_data['key_id']}")
    print(f"🔑 Key Length: {key_data['metadata']['length']} bits")
    print(f"📊 Error Rate: {key_data['metadata']['error_rate']*100:.2f}%")
    print(f"🎯 Fidelity: {key_data['metadata']['fidelity']:.3f}")
    print(f"🔒 Security Level: {key_data['metadata']['security_level']}")
    
    # Test validation
    validation = simulator.validate_key_security(key_data)
    print(f"✅ Security Valid: {validation['is_secure']}")
    
    # Test multiple key generation
    print("\n📝 Generating multiple QKD keys...")
    keys = simulator.generate_multiple_keys(count=3)
    
    for i, key in enumerate(keys):
        print(f"Key {i+1}: {key['key_id']} "
              f"(Level {key['metadata']['security_level']}, "
              f"{key['metadata']['error_rate']*100:.1f}% error)")
    
    print("\n✅ BB84 QKD Simulator test completed!")
    return key_data

if __name__ == "__main__":
    test_bb84_simulation()
