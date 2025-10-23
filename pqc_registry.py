"""Registry for available post-quantum cryptography algorithms."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class PQCAlgorithmProfile:
    """Metadata describing a PQC algorithm option."""

    name: str
    description: str
    category: str
    security_level: str
    is_available: bool = False
    requires_liboqs: bool = False
    simulated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class PQCAlgorithmRegistry:
    """Simple in-memory registry for PQC algorithm profiles."""

    def __init__(self) -> None:
        self._algorithms: Dict[str, PQCAlgorithmProfile] = {}

    def register(self, profile: PQCAlgorithmProfile) -> None:
        """Register or update an algorithm profile."""

        self._algorithms[profile.name] = profile

    def list_algorithms(self) -> List[PQCAlgorithmProfile]:
        """Return the complete list of registered algorithms."""

        return list(self._algorithms.values())

    def get(self, name: str) -> Optional[PQCAlgorithmProfile]:
        """Retrieve a profile by name."""

        return self._algorithms.get(name)

    def mark_available(self, name: str, available: bool) -> None:
        """Update the availability flag for an algorithm."""

        if name in self._algorithms:
            self._algorithms[name].is_available = available

    def register_default_algorithms(self, liboqs_available: bool) -> None:
        """Populate the registry with default PQC algorithms."""

        defaults = [
            PQCAlgorithmProfile(
                name="ML-KEM-1024",
                description="NIST Round 3 finalist (Kyber) providing IND-CCA security",
                category="KEM",
                security_level="Category 5",
                is_available=True,
                requires_liboqs=True,
                metadata={"preferred": True},
            ),
            PQCAlgorithmProfile(
                name="ML-KEM-768",
                description="Kyber variant targeting Category 3 security",
                category="KEM",
                security_level="Category 3",
                requires_liboqs=True,
            ),
            PQCAlgorithmProfile(
                name="FrodoKEM-1344",
                description="Lattice-based KEM relying on Learning With Errors",
                category="KEM",
                security_level="Category 5",
                requires_liboqs=True,
            ),
            PQCAlgorithmProfile(
                name="Classic-McEliece-348864",
                description="Code-based KEM with large public keys",
                category="KEM",
                security_level="Category 5",
                requires_liboqs=True,
            ),
            PQCAlgorithmProfile(
                name="Hybrid-MLKEM-X25519",
                description="Hybrid combination of ML-KEM and X25519 for transitional deployments",
                category="Hybrid",
                security_level="Category 5",
                simulated=True,
                is_available=True,
            ),
        ]

        for profile in defaults:
            if profile.requires_liboqs and not liboqs_available:
                profile.is_available = False
            self.register(profile)

