"""Multi-party key ceremony workflows leveraging ML-KEM hybrid encapsulation."""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from threshold_crypto import ThresholdCrypto, KeyShare
from mlkem_layer import PostQuantumMLKEM, HybridEncapsulationResult


@dataclass
class Participant:
    """Represents a participant in a key ceremony."""

    participant_id: str
    mlkem_public_key: bytes
    classical_public_key: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False


@dataclass
class CeremonyState:
    """Tracks the state of an ongoing multi-party ceremony."""

    workflow_id: str
    threshold: int
    total_shares: int
    created_at: float = field(default_factory=time.time)
    shares: Dict[str, KeyShare] = field(default_factory=dict)
    hybrid_packages: Dict[str, HybridEncapsulationResult] = field(default_factory=dict)


class MultiPartyKeyWorkflow:
    """Coordinator for distributed key ceremonies using ML-KEM."""

    def __init__(
        self,
        threshold: int,
        total_shares: int,
        mlkem_engine: Optional[PostQuantumMLKEM] = None,
        threshold_crypto: Optional[ThresholdCrypto] = None,
    ) -> None:
        if threshold < 2:
            raise ValueError("Threshold must be at least 2")
        if total_shares < threshold:
            raise ValueError("Total shares must be greater than or equal to the threshold")

        self.threshold = threshold
        self.total_shares = total_shares
        self.mlkem_engine = mlkem_engine or PostQuantumMLKEM()
        self.threshold_crypto = threshold_crypto or ThresholdCrypto()
        self.participants: Dict[str, Participant] = {}
        self.state: Optional[CeremonyState] = None

    def add_participant(
        self,
        participant_id: str,
        mlkem_public_key: bytes,
        classical_public_key: Optional[bytes] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register a ceremony participant."""

        if participant_id in self.participants:
            raise ValueError(f"Participant '{participant_id}' already registered")

        self.participants[participant_id] = Participant(
            participant_id=participant_id,
            mlkem_public_key=mlkem_public_key,
            classical_public_key=classical_public_key,
            metadata=metadata or {},
        )

    def initiate_ceremony(self, secret: bytes) -> CeremonyState:
        """Split ``secret`` and encapsulate it for each participant."""

        if len(self.participants) < self.total_shares:
            raise RuntimeError("Not enough participants registered for ceremony")

        workflow_id = f"ceremony_{int(time.time())}_{len(self.participants)}"
        shares = self.threshold_crypto.generate_shares(
            secret=secret,
            threshold=self.threshold,
            total_shares=self.total_shares,
            key_id=workflow_id,
        )

        state = CeremonyState(
            workflow_id=workflow_id,
            threshold=self.threshold,
            total_shares=self.total_shares,
        )

        for participant, share in zip(self.participants.values(), shares):
            hybrid_package = self.mlkem_engine.hybrid_encapsulate(
                participant.mlkem_public_key,
                participant.classical_public_key,
            )
            state.shares[participant.participant_id] = share
            state.hybrid_packages[participant.participant_id] = hybrid_package

        self.state = state
        return state

    def get_participant_package(self, participant_id: str) -> Dict[str, Any]:
        """Return the hybrid package for a participant."""

        if not self.state:
            raise RuntimeError("Ceremony has not been initiated")

        if participant_id not in self.state.shares:
            raise KeyError(f"Unknown participant '{participant_id}'")

        participant = self.participants[participant_id]
        package = {
            'share': self.state.shares[participant_id],
            'hybrid_result': self.state.hybrid_packages[participant_id],
            'metadata': participant.metadata,
        }
        return package

    def record_acknowledgement(self, participant_id: str) -> None:
        """Mark a participant's package as acknowledged."""

        if participant_id not in self.participants:
            raise KeyError(f"Unknown participant '{participant_id}'")

        self.participants[participant_id].acknowledged = True

    def recover_secret(self, participant_ids: List[str]) -> bytes:
        """Reconstruct the secret from the provided participant IDs."""

        if not self.state:
            raise RuntimeError("Ceremony has not been initiated")
        if len(participant_ids) < self.threshold:
            raise ValueError("Not enough shares provided for recovery")

        shares = [self.state.shares[pid] for pid in participant_ids]
        return self.threshold_crypto.reconstruct_secret(shares)

    def export_transcript(self) -> Dict[str, Any]:
        """Export a transcript describing the ceremony state."""

        if not self.state:
            raise RuntimeError("Ceremony has not been initiated")

        participants = []
        for participant_id, participant in self.participants.items():
            participants.append({
                'participant_id': participant_id,
                'acknowledged': participant.acknowledged,
                'metadata': participant.metadata,
                'algorithm_profile': (
                    self.state.hybrid_packages[participant_id].algorithm_profile.name
                    if self.state.hybrid_packages[participant_id].algorithm_profile
                    else 'Hybrid-MLKEM-X25519'
                ),
            })

        return {
            'workflow_id': self.state.workflow_id,
            'threshold': self.state.threshold,
            'total_shares': self.state.total_shares,
            'created_at': self.state.created_at,
            'participants': participants,
        }

