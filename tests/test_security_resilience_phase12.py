"""Regression tests for Security & Resilience phase 1.2."""

from entropy_monitor import benchmark_entropy_sources, EntropySource
from mlkem_layer import PostQuantumMLKEM
from distributed_workflows import MultiPartyKeyWorkflow
from threshold_crypto import ThresholdCrypto
from config import SECURITY_LEVEL_BYTES


def test_entropy_benchmark_reports_new_sources():
    metrics = benchmark_entropy_sources(samples=1, sample_size=64)
    expected_sources = {
        EntropySource.INTERRUPT.name,
        EntropySource.DISK_ACTIVITY.name,
        EntropySource.NETWORK_ACTIVITY.name,
        EntropySource.USER_INPUT.name,
    }
    assert expected_sources.issubset(metrics.keys())


def test_mlkem_hybrid_combination_size():
    engine = PostQuantumMLKEM()
    keypair = engine.generate_keypair()
    hybrid_result = engine.hybrid_encapsulate(keypair.public_key)
    assert len(hybrid_result.combined_secret) == SECURITY_LEVEL_BYTES
    assert hybrid_result.mlkem_result.key_id == hybrid_result.key_id


def test_pqc_registry_lists_multiple_algorithms():
    engine = PostQuantumMLKEM()
    algorithms = engine.list_algorithms()
    names = {profile.name for profile in algorithms}
    assert "ML-KEM-1024" in names
    assert "Hybrid-MLKEM-X25519" in names
    assert len(algorithms) >= 3


def test_distributed_workflow_secret_recovery():
    engine = PostQuantumMLKEM()
    workflow = MultiPartyKeyWorkflow(threshold=2, total_shares=3, mlkem_engine=engine, threshold_crypto=ThresholdCrypto())

    participants = []
    for pid in ("alice", "bob", "carol"):
        keypair = engine.generate_keypair()
        workflow.add_participant(pid, keypair.public_key)
        participants.append(pid)

    secret = b"phase-1.2-secret-material"
    workflow.initiate_ceremony(secret)

    recovered = workflow.recover_secret(participants[:2])
    assert recovered == secret

