"""Share manager utilities for propagating OTP counter metadata."""

import logging
from typing import Dict, Any, Optional

from key_manager import KeyManager, KeyType

logger = logging.getLogger(__name__)


class ShareSynchronizationError(Exception):
    """Raised when OTP counter synchronization fails."""


class ShareManager:
    """Manage synchronization of shared key metadata across peers."""

    def __init__(self, key_manager: KeyManager):
        self._key_manager = key_manager
        self._cached_state: Dict[str, Dict[str, Any]] = {}

    def export_otp_counter_state(self) -> Dict[str, Dict[str, Any]]:
        """Collect OTP counter metadata for synchronization."""
        state: Dict[str, Dict[str, Any]] = {}

        for metadata in self._key_manager.list_keys(KeyType.OTP):
            custom = metadata.custom_metadata or {}
            state[metadata.key_id] = {
                'otp_next_counter': int(custom.get('otp_next_counter', 0)),
                'otp_used_counters': list(custom.get('otp_used_counters', [])),
                'otp_decryption_counters': list(custom.get('otp_decryption_counters', [])),
                'otp_nonce_size': int(custom.get('otp_nonce_size', 16)),
            }

        self._cached_state = state
        return state

    def apply_remote_counter_state(self, remote_state: Optional[Dict[str, Dict[str, Any]]]) -> None:
        """Merge remote OTP counter state into the local key metadata."""
        if not remote_state:
            return

        for key_id, state in remote_state.items():
            try:
                metadata = self._key_manager.get_key_metadata(key_id)
                if not metadata:
                    logger.debug("Skipping unknown key %s during synchronization", key_id)
                    continue

                custom = dict(metadata.custom_metadata or {})

                used_counters = set(custom.get('otp_used_counters', []))
                used_counters.update(state.get('otp_used_counters', []))

                decrypted_counters = set(custom.get('otp_decryption_counters', []))
                decrypted_counters.update(state.get('otp_decryption_counters', []))

                next_counter = max(
                    int(custom.get('otp_next_counter', 0)),
                    int(state.get('otp_next_counter', 0))
                )

                nonce_size = int(state.get('otp_nonce_size', custom.get('otp_nonce_size', 16)))

                custom.update({
                    'otp_next_counter': next_counter,
                    'otp_used_counters': sorted(used_counters),
                    'otp_decryption_counters': sorted(decrypted_counters),
                    'otp_nonce_size': nonce_size
                })

                self._key_manager.update_key_metadata(key_id, custom_metadata=custom)
            except Exception as exc:
                logger.error("Failed to synchronize counters for key %s: %s", key_id, exc)
                raise ShareSynchronizationError(str(exc)) from exc

    def synchronize_with_remote(self, remote_state: Optional[Dict[str, Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
        """Synchronize local and remote OTP counter states."""
        self.apply_remote_counter_state(remote_state)
        return self.export_otp_counter_state()
