"""Utility helpers for streaming decryption workflows."""

from __future__ import annotations

import os
from typing import Iterable, List, Optional, Sequence, Union

from pipeline import (
    MultiLayerPipeline,
    read_file_chunked,
    write_chunks_to_file,
)


def load_encrypted_shares(
    share_paths: Sequence[str],
    chunk_size: int,
) -> List[bytes]:
    """Read encrypted share files using the streaming helper."""

    return [read_file_chunked(path, chunk_size) for path in share_paths]


def write_decrypted_output(
    output_path: str,
    data: Union[bytes, bytearray, memoryview, Iterable[bytes]],
    chunk_size: int,
) -> None:
    """Persist decrypted data using chunked writes."""

    write_chunks_to_file(output_path, data, chunk_size)


def decrypt_shares_to_file(
    share_paths: Sequence[str],
    output_path: str,
    pipeline: Optional[MultiLayerPipeline] = None,
    *,
    chunk_size: Optional[int] = None,
    private_key: Optional[bytes] = None,
    progress_callback: Optional[callable] = None,
) -> bytes:
    """Decrypt shares using the configured pipeline while streaming IO."""

    pipeline = pipeline or MultiLayerPipeline()
    effective_chunk_size = chunk_size or pipeline.config.chunk_size
    decrypted = pipeline.decrypt_file(
        list(share_paths),
        output_path,
        private_key=private_key,
        progress_callback=progress_callback,
    )

    if isinstance(decrypted, bytes) and not os.path.exists(output_path):
        write_chunks_to_file(output_path, decrypted, effective_chunk_size)

    return decrypted
