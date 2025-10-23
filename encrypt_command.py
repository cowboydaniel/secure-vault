"""Command-line helpers for file encryption."""

from __future__ import annotations

import sys
from typing import Optional, Callable

from pipeline import MultiLayerPipeline, PipelineConfiguration
from file_utils import InputFileValidationError, validate_input_file


def run_encrypt_command(
    input_path: str,
    *,
    config: Optional[PipelineConfiguration] = None,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> bool:
    """Encrypt ``input_path`` using the interactive pipeline command.

    This helper performs validation before delegating to :class:`MultiLayerPipeline`
    so that command-line users receive descriptive error messages for
    unsupported files.

    Args:
        input_path: Path to the file that should be encrypted.
        config: Optional pipeline configuration. When ``None`` the default
            configuration is used.
        progress_callback: Optional callback for progress updates.

    Returns:
        ``True`` if encryption succeeds, ``False`` otherwise.
    """

    pipeline = MultiLayerPipeline(config)

    try:
        validate_input_file(input_path, pipeline.config.max_input_size_bytes)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return False
    except InputFileValidationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return False

    try:
        pipeline.encrypt_file(input_path, progress_callback=progress_callback)
    except Exception as exc:  # pragma: no cover - pipeline tested elsewhere
        print(f"Encryption failed: {exc}", file=sys.stderr)
        return False
    finally:
        pipeline.shutdown()

    return True
