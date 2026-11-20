# SPDX-License-Identifier: GPL-3.0-only
"""Seed word lists, from Ark Core (``patronus_ark_core.seed_word_list``).

Ark Core is imported on first use: ``dlp_synth`` stays importable without any
native package (``scripts/l1_dlp/prepare_corpora.py``); only the seed-word
recipes and checks need Ark Core installed.
"""

from __future__ import annotations

from functools import lru_cache


@lru_cache(maxsize=None)
def seed_word_list(name: str) -> tuple[str, ...]:
    """Words of ``bip39_<language>`` or ``monero_english``, in list order."""
    from patronus_ark_core import seed_word_list as core_seed_word_list

    return tuple(core_seed_word_list(name))
