"""Inspect PKCS#12 encryption identifiers without invoking external commands."""

import sys
from collections.abc import Callable
from pathlib import Path

from asn1crypto import pkcs12


def verify_pkcs12_profile(path: Path, compatibility: bool, rounds: int | None) -> None:
    """Check certificate and key encryption plus the outer MAC in the actual file."""
    load_pfx: Callable[..., pkcs12.Pfx] = pkcs12.Pfx.load
    load_bags: Callable[..., pkcs12.SafeContents] = pkcs12.SafeContents.load
    pfx = load_pfx(path.read_bytes(), strict=True)
    expected_mac = "1.3.14.3.2.26" if compatibility else "2.16.840.1.101.3.4.2.1"
    assert (
        pfx["mac_data"]["mac"]["digest_algorithm"]["algorithm"].dotted == expected_mac
    )
    algorithms = []
    for entry in pfx.authenticated_safe:
        if entry["content_type"].native == "encrypted_data":
            algorithms.append(
                entry["content"]["encrypted_content_info"][
                    "content_encryption_algorithm"
                ]
            )
        elif entry["content_type"].native == "data":
            for bag in load_bags(entry["content"].native):
                assert bag["bag_id"].native == "pkcs8_shrouded_key_bag"
                algorithms.append(bag["bag_value"]["encryption_algorithm"])
    assert len(algorithms) == 2
    for algorithm in algorithms:
        if compatibility:
            assert algorithm["algorithm"].dotted == "1.2.840.113549.1.12.1.3"
            observed_rounds = algorithm["parameters"]["iterations"].native
        else:
            assert algorithm["algorithm"].dotted == "1.2.840.113549.1.5.13"
            parameters = algorithm["parameters"]
            assert (
                parameters["encryption_scheme"]["algorithm"].dotted
                == "2.16.840.1.101.3.4.1.42"
            )
            kdf = parameters["key_derivation_func"]["parameters"]
            assert kdf["prf"]["algorithm"].native == "sha256"
            observed_rounds = kdf["iteration_count"].native
        if rounds is not None:
            assert observed_rounds == rounds


if __name__ == "__main__":
    base = Path(sys.argv[1])
    verify_pkcs12_profile(base / "certs/identity/identity.pfx", False, None)
    for suffix in ("pfx", "p12"):
        verify_pkcs12_profile(
            base / f"certs/identity_full/identity_full.{suffix}", True, 2048
        )
