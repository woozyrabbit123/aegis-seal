"""Global pytest configuration for Aegis Seal tests."""

import random

# Lock random seed for deterministic tests (especially parallel performance tests)
random.seed(42)
