import os


# Test-only signing key; production startup requires the operator's configured key.
os.environ["BAYORA_AUDIT_CHECKPOINT_KEY"] = "bayora-test-checkpoint-key-32-bytes-minimum"
