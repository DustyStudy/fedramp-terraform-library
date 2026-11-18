# Upgrade path from library <= 3.0.0, where this root created the EBS key
# itself. The first run puts a key at the old address in state; the second
# plans the current configuration over that state. The key keeps its ARN only
# if the moved block carried it into the module; a replacement key would have
# an ARN that is unknown at plan time and fail the comparison.

# The mocked provider still validates arguments, so give it a real partition
# and parseable policy JSON in place of its random strings.
mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition = "aws-us-gov"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{}"
    }
  }
}

run "legacy_state" {
  command   = apply
  state_key = "upgrade"

  module {
    source = "./tests/legacy"
  }

  override_resource {
    target = aws_kms_key.ebs
    values = {
      arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    }
  }
}

run "existing_key_moves_into_the_module" {
  command   = plan
  state_key = "upgrade"

  assert {
    condition     = output.ebs_kms_key_arn == run.legacy_state.ebs_kms_key_arn
    error_message = "Upgrading must keep the existing EBS key (moved block), not destroy and recreate it."
  }
}
