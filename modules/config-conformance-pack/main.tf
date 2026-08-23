resource "aws_kms_key" "config" {
  description             = "KMS key for AWS Config buckets"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "config_access_log" {
  bucket = "${local.bucket_name}-access-logs"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_access_log" {
  bucket = aws_s3_bucket.config_access_log.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.config.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config_access_log" {
  bucket = aws_s3_bucket.config_access_log.id
  rule {
    id     = "abort-and-expire"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket" "config" {
  bucket = local.bucket_name
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.config.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    id     = "abort-and-transition"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    expiration {
      days = 365
    }
  }
}
