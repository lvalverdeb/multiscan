resource "aws_s3_bucket" "data" {
  bucket = "public-data"
  acl    = "public-read"
}
