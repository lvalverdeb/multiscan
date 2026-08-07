# Correctly configured — must produce zero findings.
resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true
}
