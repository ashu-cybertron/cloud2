provider "aws" {
  region     = "ap-south-1"
  profile    = "ashu"
}

resource "tls_private_key" "prkey" {
  algorithm  = "RSA"
}

resource "aws_key_pair" "webkey1" {
  key_name   = "webkey1"
  public_key = tls_private_key.prkey.public_key_openssh
}


resource "aws_security_group" "allow_80" {
  name        = "allow_80"
  description = "Allow port 80"

  ingress {
    description = "incoming http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "incoming ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_80"
  }
}


resource "aws_instance" "webserver" {
  ami           = "ami-052c08d70def0ac62"
  instance_type = "t2.micro"
  availability_zone = aws_ebs_volume.web_volume.availability_zone
  key_name      = "webkey1"
  security_groups = ["${aws_security_group.allow_80.name}"]
 
  tags = {
    Name = "WebOS"
  }
}


resource "aws_ebs_volume" "web_volume" {
  availability_zone = "ap-south-1a"
  size              = 1
  
  tags = {
    Name = "web_volume"
  }
}



resource "null_resource" "imp_soft"  {
  depends_on = [aws_instance.webserver,
                aws_volume_attachment.ebs_att]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key =tls_private_key.prkey.private_key_pem
    host     = aws_instance.webserver.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd -y",
      "sudo yum install php -y",
      "sudo systemctl start httpd",
      "sudo systemctl enable httpd",
      "sudo yum install git -y",
      "sudo setenforce 0"
    ]
  }
}



resource "aws_volume_attachment" "ebs_att" {
  device_name = "/dev/sdr"
  volume_id   = aws_ebs_volume.web_volume.id
  instance_id = aws_instance.webserver.id
  force_detach = true
}


resource "null_resource" "mount"  {
  depends_on = [aws_volume_attachment.ebs_att,
                null_resource.imp_soft]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key =tls_private_key.prkey.private_key_pem
    host     = aws_instance.webserver.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo mkfs.ext4  /dev/xvdr",
      "sudo mount  /dev/xvdr  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/ashutosh-k1/web_code.git /var/www/html/"
    ]
  }
}



resource "aws_s3_bucket" "s3bucket" {
  bucket = "poiuytrewqlkjhgfdsa"
  acl = "private"
  
  tags = {
    Name = "s3bucket"
  }
}


resource "aws_s3_bucket_public_access_block" "s3type" {
  bucket = "${aws_s3_bucket.s3bucket.id}"
  block_public_acls   = true
  block_public_policy = true
}

resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  depends_on = [aws_s3_bucket.s3bucket]
}



data "aws_iam_policy_document" "s3_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.s3bucket.arn}/*"]
    principals {
      type        = "AWS"
      identifiers = [  aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn ]
    }
  }
}



resource "aws_s3_bucket_policy" "policy" {
bucket = aws_s3_bucket.s3bucket.id
policy = data.aws_iam_policy_document.s3_policy.json
}


locals {
  s3_origin_id = "myS3Origin"
}




resource "aws_cloudfront_distribution" "webcloud" {
  origin {
    domain_name = "${aws_s3_bucket.s3bucket.bucket_regional_domain_name}"
    origin_id   = "${local.s3_origin_id}"
    s3_origin_config{
      origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }
  }
  enabled = true
  is_ipv6_enabled     = true
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "null_resource" "wepip"  {
	provisioner "local-exec" {
	    command = "echo  ${aws_instance.webserver.public_ip} > publicip.txt"
  	}
}


