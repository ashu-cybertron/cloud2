provider "aws" {
  region     = "ap-south-1"
 # profile    = "ashu1"
}


resource "tls_private_key" "prkey" {
  algorithm  = "RSA"
}


resource "aws_key_pair" "webkey1" {
  key_name   = "webkey1"
  public_key = tls_private_key.prkey.public_key_openssh
}


resource "aws_security_group" "allow_80" {
  vpc_id      = "${aws_vpc.vpc.id}"
  name        = "allow_80"
  description = "Allow port 80"

  ingress {
    description = "allow_http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "allow_https"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "allow_ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

    ingress {
    description = "allow_NFS"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
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

resource "aws_vpc" "vpc" {
  cidr_block       = "192.168.0.0/16"
  instance_tenancy = "default"
  enable_dns_hostnames = true


  tags = {
    Name = "web_vpc"
  }
}


resource "aws_subnet" "subnet" {
  
  vpc_id     = "${aws_vpc.vpc.id}"
  availability_zone = "ap-south-1a"
  cidr_block = "192.168.1.0/24"
  map_public_ip_on_launch = true


  tags = {

    Name = "web_subnet"
  }
}


resource "aws_internet_gateway" "int_gate" {
  vpc_id = "${aws_vpc.vpc.id}"

  tags = {
    Name = "web_gate"
  }
}


resource "aws_route_table" "route_table" {
  vpc_id = "${aws_vpc.vpc.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.int_gate.id}"
  }

  tags = {
    Name = "web_route_table"
  }
}


resource "aws_route_table_association" "rt_association" {
  subnet_id      = aws_subnet.subnet.id
  route_table_id = aws_route_table.route_table.id
}


resource "aws_instance" "webserver" {
  ami           = "ami-0fcefd43691fafdbf"
  instance_type = "t2.micro"
  availability_zone = "ap-south-1a"
  key_name      = "webkey1"
  subnet_id     = "${aws_subnet.subnet.id}"
  security_groups = ["${aws_security_group.allow_80.id}"]
  
  tags = {
    Name = "WebOS"
  }
}


resource "null_resource" "imp_soft"  {
  depends_on = [aws_instance.webserver]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key =tls_private_key.prkey.private_key_pem
    host     = aws_instance.webserver.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install amazon-efs-utils -y",
      "sudo yum install httpd -y",
      "sudo yum install php -y",
      "sudo systemctl start httpd",
      "sudo systemctl enable httpd",
      "sudo yum install git -y",
      "sudo setenforce 0",
      "sudo yum -y install nfs-utils"
    ]
  }
}


resource "aws_efs_file_system" "efs" {
  creation_token = "web_efs"
 
  tags = {
    Name = "web_efs"
  }
}


resource "aws_efs_mount_target" "web_target" {
  file_system_id = "${aws_efs_file_system.efs.id}"
  subnet_id      = "${aws_subnet.subnet.id}"
  security_groups = [ "${aws_security_group.allow_80.id}" ]
}


output "efs_id"{
        value=aws_efs_file_system.efs.id
}


resource "null_resource" "mount"  {
  depends_on = [aws_efs_mount_target.web_target,
                null_resource.imp_soft]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key =tls_private_key.prkey.private_key_pem
    host     = aws_instance.webserver.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo mount -t nfs -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport ${aws_efs_file_system.efs.id}.efs.ap-south-1.amazonaws.com:/ /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/ashu-cybertron/web_code.git /var/www/html/",
      "sudo sed -i 's/url/${aws_cloudfront_distribution.webcloud.domain_name}/g' /var/www/html/index.html"
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
