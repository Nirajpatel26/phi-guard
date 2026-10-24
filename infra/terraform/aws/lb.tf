resource "aws_lb" "portal" {
  name                       = "${var.prefix}-portal"
  internal                   = true
  load_balancer_type         = "application"
  subnets                    = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  tags                       = local.phi_tags
}

resource "aws_lb_target_group" "portal" {
  name     = "${var.prefix}-portal"
  port     = 8443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.main.id
}

# COMPLIANT: HTTPS with a TLS 1.2+/1.3 policy
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.portal.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:${var.region}:${var.account_id}:certificate/00000000-0000-0000-0000-000000000000"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.portal.arn
  }
}

# COMPLIANT: plain HTTP that only redirects to HTTPS
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.portal.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# NON-COMPLIANT (intentional): serves PHI over plain HTTP -> PHI-TX-03
resource "aws_lb_listener" "legacy_http" {
  load_balancer_arn = aws_lb.portal.arn
  port              = 8080
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.portal.arn
  }
}
