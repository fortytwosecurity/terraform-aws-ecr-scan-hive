variable "cloudwatch_event_rule_description" {
  type        = string
  description = "The description of the rule."
  default     = ""
}

variable "cloudwatch_event_rule_pattern" {
  description = "Event pattern described a HCL map which will be encoded as JSON with jsonencode function. See full documentation of CloudWatch Events and Event Patterns for details. http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/CloudWatchEventsandEventPatterns.html"
}

variable "company" {
  type        = string
  description = "company name"
  default     = ""
}

variable "project" {
  type        = string
  description = "project name"
  default     = ""
}

variable "environment" {
  type        = string
  description = "environment name"
  default     = ""
}