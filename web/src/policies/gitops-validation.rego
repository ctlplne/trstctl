package trstctl.abac

# The policy workbench queries data.trstctl.abac for this dry-run kind. Only
# accept a supported GitOps envelope; detailed resource schemas are checked by
# their own API when a declaration is applied.
default deny := true
default reason := "Expected apiVersion trstctl.com/v1, a supported matching kind, metadata.name, and a spec object."

valid_envelope if {
  input.action == "gitops.validate"
  input.permission == "gitops:apply"
  input.declaration.apiVersion == "trstctl.com/v1"
  input.declaration_kind in {"TrstctlProfile", "TrstctlDiscoverySource", "TrstctlNotificationRoutingPolicy", "TrstctlInstallInventory"}
  input.declaration.kind == input.declaration_kind
  is_string(input.declaration.metadata.name)
  input.declaration.metadata.name != ""
  is_object(input.declaration.spec)
}

deny := false if {
  valid_envelope
}

reason := "" if {
  valid_envelope
}
