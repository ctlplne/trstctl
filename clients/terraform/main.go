// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"trstctl.com/terraform-provider/internal/terraformprovider"
	"trstctl.com/terraform-provider/internal/version"
)

func main() {
	err := providerserver.Serve(context.Background(), terraformprovider.New(version.Version()), providerserver.ServeOpts{
		Address: "registry.terraform.io/trstctl/trstctl",
	})
	if err != nil {
		log.Fatal(err)
	}
}
