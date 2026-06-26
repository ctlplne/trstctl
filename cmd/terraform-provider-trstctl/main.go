package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/terraformprovider"
)

func main() {
	err := providerserver.Serve(context.Background(), terraformprovider.New(buildinfo.Version()), providerserver.ServeOpts{
		Address: "registry.terraform.io/trstctl/trstctl",
	})
	if err != nil {
		log.Fatal(err)
	}
}
