package terraformprovider

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = (*Provider)(nil)

type Provider struct {
	version    string
	httpClient *http.Client
}

type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Token    types.String `tfsdk:"token"`
	Tenant   types.String `tfsdk:"tenant"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &Provider{version: version}
	}
}

func NewWithHTTPClient(version string, httpClient *http.Client) func() provider.Provider {
	return func() provider.Provider {
		return &Provider{version: version, httpClient: httpClient}
	}
}

func (p *Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "trstctl"
	resp.Version = p.version
}

func (p *Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Terraform provider for the trstctl non-human identity control plane.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Base URL for the trstctl control plane. Defaults to `TRSTCTL_SERVER`.",
			},
			"token": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "trstctl API token sent as `Authorization: Bearer`. Defaults to `TRSTCTL_TOKEN`.",
			},
			"tenant": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Tenant id sent as `X-Tenant-ID` for header/dev auth. Defaults to `TRSTCTL_TENANT`; bearer tokens may carry the tenant without this field.",
			},
		},
	}
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := stringConfig(cfg.Endpoint, "TRSTCTL_SERVER")
	token := stringConfig(cfg.Token, "TRSTCTL_TOKEN")
	tenant := stringConfig(cfg.Tenant, "TRSTCTL_TENANT")
	client, err := NewClient(ClientConfig{Endpoint: endpoint, Token: token, Tenant: tenant, HTTPClient: p.httpClient})
	if err != nil {
		resp.Diagnostics.AddError("Invalid trstctl provider configuration", err.Error())
		return
	}
	resp.ResourceData = client
}

func (p *Provider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewProfileResource,
		NewPKICertificateResource,
		NewSecretResource,
	}
}

func (p *Provider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func stringConfig(v types.String, env string) string {
	if !v.IsNull() && !v.IsUnknown() {
		return v.ValueString()
	}
	return os.Getenv(env)
}

func configureClient(providerData any, target **Client) error {
	if providerData == nil {
		return nil
	}
	client, ok := providerData.(*Client)
	if !ok {
		return fmt.Errorf("expected *terraformprovider.Client, got %T", providerData)
	}
	*target = client
	return nil
}
